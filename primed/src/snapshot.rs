//! WAVICLES window-snapshot commitment.
//!
//! Every coinbaser Prime issues is computed from a window state. That state is serialized as
//! canonical JSON (sorted keys, compact, integers and strings only — so any JSON library
//! reproduces the same bytes), hashed with BLAKE2b-256, and the hash is committed as the first
//! output of the coinbaser: `OP_RETURN <tag> <hash>` (zero sats). The snapshot file is
//! published, so anyone can hash it, match the block's OP_RETURN, recompute the TIDES split
//! from `window` + `carry` + `params` and compare it with the coinbase outputs on chain.
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use serde_json::{json, Map, Value};
use tides::split::Split;
use tides::MinerStat;

pub const VERSION: u32 = 1;
/// Snapshots older than this are pruned (blocks found keep theirs: the site archives them).
pub const KEEP_SECS: u64 = 48 * 3600;

pub struct Snapshot {
    pub hash: [u8; 32],
    pub canonical: Vec<u8>,
}

impl Snapshot {
    pub fn hex(&self) -> String {
        hex::encode(self.hash)
    }

    /// `OP_RETURN <push tag||hash>` — a single push of tag bytes followed by the 32-byte hash.
    pub fn op_return(&self, tag: &str) -> Vec<u8> {
        let mut data = Vec::with_capacity(tag.len() + 32);
        data.extend_from_slice(tag.as_bytes());
        data.extend_from_slice(&self.hash);
        let mut s = Vec::with_capacity(2 + data.len());
        s.push(0x6a);
        s.push(data.len() as u8); // ≤ 72 < OP_PUSHDATA1, so a direct push
        s.extend_from_slice(&data);
        s
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build(
    tag: &str,
    height: u32,
    prev_hash_display_hex: &str,
    ts: u64,
    value: u64,
    fee_bps: u32,
    stratum_fee_bps: u32,
    min_payout: u64,
    max_outputs: usize,
    output_budget_bytes: usize,
    window_target: u64,
    window_total: u64,
    miners: &[MinerStat],
    carry: &BTreeMap<String, u64>,
    split: &Split,
) -> Snapshot {
    // Everything is an integer or a string: no floats, so the canonical form is portable.
    let mut window: Vec<Value> = miners
        .iter()
        .map(|m| json!({ "identity": m.identity, "work": m.work, "stratum_work": m.stratum_work }))
        .collect();
    window.sort_by(|a, b| a["identity"].as_str().cmp(&b["identity"].as_str()));
    let carry_v: Vec<Value> = carry.iter().map(|(i, s)| json!({ "identity": i, "sats": s })).collect();
    let payees: Vec<Value> = split
        .payees
        .iter()
        .map(|p| json!({ "identity": p.identity, "work": p.work, "sats": p.sats, "script": hex::encode(&p.script) }))
        .collect();
    let unpaid: Vec<Value> = split
        .unpaid
        .iter()
        .map(|(i, s, r)| json!({ "identity": i, "sats": s, "reason": format!("{r:?}") }))
        .collect();
    let carry_paid: Vec<Value> = split.carry_paid.iter().map(|(i, s)| json!({ "identity": i, "sats": s })).collect();
    let doc = json!({
        "v": VERSION,
        "tag": tag,
        "height": height,
        "prevhash": prev_hash_display_hex,
        "ts": ts,
        "coinbase_value": value,
        "params": {
            "fee_bps": fee_bps,
            "stratum_fee_bps": stratum_fee_bps,
            "min_payout": min_payout,
            "max_outputs": max_outputs,
            "output_budget_bytes": output_budget_bytes,
            "rule": "sats_i = value * work_i * (10000 - fee_bps) / total_work / 10000 (floor), payees largest work first; carry paid from the remainder above the fee, by identity name; pool = value - sum(paid)",
        },
        "window": { "target_work": window_target, "total_work": window_total, "identities": window },
        "carry": carry_v,
        "split": {
            "fee_sats": split.fee_sats,
            "payees": payees,
            "carry_paid": carry_paid,
            "unpaid": unpaid,
            "pool_sats": split.pool_sats,
        },
    });
    let canonical = canonical_bytes(&doc);
    let mut h = Blake2b::<U32>::new();
    h.update(&canonical);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&h.finalize());
    Snapshot { hash, canonical }
}

/// Sorted keys, no whitespace. `serde_json::Map` is a `BTreeMap` unless `preserve_order` is on,
/// but sort explicitly so the guarantee does not depend on a feature flag.
pub fn canonical_bytes(v: &Value) -> Vec<u8> {
    fn sorted(v: &Value) -> Value {
        match v {
            Value::Object(m) => {
                let mut b: Vec<(&String, &Value)> = m.iter().collect();
                b.sort_by(|a, c| a.0.cmp(c.0));
                let mut out = Map::new();
                for (k, val) in b {
                    out.insert(k.clone(), sorted(val));
                }
                Value::Object(out)
            }
            Value::Array(a) => Value::Array(a.iter().map(sorted).collect()),
            other => other.clone(),
        }
    }
    serde_json::to_vec(&sorted(v)).expect("json")
}

pub fn dir_of(data_dir: &Path) -> PathBuf {
    data_dir.join("snapshots")
}

/// Write `<dir>/<hash>.json` once (idempotent) and return its path.
pub fn store(dir: &Path, s: &Snapshot) -> std::io::Result<PathBuf> {
    fs::create_dir_all(dir)?;
    let path = dir.join(format!("{}.json", s.hex()));
    if !path.exists() {
        let tmp = dir.join(format!(".{}.tmp", s.hex()));
        fs::write(&tmp, &s.canonical)?;
        fs::rename(tmp, &path)?;
    }
    Ok(path)
}

pub fn load(dir: &Path, hex_hash: &str) -> Option<Vec<u8>> {
    if hex_hash.len() != 64 || !hex_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    fs::read(dir.join(format!("{hex_hash}.json"))).ok()
}

/// Delete snapshots older than `KEEP_SECS`, except the ones named in `keep`.
pub fn prune(dir: &Path, now: u64, keep: &[String]) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        let Some(h) = name.strip_suffix(".json") else { continue };
        if keep.iter().any(|k| k == h) {
            continue;
        }
        let Ok(md) = e.metadata() else { continue };
        let age = md.modified().ok().and_then(|m| m.elapsed().ok()).map(|d| d.as_secs()).unwrap_or(0);
        if age > KEEP_SECS && now > 0 {
            let _ = fs::remove_file(e.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_is_sorted_and_compact() {
        let v = json!({ "b": 1, "a": { "z": [3, { "y": 2, "x": 1 }], "m": "s" } });
        assert_eq!(canonical_bytes(&v), br#"{"a":{"m":"s","z":[3,{"x":1,"y":2}]},"b":1}"#.to_vec());
    }

    #[test]
    fn op_return_layout() {
        let s = Snapshot { hash: [7u8; 32], canonical: vec![] };
        let o = s.op_return("PYBLOCK-TON618");
        assert_eq!(o[0], 0x6a);
        assert_eq!(o[1] as usize, 14 + 32);
        assert_eq!(&o[2..16], b"PYBLOCK-TON618");
        assert_eq!(o.len(), 48);
    }
}
