//! Turning a window into coinbase outputs.
//!
//! `distributable = value − fee`. Each identity gets `distributable × work / total_work`,
//! rounded down. Identities that cannot be paid — no valid payout script, under the dust
//! floor, or past the size budget a gateway's coinbase can hold — are dropped and their
//! amount stays with the pool, which the gateway pays automatically as the remainder.

use serde::Serialize;
use std::collections::BTreeMap;

use crate::MinerStat;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitParams {
    /// DATUM / Prime-gateway fee in basis points (50 = 0.5%).
    pub fee_bps: u32,
    /// Public house-stratum fee in basis points (250 = 2.5%). 0 means same as `fee_bps`.
    pub stratum_fee_bps: u32,
    /// Smallest output the split will emit, in sats.
    pub min_payout: u64,
    /// Cap on the number of outputs (the protocol allows 512).
    pub max_outputs: usize,
    /// Byte budget for the emitted outputs inside the coinbase. Type-4 ("huge") coinbases
    /// hold 16 KiB total; leave room for the scriptSig, the pool output and the witness
    /// commitment.
    pub output_budget_bytes: usize,
}

impl Default for SplitParams {
    fn default() -> Self {
        SplitParams {
            fee_bps: 0,
            stratum_fee_bps: 0,
            min_payout: 546,
            max_outputs: 512,
            output_budget_bytes: 14_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Payee {
    pub identity: String,
    pub work: u64,
    pub sats: u64,
    #[serde(with = "hex_bytes")]
    pub script: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Split {
    pub value: u64,
    pub fee_sats: u64,
    pub total_work: u64,
    /// Paid outputs, largest first.
    pub payees: Vec<Payee>,
    /// Identities in the window that will not get an output, with the sats they would have.
    pub unpaid: Vec<(String, u64, UnpaidReason)>,
    /// Carry-forward paid in this split: sats owed from earlier blocks (dust, outputs that did
    /// not fit, blocks found on an empty window) now added to an identity's output. Deducted
    /// from the carry ledger only when a block actually pays this split.
    pub carry_paid: Vec<(String, u64)>,
    /// What the pool script receives: fee plus rounding plus everything unpaid.
    pub pool_sats: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum UnpaidReason {
    NoScript,
    BelowMinimum,
    OverBudget,
}

impl Split {
    pub fn paid_sats(&self) -> u64 {
        self.payees.iter().map(|p| p.sats).sum()
    }
}

pub fn fee_for(value: u64, fee_bps: u32) -> u64 {
    ((u128::from(value) * u128::from(fee_bps)) / 10_000) as u64
}

pub fn compute(
    miners: Vec<MinerStat>,
    total_work: u64,
    value: u64,
    p: &SplitParams,
    mut script_for: impl FnMut(&str) -> Option<Vec<u8>>,
) -> Split {
    compute_with_carry(miners, total_work, value, p, &BTreeMap::new(), &mut script_for)
}

/// `compute` plus carry-forward: every identity with sats owed from earlier blocks gets them
/// added to its output (or a new output, if it has no work in the window right now), as long
/// as the block can pay it — the pool's remainder is what funds it, so `paid` never exceeds
/// `value`. Identities are served in the order of the carry map (by name) until the block's
/// remainder is exhausted; whatever could not be paid stays in the carry ledger.
pub fn compute_with_carry(
    miners: Vec<MinerStat>,
    total_work: u64,
    value: u64,
    p: &SplitParams,
    carry: &BTreeMap<String, u64>,
    script_for: &mut impl FnMut(&str) -> Option<Vec<u8>>,
) -> Split {
    let stratum_bps = if p.stratum_fee_bps == 0 { p.fee_bps } else { p.stratum_fee_bps };
    let mut fee_sats = 0u64;
    let mut payees = Vec::new();
    let mut unpaid = Vec::new();
    let mut paid = 0u64;
    let mut bytes = 0usize;
    if total_work > 0 {
        for m in miners {
            let sw = m.stratum_work.min(m.work);
            let dw = m.work - sw;
            let keep = u128::from(sw) * u128::from(10_000 - stratum_bps)
                + u128::from(dw) * u128::from(10_000 - p.fee_bps);
            let sats = (u128::from(value) * keep / u128::from(total_work) / 10_000) as u64;
            fee_sats = fee_sats.saturating_add(
                (u128::from(value)
                    * (u128::from(sw) * u128::from(stratum_bps) + u128::from(dw) * u128::from(p.fee_bps))
                    / u128::from(total_work)
                    / 10_000) as u64,
            );
            if sats == 0 {
                continue;
            }
            if sats < p.min_payout {
                unpaid.push((m.identity, sats, UnpaidReason::BelowMinimum));
                continue;
            }
            let Some(script) = script_for(&m.identity) else {
                unpaid.push((m.identity, sats, UnpaidReason::NoScript));
                continue;
            };
            let need = 8 + 1 + script.len();
            if payees.len() >= p.max_outputs || bytes + need > p.output_budget_bytes {
                unpaid.push((m.identity, sats, UnpaidReason::OverBudget));
                continue;
            }
            bytes += need;
            paid += sats;
            payees.push(Payee { identity: m.identity, work: m.work, sats, script });
        }
    }
    // Carry-forward: pay what earlier blocks could not, out of everything this block would
    // send to the pool — fee included. The pool already received those sats in the earlier
    // coinbase, so its own output is what returns them; over time the pool nets exactly its
    // fee and never holds a balance for anyone.
    let mut carry_paid = Vec::new();
    if !carry.is_empty() {
        let mut room = value.saturating_sub(paid);
        for (identity, &owed) in carry {
            if room == 0 {
                break;
            }
            if owed == 0 {
                continue;
            }
            let give = owed.min(room);
            if let Some(payee) = payees.iter_mut().find(|q| q.identity == *identity) {
                payee.sats += give;
            } else {
                if give < p.min_payout {
                    continue;
                }
                let Some(script) = script_for(identity) else { continue };
                let need = 8 + 1 + script.len();
                if payees.len() >= p.max_outputs || bytes + need > p.output_budget_bytes {
                    continue;
                }
                bytes += need;
                payees.push(Payee { identity: identity.clone(), work: 0, sats: give, script });
            }
            paid += give;
            room -= give;
            carry_paid.push((identity.clone(), give));
        }
    }
    // `paid` cannot exceed `value` (each payee is a proper fraction of it, and the carry only
    // spends the remainder), but the pool's remainder must never wrap to a 2^64 output if
    // that invariant is ever broken upstream.
    Split { value, fee_sats, total_work, payees, unpaid, carry_paid, pool_sats: value.saturating_sub(paid) }
}

mod hex_bytes {
    use serde::Serializer;
    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&b.iter().map(|x| format!("{x:02x}")).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn miner(id: &str, work: u64) -> MinerStat {
        MinerStat { identity: id.into(), work, stratum_work: 0, credits: 1, last_ts: 0 }
    }

    fn miner_stratum(id: &str, work: u64) -> MinerStat {
        MinerStat { identity: id.into(), work, stratum_work: work, credits: 1, last_ts: 0 }
    }

    fn script(id: &str) -> Option<Vec<u8>> {
        if id.starts_with("bad") {
            None
        } else {
            Some(vec![0x00, 0x14, id.as_bytes()[0]])
        }
    }

    #[test]
    fn proportional_with_fee_and_floor() {
        let miners = vec![miner("a", 600), miner("b", 300), miner("c", 100), miner("d", 1)];
        // one unit of work is worth ~310k sats here; a 400k floor drops only `d`
        let p = SplitParams {
            fee_bps: 50,
            stratum_fee_bps: 50,
            min_payout: 400_000,
            max_outputs: 512,
            output_budget_bytes: 14_000,
        };
        let s = compute(miners, 1001, 312_538_966, &p, script);
        assert_eq!(s.fee_sats, 1_562_694);
        let dist = 312_538_966 - 1_562_694;
        assert_eq!(s.payees.len(), 3);
        assert_eq!(s.payees[0].sats, dist * 600 / 1001);
        assert_eq!(s.payees[1].sats, dist * 300 / 1001);
        assert_eq!(s.payees[2].sats, dist * 100 / 1001);
        assert_eq!(s.unpaid.len(), 1);
        assert_eq!(s.unpaid[0].2, UnpaidReason::BelowMinimum);
        assert_eq!(s.pool_sats + s.paid_sats(), 312_538_966);
        assert!(s.pool_sats >= s.fee_sats + s.unpaid[0].1);
    }

    #[test]
    fn unpayable_and_budget() {
        let miners: Vec<MinerStat> =
            (0..20).map(|i| miner(&format!("{}{}", if i == 3 { "bad" } else { "m" }, i), 100)).collect();
        let p = SplitParams { fee_bps: 0, stratum_fee_bps: 0, min_payout: 1, max_outputs: 5, output_budget_bytes: 14_000 };
        let s = compute(miners, 2000, 1_000_000, &p, script);
        assert_eq!(s.payees.len(), 5);
        assert!(s.unpaid.iter().any(|u| u.2 == UnpaidReason::NoScript));
        assert_eq!(s.unpaid.iter().filter(|u| u.2 == UnpaidReason::OverBudget).count(), 14);
        let p = SplitParams { fee_bps: 0, stratum_fee_bps: 0, min_payout: 1, max_outputs: 512, output_budget_bytes: 12 * 2 };
        let s = compute(vec![miner("a", 1), miner("b", 1), miner("c", 1)], 3, 300, &p, script);
        assert_eq!(s.payees.len(), 2);
        assert_eq!(s.pool_sats, 100);
    }

    #[test]
    fn empty_window_pays_the_pool() {
        let s = compute(vec![], 0, 100, &SplitParams::default(), script);
        assert!(s.payees.is_empty());
        assert_eq!(s.pool_sats, 100);
    }

    #[test]
    fn stratum_pays_a_higher_fee_than_datum() {
        let miners = vec![miner("datum", 600), miner_stratum("house", 400)];
        let p = SplitParams {
            fee_bps: 50,
            stratum_fee_bps: 500,
            min_payout: 1,
            max_outputs: 512,
            output_budget_bytes: 14_000,
        };
        let s = compute(miners, 1000, 10_000_000, &p, script);
        assert_eq!(s.payees[0].identity, "datum");
        assert_eq!(s.payees[0].sats, 5_970_000);
        assert_eq!(s.payees[1].identity, "house");
        assert_eq!(s.payees[1].sats, 3_800_000);
        assert_eq!(s.fee_sats, 230_000);
        assert_eq!(s.pool_sats + s.paid_sats(), 10_000_000);
    }

    #[test]
    fn carry_forward_pays_from_remainder_and_never_exceeds_value() {
        let p = SplitParams { fee_bps: 40, stratum_fee_bps: 0, min_payout: 546, max_outputs: 512, output_budget_bytes: 14_000 };
        let miners = vec![
            MinerStat { identity: "a".into(), work: 3, stratum_work: 0, credits: 1, last_ts: 0 },
            MinerStat { identity: "b".into(), work: 1, stratum_work: 0, credits: 1, last_ts: 0 },
        ];
        let script = |_: &str| Some(vec![0u8, 20, 1, 2, 3]);
        let mut carry = BTreeMap::new();
        carry.insert("b".to_string(), 10_000u64); // b is owed from an earlier block
        carry.insert("c".to_string(), 5_000u64); // c has no work now, still owed
        let value = 1_000_000u64;
        let mut sf = script;
        let s = compute_with_carry(miners.clone(), 4, value, &p, &carry, &mut sf);
        let fee = fee_for(value, 40);
        // work-based: a 3/4, b 1/4 of (value - fee); then carry on top, out of the remainder
        let base_a = (value as u128 * 3 * (10_000 - 40) / 4 / 10_000) as u64;
        let a = s.payees.iter().find(|q| q.identity == "a").unwrap();
        let b = s.payees.iter().find(|q| q.identity == "b").unwrap();
        let c = s.payees.iter().find(|q| q.identity == "c");
        assert_eq!(a.sats, base_a);
        // the window is full, so only the pool's own share (fee + rounding = 4000 sats) funds
        // the carry this block: "b" (first by name) gets it all, "c" waits for the next block
        let base_b = (value as u128 * (10_000 - 40) / 4 / 10_000) as u64;
        assert_eq!(b.sats, base_b + (value - base_a - base_b));
        assert!(c.is_none(), "c is below min_payout once the remainder ran out");
        let paid: u64 = s.payees.iter().map(|q| q.sats).sum();
        assert_eq!(paid + s.pool_sats, value);
        assert_eq!(s.pool_sats, 0, "the pool's fee repays carry before the pool keeps anything");
        assert_eq!(s.carry_paid, vec![("b".to_string(), value - base_a - base_b)]);
        let _ = fee;
        // remainder too small: carry is paid partially and the rest stays owed
        let mut big = BTreeMap::new();
        big.insert("c".to_string(), value * 10);
        let s2 = compute_with_carry(miners, 4, value, &p, &big, &mut sf);
        let paid2: u64 = s2.payees.iter().map(|q| q.sats).sum();
        assert_eq!(paid2 + s2.pool_sats, value);
        assert_eq!(s2.pool_sats, 0);
    }
}
