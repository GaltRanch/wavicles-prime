#!/usr/bin/env python3
"""Verify a WAVICLES (PyBLOCK DATUM · BLAKE2b) block's coinbase against the window snapshot Prime committed to.

What is checked, from public data only:
  1. the coinbase carries `OP_RETURN <tag><hash>` and BLAKE2b-256(snapshot) == hash  → the published window is the one
     the split was computed from, and cannot be rewritten after the block exists;
  2. the TIDES split recomputed from `window` + `carry` + `params` equals the snapshot's `split.payees`;
  3. every payee (and the pool's remainder) is paid on chain, compared by scriptPubKey.
What still rests on the pool: that `window` reflects the shares gateways really sent (signed share receipts address that).

  verify_wavicles_block.py --height H --conf bitcoin.conf [--snapshot-dir DIR | --url https://b.pyblock.xyz/wavicles_api.php]
  verify_wavicles_block.py --snapshot FILE            # self-check: reproduces its own split
"""
import argparse, base64, hashlib, json, os, sys, urllib.request

def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def b2b(b: bytes) -> bytes:
    return hashlib.blake2b(b, digest_size=32).digest()

def recompute(snap):
    """Return (problems, payees[(identity, sats, script_hex)], pool_sats) from the snapshot's inputs."""
    problems = []
    p = snap["params"]; fee_bps = int(p["fee_bps"]); min_payout = int(p["min_payout"])
    value = int(snap["coinbase_value"]); ids = snap["window"]["identities"]
    total_work = sum(int(i["work"]) for i in ids)
    if total_work != int(snap["window"]["total_work"]):
        problems.append(f"window total_work {snap['window']['total_work']} != sum of identities {total_work}")
    script_of = {q["identity"]: q["script"] for q in snap["split"]["payees"]}
    miners = sorted(ids, key=lambda m: (-int(m["work"]), m["identity"]))
    payees = []; paid = 0; fee = 0
    if total_work > 0:
        for m in miners:
            w = int(m["work"])
            sats = value * w * (10000 - fee_bps) // total_work // 10000
            fee += value * w * fee_bps // total_work // 10000
            if sats == 0: continue
            if sats < min_payout: continue  # unpaid: BelowMinimum
            if m["identity"] not in script_of: continue  # NoScript / OverBudget — listed in split.unpaid
            payees.append([m["identity"], sats, script_of[m["identity"]]]); paid += sats
    # PyBLØCK max_payees (2026-09-09): keep the largest `max_payees` by work and give them value − fee in full;
    # the pool's output is exactly the fee; identities below the cut get nothing (BelowCut), nothing is carried.
    max_payees = int(p.get("max_payees", 0) or 0)
    if max_payees > 0 and payees:
        ids_by = {i["identity"]: int(i["work"]) for i in ids}
        sw_all = sum(int(i.get("stratum_work", 0)) for i in ids); dw_all = total_work - sw_all
        sbps = int(p.get("stratum_fee_bps", 0) or 0) or fee_bps
        fee = value * (sw_all * sbps + dw_all * fee_bps) // max(total_work, 1) // 10000
        payees.sort(key=lambda q: (-ids_by[q[0]], q[0]))
        # 2026-09-11: largest first until the cap OR the gateway's coinbase byte budget (params.output_budget_bytes)
        # is full; what does not fit is OverBudget (not paid by this block, not weighed), never truncated by the gateway.
        budget = int(p.get("output_budget_bytes", 0) or 0); used = 0; kept = []
        for q in payees:
            need = 9 + len(q[2]) // 2
            if len(kept) >= max_payees: break
            if budget and used + need > budget: continue
            used += need; kept.append(q)
        payees = kept
        distributable = value - fee; kept_work = sum(ids_by[q[0]] for q in payees)
        tot = 0
        for q in payees:
            q[1] = distributable * ids_by[q[0]] // max(kept_work, 1); tot += q[1]
        top = max(payees, key=lambda q: q[1]); top[1] += distributable - tot
        paid = distributable
    # carry: paid from everything the pool would get (fee included), by identity name (BTreeMap order)
    room = value - paid
    for c in sorted(snap.get("carry", []), key=lambda c: c["identity"]):
        if room <= 0: break
        owed = int(c["sats"]);
        if owed == 0: continue
        give = min(owed, room)
        hit = next((q for q in payees if q[0] == c["identity"]), None)
        if hit: hit[1] += give
        else:
            if give < min_payout or c["identity"] not in script_of: continue
            payees.append([c["identity"], give, script_of[c["identity"]]])
        paid += give; room -= give
    pool_sats = value - paid
    got = [(q["identity"], int(q["sats"])) for q in snap["split"]["payees"]]
    if [(a, b) for a, b, _ in payees] != got:
        problems.append("recomputed split != snapshot split.payees")
    if pool_sats != int(snap["split"]["pool_sats"]):
        problems.append(f"pool_sats: recomputed {pool_sats} vs snapshot {snap['split']['pool_sats']}")
    return problems, payees, pool_sats

def rpc_factory(conf):
    c = dict(l.strip().split("=", 1) for l in open(conf) if "=" in l and not l.strip().startswith("#"))
    url = f"http://{c.get('rpcconnect', '127.0.0.1')}:{c['rpcport']}/"
    auth = base64.b64encode(f"{c['rpcuser']}:{c['rpcpassword']}".encode()).decode()
    def rpc(m, *p):
        req = urllib.request.Request(url, json.dumps({"method": m, "params": list(p), "id": 1}).encode(),
                                     {"Authorization": "Basic " + auth, "Content-Type": "application/json"})
        r = json.load(urllib.request.urlopen(req, timeout=60))
        if r.get("error"): raise SystemExit(f"rpc {m}: {r['error']}")
        return r["result"]
    return rpc

def load_snapshot(hx, snapshot_dir, url):
    if snapshot_dir:
        p = os.path.join(snapshot_dir, hx + ".json")
        if os.path.exists(p): return open(p, "rb").read()
    if url:
        u = f"{url}?mode=snapshot&hash={hx}" if "?" not in url and url.endswith(".php") else f"{url.rstrip('/')}/snapshot/{hx}"
        with urllib.request.urlopen(u, timeout=15) as r: return r.read()
    raise SystemExit(f"snapshot {hx} not found (looked in {snapshot_dir!r} / {url!r})")

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--snapshot"); ap.add_argument("--height", type=int); ap.add_argument("--conf")
    ap.add_argument("--snapshot-dir"); ap.add_argument("--url"); ap.add_argument("--tag", default="PYBLOCK-TON618")
    a = ap.parse_args(); ok = True
    if a.snapshot and not a.height:
        raw = open(a.snapshot, "rb").read(); snap = json.loads(raw)
        print(f"snapshot h={snap['height']} prev={snap['prevhash'][:16]}… identities={len(snap['window']['identities'])} payees={len(snap['split']['payees'])} hash={b2b(canon(snap)).hex()}")
        if canon(snap) != raw.strip(): print("note: file is not in canonical form (re-serialized for hashing)")
        problems, _, _ = recompute(snap)
        for p in problems: print("FAIL", p)
        print("OK snapshot reproduces its own split" if not problems else "MISMATCH"); return 0 if not problems else 1
    if not (a.height and a.conf): ap.print_help(); return 2
    rpc = rpc_factory(a.conf); bh = rpc("getblockhash", a.height); blk = rpc("getblock", bh, 2); cb = blk["tx"][0]
    tag = a.tag.encode(); commit = None; outs = {}
    for o in cb["vout"]:
        spk = bytes.fromhex(o["scriptPubKey"]["hex"])
        if spk[:1] == b"\x6a" and len(spk) == 2 + len(tag) + 32 and spk[1] == len(tag) + 32 and spk[2:2 + len(tag)] == tag:
            commit = spk[2 + len(tag):].hex()
        elif o["value"] > 0:
            outs[spk.hex()] = outs.get(spk.hex(), 0) + round(o["value"] * 1e8)
    if not commit:
        print(f"block {a.height}: no {a.tag} commitment in the coinbase (not a WAVICLES block, or built before commitments)"); return 2
    print(f"block {a.height} {bh[:16]}… commitment={commit}")
    raw = load_snapshot(commit, a.snapshot_dir, a.url); snap = json.loads(raw)
    h = b2b(canon(snap)).hex()
    if h != commit: print(f"FAIL snapshot hash {h} != commitment {commit}"); ok = False
    else: print("OK snapshot hashes to the commitment")
    # prevhash binds the snapshot to this block's parent (the split was computed for the next block on it);
    # height is Prime's node view when the coinbaser was issued and can lag by one when the gateway's node
    # saw the parent first — informational only.
    if snap["prevhash"] != blk["previousblockhash"]:
        print(f"FAIL snapshot was computed on prev={snap['prevhash'][:16]}…, block's prev={blk['previousblockhash'][:16]}…"); ok = False
    else:
        print(f"OK snapshot was computed on this block's parent" + (f" (height noted {snap['height']}, block {a.height})" if snap["height"] != a.height else ""))
    problems, payees, pool_sats = recompute(snap)
    for p in problems: print("FAIL", p); ok = False
    if not problems: print(f"OK TIDES split ({len(payees)} payees, fee {snap['params']['fee_bps']} bps, carry paid {sum(x['sats'] for x in snap['split']['carry_paid'])} sats) reproduces from the committed window")
    total = sum(round(o["value"] * 1e8) for o in cb["vout"])
    scale = total / int(snap["coinbase_value"]) if int(snap["coinbase_value"]) else 1.0
    missing = []
    for ident, sats, script in payees:
        got = outs.get(script)
        want = sats if abs(scale - 1.0) < 1e-12 else int(sats * scale)
        if got is None or abs(got - want) > 2 + len(payees): missing.append((ident, want, got))
    if missing:
        for ident, want, got in missing: print(f"FAIL coinbase does not pay {ident} {want} sats (got {got})"); ok = False
    else: print(f"OK every payee is paid on chain (coinbase total {total} sats{' — outputs scaled by ' + format(scale, '.6f') if abs(scale-1) > 1e-12 else ''})")
    print("VERIFIED" if ok else "MISMATCH"); return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
