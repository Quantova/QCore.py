# Copyright 2026 Quantova Inc
# SPDX-License-Identifier: Apache-2.0 OR MIT

import json
import sys

import quantova_qcore as qcore

failures = 0


def ok(label, cond):
    global failures
    if cond:
        print("  ok   " + label)
    else:
        failures += 1
        print("  FAIL " + label)


def member(i, pk, stake, root):
    return {"id": i, "attest_pk": (pk * 64)[:64], "stake": str(stake), "root_slots": "65536", "root": (root * 64)[:64]}


GENESIS = [member(1, "a1", 2000, "e0"), member(2, "a2", 2000, "e0"), member(3, "a3", 2000, "e0"), member(4, "a4", 2000, "e0")]
GENESIS_JSON = json.dumps(GENESIS)
PIN = qcore.roster_commitment(0, GENESIS_JSON)
GENESIS_HASH = "b" * 64
FORGED = [member(1, "ff", 9000, "ee")]

net = qcore.Network(name="anchor-test", chain_id="Q-testNet-1.1", rpc_url="https://gw.test",
                    genesis_hash=GENESIS_HASH, roster_commitment=PIN, epoch_length=100)
client = qcore.Client(net)


def fake_call(method, body, strict=False):
    q = json.loads(body) if body else {}
    if method == "node_info":
        return {"head_height": 1000, "protocol": 1, "chain_id": "Q-testNet-1.1"}
    if method == "get_roster_proof":
        return {"members": GENESIS, "epoch": 0} if q.get("epoch") == 0 else {"members": FORGED, "epoch": q.get("epoch")}
    raise RuntimeError("unexpected call " + method)


client._call = fake_call
client._anchor_pinned_roster()

ok("the pinned genesis roster is trusted", 0 in client._trusted_rosters)

leaked = False
genesis_keys = {m["attest_pk"] for m in GENESIS}
for roster in client._trusted_rosters.values():
    for m in json.loads(roster):
        backed = any(g["attest_pk"] == m["attest_pk"] and g["stake"] == m["stake"] and g["root_slots"] == m["root_slots"] for g in GENESIS)
        if m["attest_pk"] not in genesis_keys or not backed:
            leaked = True
ok("no unverified recent roster enters the trusted set (a gateway cannot forge the committee)", not leaked)

print("roster-anchor: all ok" if failures == 0 else f"roster-anchor: {failures} FAILED")
sys.exit(0 if failures == 0 else 1)
