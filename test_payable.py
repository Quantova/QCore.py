# Copyright 2026 Quantova Inc
# SPDX-License-Identifier: Apache-2.0 OR MIT

import json
import os
import sys

try:
    import qcore
except ModuleNotFoundError:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "python"))
    import qcore

failures = 0

def ok(label, cond):
    global failures
    if cond:
        print("  ok   " + label)
    else:
        failures += 1
        print("  FAIL " + label)

LOCAL_CHAIN_ID = qcore.local_chain_id()
MAINNET_CHAIN_ID = qcore.mainnet_chain_id()
TESTNET_CHAIN_ID = qcore.testnet_chain_id()

def main():
    seed = "0b" * 32
    target = qcore.address(seed, 1)

    plain = json.loads(qcore.sign_call(seed, 0, target, "", 3, 21000, 9000, LOCAL_CHAIN_ID, 300, 500))
    payable = json.loads(qcore.sign_payable_call(seed, 0, target, "", 3, 21000, 9000, 0, LOCAL_CHAIN_ID, 300, 500))
    ok("a payable call with no value on the local chain matches a plain call",
       payable["tx_hex"] == plain["tx_hex"])
    ok("a payable call with no value on the local chain matches a plain call's id",
       payable["tx_id"] == plain["tx_id"])

    unpaid = json.loads(qcore.sign_payable_call(seed, 0, target, "", 3, 21000, 9000, 0, LOCAL_CHAIN_ID, 300, 500))
    paid = json.loads(qcore.sign_payable_call(seed, 0, target, "", 3, 21000, 9000, 4200, LOCAL_CHAIN_ID, 300, 500))
    ok("a nonzero value changes the signed bytes", unpaid["tx_hex"] != paid["tx_hex"])
    ok("a nonzero value changes the transaction id", unpaid["tx_id"] != paid["tx_id"])

    on_local = json.loads(qcore.sign_payable_call(seed, 0, target, "", 3, 21000, 9000, 0, LOCAL_CHAIN_ID, 300, 500))
    on_mainnet = json.loads(qcore.sign_payable_call(seed, 0, target, "", 3, 21000, 9000, 0, MAINNET_CHAIN_ID, 300, 500))
    on_testnet = json.loads(qcore.sign_payable_call(seed, 0, target, "", 3, 21000, 9000, 0, TESTNET_CHAIN_ID, 300, 500))
    ok("a different chain id changes the signed bytes", on_local["tx_hex"] != on_mainnet["tx_hex"])
    ok("mainnet and testnet chain ids sign to different bytes", on_mainnet["tx_hex"] != on_testnet["tx_hex"])
    ok("a different chain id changes the transaction id", on_local["tx_id"] != on_mainnet["tx_id"])

    upper = json.loads(qcore.sign_payable_call(seed, 0, target, "", 3, 21000, 9000, 10, TESTNET_CHAIN_ID, 300, 500))
    lower = json.loads(qcore.sign_payable_call(seed, 0, target.lower(), "", 3, 21000, 9000, 10, TESTNET_CHAIN_ID, 300, 500))
    ok("the target address case never changes the signed bytes", upper["tx_hex"] == lower["tx_hex"])
    ok("the target address case never changes the transaction id", upper["tx_id"] == lower["tx_id"])
    ok("the from field renders as an uppercase Q1 address", upper["from"].startswith("Q1"))

    for bad in ("not an address", "", "Q1zzzz", target[:-1] + ("q" if target[-1] != "q" else "p")):
        threw = False
        try:
            qcore.sign_payable_call(seed, 0, bad, "", 3, 21000, 9000, 0, LOCAL_CHAIN_ID, 300, 500)
        except ValueError:
            threw = True
        ok(f"a malformed target is refused: {bad!r}", threw)

    def refusal(fn):
        try:
            fn()
        except ValueError as err:
            return str(err)
        return None

    ok("a call pays one transfer fee per started 1210 meter",
       qcore.vm_call_fee(500, 21000) == 9000 and qcore.vm_call_fee(500, 1210) == 500
       and qcore.vm_call_fee(500, 1) == 500 and qcore.vm_call_fee(500, 1211) == 1000)
    low = refusal(lambda: qcore.sign_call(seed, 0, target, "", 3, 1209, 500, LOCAL_CHAIN_ID, 300, 500))
    ok("a meter limit below 1210 is refused", low is not None and "meter limit" in low)
    high = refusal(lambda: qcore.sign_payable_call(
        seed, 0, target, "", 3, 12_500_001, qcore.vm_call_fee(500, 12_500_001), 0, LOCAL_CHAIN_ID, 300, 500))
    ok("a meter limit above 12500000 is refused", high is not None and "meter limit" in high)
    ceiling = json.loads(qcore.sign_call(
        seed, 0, target, "", 3, 12_500_000, qcore.vm_call_fee(500, 12_500_000), LOCAL_CHAIN_ID, 300, 500))
    ok("the chain meter ceiling signs", bool(ceiling["tx_hex"]))
    big = refusal(lambda: qcore.sign_call(
        seed, 0, target, "00" * (128 * 1024 + 1), 3, 21000, 9000, LOCAL_CHAIN_ID, 300, 500))
    ok("call arguments above 128 KiB are refused", big is not None and "byte cap" in big)
    cheap = refusal(lambda: qcore.sign_call(seed, 0, target, "", 3, 21000, 8999, LOCAL_CHAIN_ID, 300, 500))
    ok("a fee below the meter fee is refused", cheap is not None and "below" in cheap)
    forever = refusal(lambda: qcore.sign_call(seed, 0, target, "", 3, 21000, 9000, LOCAL_CHAIN_ID, 0, 500))
    ok("a deadline of zero is refused", forever is not None and "never expires" in forever)
    ok("the testnet chain id follows the testnet network",
       TESTNET_CHAIN_ID == qcore.chain_id_from_name(qcore.Network.testnet().chain_id))
    capped = refusal(lambda: qcore.check_valid_until(1000 + 3600 + 1, 1000))
    ok("a deadline more than 3600 blocks past the head is refused",
       capped is not None and refusal(lambda: qcore.check_valid_until(1000 + 3600, 1000)) is None)

    if failures > 0:
        print("\npayable: " + str(failures) + " checks failed")
        sys.exit(1)
    print("\npayable: all cases passed")

if __name__ == "__main__":
    main()
