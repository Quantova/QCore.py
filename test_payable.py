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


LOCAL_CHAIN_ID = 0x5154_5644_4556_4E31
MAINNET_CHAIN_ID = 0x5154_4F56_4D41_494E
TESTNET_CHAIN_ID = 0x5154_4F56_5445_5354


def main():
    seed = "0b" * 32
    target = qcore.address(seed, 1)

    plain = json.loads(qcore.sign_call(seed, 0, target, "", 3, 21000, 500))
    payable = json.loads(qcore.sign_payable_call(seed, 0, target, "", 3, 21000, 500, 0, LOCAL_CHAIN_ID))
    ok("a payable call with no value on the local chain matches a plain call",
       payable["tx_hex"] == plain["tx_hex"])
    ok("a payable call with no value on the local chain matches a plain call's id",
       payable["tx_id"] == plain["tx_id"])

    unpaid = json.loads(qcore.sign_payable_call(seed, 0, target, "", 3, 21000, 500, 0, LOCAL_CHAIN_ID))
    paid = json.loads(qcore.sign_payable_call(seed, 0, target, "", 3, 21000, 500, 4200, LOCAL_CHAIN_ID))
    ok("a nonzero value changes the signed bytes", unpaid["tx_hex"] != paid["tx_hex"])
    ok("a nonzero value changes the transaction id", unpaid["tx_id"] != paid["tx_id"])

    on_local = json.loads(qcore.sign_payable_call(seed, 0, target, "", 3, 21000, 500, 0, LOCAL_CHAIN_ID))
    on_mainnet = json.loads(qcore.sign_payable_call(seed, 0, target, "", 3, 21000, 500, 0, MAINNET_CHAIN_ID))
    on_testnet = json.loads(qcore.sign_payable_call(seed, 0, target, "", 3, 21000, 500, 0, TESTNET_CHAIN_ID))
    ok("a different chain id changes the signed bytes", on_local["tx_hex"] != on_mainnet["tx_hex"])
    ok("mainnet and testnet chain ids sign to different bytes", on_mainnet["tx_hex"] != on_testnet["tx_hex"])
    ok("a different chain id changes the transaction id", on_local["tx_id"] != on_mainnet["tx_id"])

    upper = json.loads(qcore.sign_payable_call(seed, 0, target, "", 3, 21000, 500, 10, TESTNET_CHAIN_ID))
    lower = json.loads(qcore.sign_payable_call(seed, 0, target.lower(), "", 3, 21000, 500, 10, TESTNET_CHAIN_ID))
    ok("the target address case never changes the signed bytes", upper["tx_hex"] == lower["tx_hex"])
    ok("the target address case never changes the transaction id", upper["tx_id"] == lower["tx_id"])
    ok("the from field renders as an uppercase Q1 address", upper["from"].startswith("Q1"))

    for bad in ("not an address", "", "Q1zzzz", target[:-1] + ("q" if target[-1] != "q" else "p")):
        threw = False
        try:
            qcore.sign_payable_call(seed, 0, bad, "", 3, 21000, 500, 0, LOCAL_CHAIN_ID)
        except ValueError:
            threw = True
        ok(f"a malformed target is refused: {bad!r}", threw)

    if failures > 0:
        print("\npayable: " + str(failures) + " checks failed")
        sys.exit(1)
    print("\npayable: all cases passed")


if __name__ == "__main__":
    main()
