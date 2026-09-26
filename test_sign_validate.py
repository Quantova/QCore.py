# Copyright 2026 Quantova Inc
# SPDX-License-Identifier: Apache-2.0 OR MIT

import os
import sys

try:
    import qcore
except ModuleNotFoundError:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "python"))
    import qcore

def main():
    seed = "11" * 32
    own = qcore.address(seed, 0)
    good = qcore.address(seed, 1)

    chain = qcore.local_chain_id()

    signed = qcore.sign_transfer(seed, 0, good, 5, 0, 1, chain, 300)
    assert "tx_hex" in signed, "a valid recipient must sign"

    signed = qcore.sign_call(seed, 0, good, "", 0, 1210, 1, chain, 300, 1)
    assert "tx_hex" in signed, "a valid target must sign"

    for bad in ("not an address", "", "Q1zzzz", good[:-1] + ("q" if good[-1] != "q" else "p")):
        try:
            qcore.sign_transfer(seed, 0, bad, 5, 0, 1, chain, 300)
        except ValueError:
            pass
        else:
            raise AssertionError(f"sign_transfer signed a bad recipient {bad!r}")
        try:
            qcore.sign_call(seed, 0, bad, "", 0, 1210, 1, chain, 300, 1)
        except ValueError:
            pass
        else:
            raise AssertionError(f"sign_call signed a bad target {bad!r}")

    for recipient in (own, own.lower()):
        try:
            qcore.sign_transfer(seed, 0, recipient, 5, 0, 1, chain, 300)
        except ValueError as err:
            assert "self transfer" in str(err), str(err)
        else:
            raise AssertionError("a transfer to the sending account itself was signed")
    for sign in (
        lambda: qcore.sign_transfer(seed, 0, good, 5, 0, 1, chain, 0),
        lambda: qcore.sign_register(seed, 0, 0, 1, chain, 0),
        lambda: qcore.sign_call(seed, 0, good, "", 0, 1210, 1, chain, 0, 1),
    ):
        try:
            sign()
        except ValueError as err:
            assert "never expires" in str(err), str(err)
        else:
            raise AssertionError("a validity deadline of zero was signed")

    print("exported sign validation: all cases passed")

if __name__ == "__main__":
    main()
