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
    seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    chain = qcore.testnet_chain_id()

    address = qcore.address(seed, 0)
    assert address.startswith("Q1"), "the seed decodes through the zeroizing scratch to an address"

    recipient = qcore.address(seed, 1)
    first = qcore.sign_transfer(seed, 0, recipient, 1000, 3, 500, chain, 310)
    second = qcore.sign_transfer(seed, 0, recipient, 1000, 3, 500, chain, 310)
    assert first == second, "signing stays deterministic after the seed routes through wiped scratch"

    phrase = qcore.mnemonic_from_seed(seed)
    messy = "  " + "   ".join(phrase.upper().split(" ")) + "\n"
    assert qcore.seed_from_mnemonic(messy) == seed, "case and spacing do not change the restored seed"
    wide = "".join(chr(ord(c) - 97 + 0xFF41) if "a" <= c <= "z" else c for c in phrase)
    assert qcore.seed_from_mnemonic(wide) == seed, "full width letters restore the same seed"
    try:
        qcore.seed_from_mnemonic(" ".join(["abandon"] * 11 + ["about"]))
    except ValueError as err:
        assert "standard BIP-39" in str(err), str(err)
    else:
        raise AssertionError("a standard BIP-39 phrase was restored as a Quantova phrase")
    try:
        qcore.seed_from_mnemonic(" ".join(["abandon"] * 24))
    except ValueError as err:
        assert "typo" in str(err), str(err)
    else:
        raise AssertionError("a phrase with a bad checksum was restored")

    for bad in ("00", "ab" * 33, "zz" * 32):
        try:
            qcore.address(bad, 0)
        except ValueError:
            pass
        else:
            raise AssertionError(f"a seed that is not thirty two bytes was accepted {bad!r}")

    print("seed scratch: decode through the zeroizing handle passed")

if __name__ == "__main__":
    main()
