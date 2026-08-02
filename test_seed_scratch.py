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

    first = qcore.sign_transfer(seed, 0, address, 1000, 3, 500, chain)
    second = qcore.sign_transfer(seed, 0, address, 1000, 3, 500, chain)
    assert first == second, "signing stays deterministic after the seed routes through wiped scratch"

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
