# Copyright 2026 Quantova Inc
# SPDX-License-Identifier: Apache-2.0 OR MIT

import os
import sys

try:
    import qcore
except ModuleNotFoundError:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "python"))
    import qcore

from qcore import Client, Network

failures = 0


def ok(label, cond):
    global failures
    if cond:
        print("  ok   " + label)
    else:
        failures += 1
        print("  FAIL " + label)


def throws(label, fn):
    threw = False
    try:
        fn()
    except Exception:
        threw = True
    ok(label, threw)


def main():
    testnet = Network.testnet()
    ok("testnet chain id", testnet.chain_id == "Q-test-net-1")
    ok("testnet rpc url", testnet.rpc_url == "https://rpc-testnet.quantova.org")
    ok("testnet denomination", testnet.denomination == "Quon")
    ok("testnet decimals are six", testnet.decimals == 6)
    ok("testnet is not mainnet", testnet.is_mainnet is False)
    ok("mainnet is flagged", Network.mainnet().is_mainnet is True)
    ok("mainnet rpc is not the testnet url", Network.mainnet().rpc_url != testnet.rpc_url)

    client = Client(testnet)
    ok("testnet client carries its network", client.network.chain_id == "Q-test-net-1")

    live_mainnet = Network(name="mainnet", chain_id="Q-main-net-1",
                           rpc_url="https://rpc.quantova.org", is_mainnet=True)
    throws("mainnet client without acknowledgement is refused", lambda: Client(live_mainnet))
    acked = None
    try:
        acked = Client(live_mainnet, acknowledge_mainnet=True)
    except Exception:
        acked = None
    ok("mainnet client opens with acknowledgement", acked is not None)

    over_url = Client("https://rpc-testnet.quantova.org")
    ok("a plain url client is not forced to acknowledge mainnet by any gateway string",
       over_url._guard_mainnet() is None)
    hostile_mainnet = Client("https://rpc.quantova.org", network=Network.mainnet())
    throws("a configured mainnet network is refused when not acknowledged, whatever the gateway reports",
           lambda: hostile_mainnet._guard_mainnet())
    over_url_acked = Client("https://rpc.quantova.org", acknowledge_mainnet=True, network=Network.mainnet())
    ok("an acknowledged mainnet client passes the guard",
       over_url_acked._guard_mainnet() is None)

    if failures > 0:
        print("\nnetwork: " + str(failures) + " checks failed")
        sys.exit(1)
    print("\nnetwork: the safety gate holds")


if __name__ == "__main__":
    main()
