# Copyright 2026 Quantova Inc
# SPDX-License-Identifier: Apache-2.0 OR MIT

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

try:
    import quantova_qcore as qcore
except ModuleNotFoundError:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "python"))
    import quantova_qcore as qcore

state = {"nonce": 0, "submitted": 0, "head": 10, "verdict": "accepted"}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")

        def send(obj, code=200):
            payload = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        if self.path == "/v1/node_info":
            send({"chain_id": "Q-dev-net-1", "head_height": state["head"], "denomination": "Quon",
                  "fee": {"transfer_quon": "500", "quon_per_qtov": "1000000"}, "version": "test"})
        elif self.path == "/v1/get_account":
            reply = {"nonce": state["nonce"], "balance": "0", "scheme": 1, "has_key": True}
            if not state.get("anonymous"):
                reply["address"] = body["address"]
            send(reply)
        elif self.path == "/v1/submit_transaction":
            state["submitted"] += 1
            if state["verdict"] == "rejected":
                send({"verdict": "rejected", "reason": "insufficient_funds"})
            else:
                send({"verdict": "accepted", "state": "fresh", "tx_id": "Qtxabc"})
        else:
            send({"error": "unknown_method", "message": self.path}, 404)

def fail(message):
    print("FAIL " + message)
    sys.exit(1)

def main():
    for bad in (1.5, 4.9, 2.0, -1, 2 ** 64, "1.5", "5", " 5", "+5", "5_0", "\u0665", True):
        try:
            qcore._gateway_integer(bad, "nonce")
            fail(f"a bad nonce {bad!r} was accepted")
        except RuntimeError:
            pass
    for good, expected in ((5, 5), (2 ** 64 - 1, 2 ** 64 - 1), (9007199254740993, 9007199254740993)):
        if qcore._gateway_integer(good, "nonce") != expected:
            fail(f"a good nonce {good!r} was not accepted exactly")
    for bad in ("+500", " 500", "500 ", "5_00", "\u0665\u0660\u0660", "", 500, None):
        try:
            qcore._transfer_fee({"fee": {"transfer_quon": bad}})
            fail(f"a bad transfer fee {bad!r} was accepted")
        except RuntimeError:
            pass
    if qcore._transfer_fee({"fee": {"transfer_quon": "500"}}) != 500:
        fail("a plain digit transfer fee was not accepted")

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    client = qcore.Client(f"http://127.0.0.1:{server.server_address[1]}")
    seed = bytes.fromhex("0b" * 32)
    to = qcore.address(seed, 1)

    state["nonce"] = 4.9
    try:
        client.transfer(seed, 0, to, "1000", "1000000")
        fail("a float nonce from the gateway was signed")
    except RuntimeError:
        pass
    if state["submitted"] != 0:
        fail("a refused float nonce still reached submit")

    state["nonce"] = 7
    client.transfer(seed, 0, to, "1000", "1000000")
    if state["submitted"] != 1:
        fail("an honest nonce did not submit exactly once")

    state["nonce"] = 0
    fresh = qcore.Client(f"http://127.0.0.1:{server.server_address[1]}")
    signed, _ = fresh.transfer(seed, 0, to, "1000", "1000000")
    chain_id = qcore.chain_id_from_name("Q-dev-net-1")
    expected = json.loads(qcore.sign_transfer(seed, 0, to, 1000, 0, 500, chain_id, 310))
    if signed["tx_hex"] != expected["tx_hex"]:
        fail("a client transfer did not expire 300 blocks past the head")
    later = json.loads(qcore.sign_transfer(seed, 0, to, 1000, 0, 500, chain_id, 311))
    if later["tx_hex"] == expected["tx_hex"]:
        fail("the validity window is not part of what is signed")
    try:
        qcore.sign_transfer(seed, 0, to, 1000, 0, 500, chain_id, 0)
        fail("a deadline of zero that never expires was signed")
    except ValueError:
        pass

    held = state["submitted"]
    for reported in (7, 3):
        state["nonce"] = reported
        for path in (
            lambda: client.call(seed, 0, to, "01", 21000, "1000000", expected_nonce=5),
            lambda: client.register(seed, 0, "1000000", expected_nonce=5),
        ):
            try:
                path()
                fail("an expected nonce other than the reported one was signed")
            except RuntimeError as err:
                if "you expected 5" not in str(err):
                    fail("unclear expected nonce error: " + str(err))
    if state["submitted"] != held:
        fail("a contradicted expected nonce still reached submit")
    state["nonce"] = 0
    try:
        client.call(seed, 0, to, "01", 21000, "1000", expected_nonce=0)
        fail("a call whose meter fee passes the ceiling was signed")
    except ValueError as err:
        if "above the maximum" not in str(err):
            fail("unclear meter fee error: " + str(err))
    client.call(seed, 0, to, "01", 21000, "1000000", expected_nonce=0)

    stuck = qcore.Client(f"http://127.0.0.1:{server.server_address[1]}")
    state["nonce"] = 3
    stuck.transfer(seed, 0, to, "1000", "1000000")
    try:
        stuck.transfer(seed, 0, to, "1000", "1000000")
        fail("a second signature at a held nonce was produced without the caller naming it")
    except RuntimeError as err:
        if "already signed" not in str(err):
            fail("unclear held nonce error: " + str(err))
    signed, _ = stuck.transfer(seed, 0, to, "1000", "1000000", expected_nonce=3)
    again = json.loads(qcore.sign_transfer(seed, 0, to, 1000, 3, 500, chain_id, 310))
    if signed["tx_hex"] != again["tx_hex"]:
        fail("a submission that never landed pushed the next one past the nonce the chain admits")
    state["nonce"] = 9
    signed, _ = stuck.transfer(seed, 0, to, "1000", "1000000")
    at_nine = json.loads(qcore.sign_transfer(seed, 0, to, 1000, 9, 500, chain_id, 310))
    if signed["tx_hex"] != at_nine["tx_hex"]:
        fail("a gateway nonce above the local one must be signed at, not refused")
    if stuck._session.next_nonce(signed["from"]) != 10:
        fail("the local next nonce did not follow the highest nonce seen")

    retry = qcore.Client(f"http://127.0.0.1:{server.server_address[1]}")
    state["nonce"] = 3
    state["verdict"] = "rejected"
    _, outcome = retry.transfer(seed, 0, to, "1", "1000000")
    if outcome["verdict"] != "rejected":
        fail("the stub gateway should reject this send")
    state["verdict"] = "accepted"
    try:
        retry.transfer(seed, 0, to, "2", "1000000")
        fail("a gateway rejection must not free a signed nonce on its own")
    except RuntimeError as err:
        if "already signed" not in str(err):
            fail("unclear held nonce error: " + str(err))
    _, outcome = retry.transfer(seed, 0, to, "2", "1000000", expected_nonce=3)
    if outcome["verdict"] != "accepted":
        fail("naming the nonce explicitly did not override the hold")
    retry._validity({"head_height": 250})
    try:
        retry._validity({"head_height": 200})
        fail("a head below the highest one seen was accepted")
    except RuntimeError as err:
        if "below the 250" not in str(err):
            fail("unclear head floor error: " + str(err))
    state["head"] = 400
    try:
        retry.transfer(seed, 0, to, "4", "1000000")
        fail("a gateway head past the deadline freed a nonce before blocks could have been made")
    except RuntimeError as err:
        if "already signed" not in str(err):
            fail("unclear held nonce error: " + str(err))
    state["nonce"] = 4
    _, outcome = retry.transfer(seed, 0, to, "4", "1000000")
    if outcome["verdict"] != "accepted":
        fail("a nonce the gateway reports past an accepted send was not signed")
    state["verdict"] = "rejected"
    state["nonce"] = 5
    retry.transfer(seed, 0, to, "5", "1000000")
    state["verdict"] = "accepted"
    state["nonce"] = 6
    try:
        retry.transfer(seed, 0, to, "5", "1000000")
        fail("a gateway that rejected a send and then reported the next nonce got a second signature")
    except RuntimeError as err:
        if "was not accepted" not in str(err):
            fail("unclear skipped nonce error: " + str(err))
    _, outcome = retry.transfer(seed, 0, to, "5", "1000000", expected_nonce=6)
    if outcome["verdict"] != "accepted":
        fail("naming the nonce did not let the caller vouch for the earlier send")
    state["head"] = 10

    state["anonymous"] = True
    try:
        client.account(to)
        fail("an account reply naming no address was trusted")
    except RuntimeError:
        pass
    state["anonymous"] = False

    print("ok nonce validate")

if __name__ == "__main__":
    main()
