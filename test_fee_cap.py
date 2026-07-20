# Prove the fee ceiling with no running gateway, so this runs anywhere. A small mock gateway
# reports a fee, and the client must submit only when the fee is at or below the ceiling the
# caller allowed, must refuse and never submit when the fee is above it, and must reject a
# missing or malformed ceiling before it ever touches the network. Run with: python3 test_fee_cap.py

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

try:
    import qcore
except ModuleNotFoundError:
    # Fall back to the in tree package so the test runs from the repo without an install.
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "python"))
    import qcore

state = {"fee": "100", "submitted": 0}


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
            send({"chain_id": "Q-test-net-1", "head_height": 10, "denomination": "Quon",
                  "fee": {"transfer_quon": state["fee"], "quon_per_qtov": "1000000"}, "version": "test"})
        elif self.path == "/v1/get_account":
            send({"address": body["address"], "nonce": 0, "balance": "0", "scheme": 1, "has_key": True})
        elif self.path == "/v1/submit_transaction":
            state["submitted"] += 1
            send({"verdict": "accepted", "state": "fresh", "tx_id": "Qtxabc"})
        else:
            send({"error": "unknown_method", "message": self.path}, 404)


def fail(message):
    print("FAIL " + message)
    sys.exit(1)


def main():
    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    client = qcore.Client(f"http://127.0.0.1:{server.server_address[1]}")
    seed = "0b" * 32
    to = qcore.address(seed, 1)

    # A fee at or below the ceiling signs and submits once.
    state["fee"] = "100"
    _, outcome = client.transfer(seed, 0, to, 1000, 1000)
    if outcome["verdict"] != "accepted":
        fail("a fee below the ceiling should be accepted")
    if state["submitted"] != 1:
        fail("an allowed transfer submits exactly once")

    # A fee above the ceiling is refused and never submits.
    state["fee"] = "5000"
    refused = False
    try:
        client.transfer(seed, 0, to, 1000, 1000)
    except ValueError as err:
        refused = True
        if "above the maximum" not in str(err):
            fail("wrong refusal message: " + str(err))
    if not refused:
        fail("a fee above the ceiling must be refused")
    if state["submitted"] != 1:
        fail("a refused transfer must never submit")

    # The ceiling is inclusive at the boundary.
    state["fee"] = "1000"
    _, outcome = client.transfer(seed, 0, to, 1000, 1000)
    if outcome["verdict"] != "accepted" or state["submitted"] != 2:
        fail("a fee equal to the ceiling is allowed")

    # A missing or malformed ceiling fails before any network call.
    for bad in (None, "abc", -1):
        threw = False
        try:
            client.transfer(seed, 0, to, 1000, bad)
        except ValueError as err:
            threw = True
            if "maximum fee" not in str(err):
                fail("unclear ceiling error: " + str(err))
        if not threw:
            fail("a bad ceiling must be rejected: " + repr(bad))
    if state["submitted"] != 2:
        fail("a bad ceiling must fail before submitting")

    server.shutdown()
    print("fee ceiling: all cases passed")


if __name__ == "__main__":
    main()
