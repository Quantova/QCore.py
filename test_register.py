import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

try:
    import qcore
except ModuleNotFoundError:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "python"))
    import qcore

state = {"fee": "100", "submitted": 0, "last_tx": None, "asked_account": None}


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
            state["asked_account"] = body["address"]
            send({"address": body["address"], "nonce": 0, "balance": "5000", "scheme": 1, "has_key": False})
        elif self.path == "/v1/submit_transaction":
            state["submitted"] += 1
            state["last_tx"] = body.get("tx")
            send({"verdict": "accepted", "state": "fresh", "tx_id": "Qtxreg"})
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
    sender = qcore.address(seed, 0)

    state["fee"] = "100"
    signed, outcome = client.register(seed, 0, 1000)
    if outcome["verdict"] != "accepted":
        fail("a fee below the ceiling should be accepted")
    if state["submitted"] != 1:
        fail("an allowed registration submits exactly once")
    if signed["from"] != sender:
        fail("a registration must be sent from the account registering its own key")
    if not signed["tx_hex"] or state["last_tx"] != signed["tx_hex"]:
        fail("the submitted transaction must be the signed registration bytes")
    if state["asked_account"] != sender:
        fail("register must read the nonce of the account it registers")
    transfer_signed = json.loads(qcore.sign_transfer(seed, 0, sender, 1000, 0, 100, qcore.local_chain_id()))
    if signed["tx_hex"] == transfer_signed["tx_hex"]:
        fail("a registration must not be identical to a transfer")

    state["fee"] = "5000"
    refused = False
    try:
        client.register(seed, 0, 1000)
    except ValueError as err:
        refused = True
        if "above the maximum" not in str(err):
            fail("wrong refusal message: " + str(err))
    if not refused:
        fail("a fee above the ceiling must be refused")
    if state["submitted"] != 1:
        fail("a refused registration must never submit")

    state["fee"] = "1000"
    _, outcome = client.register(seed, 0, 1000)
    if outcome["verdict"] != "accepted" or state["submitted"] != 2:
        fail("a fee equal to the ceiling is allowed")

    for bad in (None, "abc", -1):
        threw = False
        try:
            client.register(seed, 0, bad)
        except ValueError as err:
            threw = True
            if "maximum fee" not in str(err):
                fail("unclear ceiling error: " + str(err))
        if not threw:
            fail("a bad ceiling must be rejected: " + repr(bad))
    if state["submitted"] != 2:
        fail("a bad ceiling must fail before submitting")

    server.shutdown()
    print("register: all cases passed")


if __name__ == "__main__":
    main()
