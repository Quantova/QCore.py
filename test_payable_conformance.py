import json
import os
import re
import sys

try:
    import qcore
except ModuleNotFoundError:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "python"))
    import qcore

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, "conformance")

failures = 0


def load(name):
    with open(os.path.join(VECTORS, name), "r", encoding="utf8") as handle:
        return json.load(handle)


def check(label, got, want):
    global failures
    if got == want:
        print("  ok   " + label)
    else:
        failures += 1
        print("  FAIL " + label + "\n         got  " + repr(got) + "\n         want " + repr(want))


def bech32_equal(a, b):
    return str(a).lower() == str(b).lower()


class Reader:
    def __init__(self, hexstr):
        self.data = bytes.fromhex(hexstr)
        self.at = 0

    def uint(self, n):
        value = int.from_bytes(self.data[self.at:self.at + n], "little")
        self.at += n
        return value

    def take(self, n):
        chunk = self.data[self.at:self.at + n]
        self.at += n
        return chunk


def parse_payable_body(hexstr):
    r = Reader(hexstr)
    sender = r.take(r.uint(8)).decode("ascii")
    nonce = r.uint(8)
    meter = r.uint(8)
    fee = r.uint(16)
    target = r.take(r.uint(8)).decode("ascii")
    args = r.take(r.uint(8)).hex()
    value = r.uint(8)
    chain_id = r.uint(8)
    return {"sender": sender, "nonce": nonce, "meter": meter, "fee": fee,
            "target": target, "args": args, "value": value, "chain_id": chain_id,
            "length": r.at}


def payable_vector():
    print("transaction.payable")
    v = load("transaction.payable.json")

    sender = qcore.address(v["master_seed"], v["sender_index"])
    target = qcore.address(v["master_seed"], v["target_index"])
    check("sender derives to the vector sender", bech32_equal(sender, v["sender"]), True)
    check("target derives to the vector target", bech32_equal(target, v["target"]), True)
    check("the derived sender renders uppercase Q1", sender.startswith("Q1"), True)
    check("the derived target renders uppercase Q1", target.startswith("Q1"), True)

    signed = json.loads(qcore.sign_payable_call(
        v["master_seed"], v["sender_index"], target, v["args"],
        v["nonce"], v["gas_limit"], v["fee"], v["value"], v["chain_id"]))
    check("the signer address is the vector sender", bech32_equal(signed["from"], v["sender"]), True)
    check("the from field renders uppercase Q1", signed["from"].startswith("Q1"), True)

    want = parse_payable_body(v["body_bytes"])
    got = parse_payable_body(signed["tx_hex"])
    check("serialized sender field", bech32_equal(got["sender"], want["sender"]), True)
    check("the serialized sender is uppercase Q1", got["sender"].startswith("Q1"), True)
    check("serialized nonce field", got["nonce"] == want["nonce"], True)
    check("serialized meter field", got["meter"] == want["meter"], True)
    check("serialized fee field", got["fee"] == want["fee"], True)
    check("serialized target field", bech32_equal(got["target"], want["target"]), True)
    check("the serialized target is uppercase Q1", got["target"].startswith("Q1"), True)
    check("serialized args field", got["args"] == want["args"], True)
    check("serialized value field", got["value"] == want["value"], True)
    check("serialized chain_id field", got["chain_id"] == want["chain_id"], True)
    check("body length matches the vector", got["length"] == want["length"], True)

    again = json.loads(qcore.sign_payable_call(
        v["master_seed"], v["sender_index"], target, v["args"],
        v["nonce"], v["gas_limit"], v["fee"], v["value"], v["chain_id"]))
    check("signing is deterministic", again["tx_hex"] == signed["tx_hex"], True)
    check("the transaction id matches the vector", bech32_equal(signed["tx_id"], v["tx_id"]), True)
    check("the transaction id is a qtx identifier",
          bool(re.match(r"^qtx1[0-9a-z]+$", signed["tx_id"], re.IGNORECASE)), True)


def main():
    payable_vector()
    if failures > 0:
        print("\npayable conformance: " + str(failures) + " checks failed")
        sys.exit(1)
    print("\npayable conformance: the Python binding matches the frozen vector")


if __name__ == "__main__":
    main()
