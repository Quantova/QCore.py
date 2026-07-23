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


def parse_body(hexstr):
    r = Reader(hexstr)
    sender = r.take(r.uint(8)).decode("ascii")
    nonce = r.uint(8)
    meter = r.uint(8)
    fee = r.uint(16)
    target = r.take(r.uint(8)).decode("ascii")
    args = r.take(r.uint(8)).hex()
    return {"sender": sender, "nonce": nonce, "meter": meter, "fee": fee,
            "target": target, "args": args, "length": r.at}


def address_vector():
    print("address.derivation")
    v = load("address.derivation.json")
    derived = qcore.address(v["master_seed"], v["index"])
    check("address matches the vector as bech32",
          bech32_equal(derived, v["canonical"]) and qcore.valid_address(derived), True)


def transaction_vector():
    print("transaction.transfer")
    v = load("transaction.transfer.json")

    sender = qcore.address(v["master_seed"], v["sender_index"])
    target = qcore.address(v["master_seed"], v["target_index"])
    check("sender derives to the vector sender", bech32_equal(sender, v["sender"]), True)
    check("target derives to the vector target", bech32_equal(target, v["target"]), True)

    signed = json.loads(qcore.sign_call(
        v["master_seed"], v["sender_index"], target, v["args"], v["nonce"], v["gas_limit"], v["fee"]))
    check("the signer address is the vector sender", bech32_equal(signed["from"], v["sender"]), True)

    want = parse_body(v["body_bytes"])
    got = parse_body(signed["tx_hex"])
    check("serialized sender field", bech32_equal(got["sender"], want["sender"]), True)
    check("serialized nonce field", got["nonce"] == want["nonce"], True)
    check("serialized meter field", got["meter"] == want["meter"], True)
    check("serialized fee field", got["fee"] == want["fee"], True)
    check("serialized target field", bech32_equal(got["target"], want["target"]), True)
    check("serialized args field", got["args"] == want["args"], True)
    check("body length matches the vector", got["length"] == want["length"], True)

    again = json.loads(qcore.sign_call(
        v["master_seed"], v["sender_index"], target, v["args"], v["nonce"], v["gas_limit"], v["fee"]))
    check("signing is deterministic", again["tx_hex"] == signed["tx_hex"], True)
    check("the transaction id is a qtx identifier",
          bool(re.match(r"^qtx1[0-9a-z]+$", signed["tx_id"], re.IGNORECASE)), True)


def main():
    address_vector()
    transaction_vector()
    if failures > 0:
        print("\nconformance: " + str(failures) + " checks failed")
        sys.exit(1)
    print("\nconformance: the Python binding matches the frozen vectors")


if __name__ == "__main__":
    main()
