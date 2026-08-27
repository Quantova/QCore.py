# Copyright 2026 Quantova Inc
# SPDX-License-Identifier: Apache-2.0 OR MIT

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

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def decode_payload_hex(address):
    lowered = address.lower()
    separator = lowered.rfind("1")
    groups = [CHARSET.index(c) for c in lowered[separator + 1:]]
    acc = 0
    bits = 0
    out = bytearray()
    for value in groups[:-6]:
        acc = (acc << 5) | value
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    return bytes(out).hex()

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
    sender = r.take(r.uint(8)).hex()
    nonce = r.uint(8)
    meter = r.uint(8)
    fee = r.uint(16)
    target = r.take(r.uint(8)).hex()
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
        v["nonce"], v["meter_limit"], v["fee"], v["value"], int(v["chain_id"])))
    check("the signer address is the vector sender", bech32_equal(signed["from"], v["sender"]), True)
    check("the from field renders uppercase Q1", signed["from"].startswith("Q1"), True)
    check("the signed bytes match the frozen QCore.js tx hex byte for byte",
          signed["tx_hex"], v["tx_hex"])
    check("the transaction id matches the frozen QCore.js vector", signed["tx_id"], v["tx_id"])

    got = parse_payable_body(signed["tx_hex"])
    check("the sender field is the raw 32 byte payload not the rendered string",
          got["sender"], decode_payload_hex(sender))
    check("the target field is the raw 32 byte payload not the rendered string",
          got["target"], decode_payload_hex(target))
    check("the serialized sender is 32 bytes", len(got["sender"]) == 64, True)
    check("the serialized target is 32 bytes", len(got["target"]) == 64, True)
    check("serialized value field", got["value"] == v["value"], True)
    check("serialized chain id field", got["chain_id"] == int(v["chain_id"]), True)

    again = json.loads(qcore.sign_payable_call(
        v["master_seed"], v["sender_index"], target, v["args"],
        v["nonce"], v["meter_limit"], v["fee"], v["value"], int(v["chain_id"])))
    check("signing is deterministic", again["tx_hex"] == signed["tx_hex"], True)

    lower = json.loads(qcore.sign_payable_call(
        v["master_seed"], v["sender_index"], target.lower(), v["args"],
        v["nonce"], v["meter_limit"], v["fee"], v["value"], int(v["chain_id"])))
    check("a lowercase target signs the same bytes", lower["tx_hex"] == signed["tx_hex"], True)

def main():
    payable_vector()
    if failures > 0:
        print("\npayable conformance: " + str(failures) + " checks failed")
        sys.exit(1)
    print("\npayable conformance: the Python binding matches the frozen vector")

if __name__ == "__main__":
    main()
