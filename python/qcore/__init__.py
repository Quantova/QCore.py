"""The Quantova client core for Python."""

import json
import secrets
import urllib.error
import urllib.request

from ._native import (
    address,
    valid_address,
    mnemonic_from_seed,
    seed_from_mnemonic,
    sign_transfer,
    sign_call,
    sign_register,
    submit_body,
    account_body,
    transaction_body,
    block_by_height_body,
)

def generate_seed():
    return secrets.token_bytes(32).hex()


__all__ = [
    "Client",
    "generate_seed",
    "address",
    "valid_address",
    "mnemonic_from_seed",
    "seed_from_mnemonic",
    "sign_transfer",
    "sign_call",
    "sign_register",
    "submit_body",
    "account_body",
    "transaction_body",
    "block_by_height_body",
]

_MAX_RESPONSE = 8 * 1024 * 1024


def _loads(raw):
    try:
        return json.loads(raw)
    except (ValueError, RecursionError):
        raise RuntimeError("the gateway returned a response that is not valid JSON")


def _fee_ceiling(max_fee):
    try:
        ceiling = int(max_fee)
    except (TypeError, ValueError):
        raise ValueError("the maximum fee must be an integer number of Quon")
    if ceiling < 0:
        raise ValueError("the maximum fee cannot be negative")
    return ceiling


class Client:
    def __init__(self, base):
        self.base = str(base).rstrip("/")

    def _call(self, method, body):
        req = urllib.request.Request(
            f"{self.base}/v1/{method}",
            data=(body or "{}").encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as res:
                raw = res.read(_MAX_RESPONSE + 1)
                if len(raw) > _MAX_RESPONSE:
                    raise RuntimeError("the response is too large")
                return _loads(raw)
        except urllib.error.HTTPError as err:
            data = _loads(err.read(_MAX_RESPONSE))
            message = data.get("message") or data.get("error") if isinstance(data, dict) else None
            raise RuntimeError(message or f"status {err.code}")

    def node_info(self):
        return self._call("node_info", "{}")

    def head(self):
        return self._call("head", "{}")

    def account(self, addr):
        return self._call("get_account", account_body(addr))

    def transaction(self, tx_id):
        return self._call("get_transaction", transaction_body(tx_id))

    def block(self, height):
        return self._call("get_block", block_by_height_body(height))

    def submit(self, tx_hex):
        return self._call("submit_transaction", submit_body(tx_hex))

    def address(self, seed_hex, index):
        return address(seed_hex, index)

    def transfer(self, seed_hex, index, to, amount, max_fee):
        if not valid_address(to):
            raise ValueError("the recipient is not a Q1 address")
        ceiling = _fee_ceiling(max_fee)
        info = self.node_info()
        fee = info.get("fee", {}).get("transfer_quon") if isinstance(info, dict) else None
        if fee is None:
            raise RuntimeError("the gateway did not report a transfer fee")
        if int(fee) > ceiling:
            raise ValueError(
                f"the gateway fee {fee} is above the maximum you allowed {max_fee}, refusing to sign"
            )
        sender = address(seed_hex, index)
        acct = self.account(sender)
        nonce = acct.get("nonce") if isinstance(acct, dict) else None
        if nonce is None:
            raise RuntimeError("the gateway did not report a nonce")
        signed = _loads(sign_transfer(seed_hex, index, to, int(amount), int(nonce), int(fee)))
        outcome = self.submit(signed["tx_hex"])
        return signed, outcome

    def register(self, seed_hex, index, max_fee):
        ceiling = _fee_ceiling(max_fee)
        info = self.node_info()
        fee = info.get("fee", {}).get("transfer_quon") if isinstance(info, dict) else None
        if fee is None:
            raise RuntimeError("the gateway did not report a transfer fee")
        if int(fee) > ceiling:
            raise ValueError(
                f"the gateway fee {fee} is above the maximum you allowed {max_fee}, refusing to sign"
            )
        sender = address(seed_hex, index)
        acct = self.account(sender)
        nonce = acct.get("nonce") if isinstance(acct, dict) else None
        if nonce is None:
            raise RuntimeError("the gateway did not report a nonce")
        signed = _loads(sign_register(seed_hex, index, int(nonce), int(fee)))
        outcome = self.submit(signed["tx_hex"])
        return signed, outcome

    def call(self, seed_hex, index, target, args_hex, meter_limit, max_fee):
        if not valid_address(target):
            raise ValueError("the target is not a Q1 address")
        ceiling = _fee_ceiling(max_fee)
        info = self.node_info()
        fee = info.get("fee", {}).get("transfer_quon") if isinstance(info, dict) else None
        if fee is None:
            raise RuntimeError("the gateway did not report a transfer fee")
        if int(fee) > ceiling:
            raise ValueError(
                f"the gateway fee {fee} is above the maximum you allowed {max_fee}, refusing to sign"
            )
        sender = address(seed_hex, index)
        acct = self.account(sender)
        nonce = acct.get("nonce") if isinstance(acct, dict) else None
        if nonce is None:
            raise RuntimeError("the gateway did not report a nonce")
        signed = _loads(sign_call(seed_hex, index, target, args_hex, int(nonce), int(meter_limit), int(fee)))
        outcome = self.submit(signed["tx_hex"])
        return signed, outcome
