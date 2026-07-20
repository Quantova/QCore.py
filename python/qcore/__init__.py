"""The Quantova client core for Python.

The key derivation, the post quantum signing, and every RPC request body come from the
Rust core, exposed here as the native extension. This module only does the HTTP and reads
the documented response fields, so nothing is signed or built in Python.
"""

import json
import urllib.error
import urllib.request

from ._native import (
    address,
    valid_address,
    mnemonic_from_seed,
    seed_from_mnemonic,
    sign_transfer,
    sign_call,
    submit_body,
    account_body,
    transaction_body,
    block_by_height_body,
)

__all__ = [
    "Client",
    "address",
    "valid_address",
    "mnemonic_from_seed",
    "seed_from_mnemonic",
    "sign_transfer",
    "sign_call",
    "submit_body",
    "account_body",
    "transaction_body",
    "block_by_height_body",
]

# The largest reply the client will hold, so a hostile gateway cannot exhaust memory with an
# unbounded body.
_MAX_RESPONSE = 8 * 1024 * 1024


def _loads(raw):
    try:
        return json.loads(raw)
    except (ValueError, RecursionError):
        raise RuntimeError("the gateway returned a response that is not valid JSON")


class Client:
    """A client bound to a gateway base url, for example http://127.0.0.1:8645."""

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
        """Read the fee and the nonce, sign in the core, and submit. The caller passes the highest
        fee it will accept as max_fee, and the shortcut refuses to sign if the gateway reports a fee
        above it, so a hostile or rewritten gateway cannot inflate the fee and drain the signer.
        Nothing is signed in Python."""
        if not valid_address(to):
            raise ValueError("the recipient is not a q1 address")
        info = self.node_info()
        fee = info.get("fee", {}).get("transfer_quon") if isinstance(info, dict) else None
        if fee is None:
            raise RuntimeError("the gateway did not report a transfer fee")
        if int(fee) > int(max_fee):
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

    def call(self, seed_hex, index, target, args_hex, meter_limit, max_fee):
        """Read the fee and the nonce, sign a call to a target in the core, and submit. A
        contract deploy or call runs the same path as a transfer, only the target and the
        arguments differ. Like transfer, the caller passes the highest fee it will accept as
        max_fee and the shortcut refuses a gateway fee above it."""
        if not valid_address(target):
            raise ValueError("the target is not a q1 address")
        info = self.node_info()
        fee = info.get("fee", {}).get("transfer_quon") if isinstance(info, dict) else None
        if fee is None:
            raise RuntimeError("the gateway did not report a transfer fee")
        if int(fee) > int(max_fee):
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
