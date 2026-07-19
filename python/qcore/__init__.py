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
    sign_transfer,
    submit_body,
    account_body,
    transaction_body,
    block_by_height_body,
)

__all__ = [
    "Client",
    "address",
    "sign_transfer",
    "submit_body",
    "account_body",
    "transaction_body",
    "block_by_height_body",
]


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
                return json.loads(res.read())
        except urllib.error.HTTPError as err:
            data = json.loads(err.read())
            raise RuntimeError(data.get("message") or data.get("error") or f"status {err.code}")

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

    def transfer(self, seed_hex, index, to, amount):
        """Read the fee and the nonce, sign in the core, and submit. Nothing is signed or
        built in Python."""
        info = self.node_info()
        sender = address(seed_hex, index)
        acct = self.account(sender)
        signed = json.loads(
            sign_transfer(
                seed_hex,
                index,
                to,
                int(amount),
                int(acct["nonce"]),
                int(info["fee"]["transfer_qgas"]),
            )
        )
        outcome = self.submit(signed["tx_hex"])
        return signed, outcome
