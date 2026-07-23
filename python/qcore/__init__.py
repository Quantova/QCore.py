"""The Quantova client core for Python."""

import ipaddress
import json
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request

from ._native import (
    address,
    valid_address,
    mnemonic_from_seed,
    seed_from_mnemonic,
    sign_transfer,
    sign_call,
    sign_payable_call,
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
    "Network",
    "generate_seed",
    "address",
    "valid_address",
    "mnemonic_from_seed",
    "seed_from_mnemonic",
    "sign_transfer",
    "sign_call",
    "sign_payable_call",
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


def _is_loopback(host):
    if host is None:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _require_safe_transport(base):
    parts = urllib.parse.urlsplit(base)
    if parts.scheme not in ("http", "https"):
        raise ValueError("the gateway base must start with http:// or https://")
    if parts.scheme == "http" and not _is_loopback(parts.hostname):
        raise ValueError(
            f"refusing plaintext http to a non loopback gateway ({parts.hostname}); its fee "
            "and nonce would be unauthenticated and rewritable to drain funds, use https or a "
            "loopback node"
        )
    return base


def _fee_ceiling(max_fee):
    try:
        ceiling = int(max_fee)
    except (TypeError, ValueError):
        raise ValueError("the maximum fee must be an integer number of Quon")
    if ceiling < 0:
        raise ValueError("the maximum fee cannot be negative")
    return ceiling


DENOMINATION = "Quon"
DECIMALS = 6


class Network:
    def __init__(self, name, chain_id=None, rpc_url=None, explorer_url=None,
                 denomination=DENOMINATION, decimals=DECIMALS, is_mainnet=False):
        self.name = name
        self.chain_id = chain_id
        self.rpc_url = rpc_url
        self.explorer_url = explorer_url
        self.denomination = denomination
        self.decimals = decimals
        self.is_mainnet = is_mainnet is True

    @classmethod
    def testnet(cls):
        return cls(name="testnet", chain_id="Q-test-net-1",
                   rpc_url="https://rpc-testnet.quantova.org",
                   explorer_url="https://qvmscan.io", is_mainnet=False)

    @classmethod
    def mainnet(cls):
        return cls(name="mainnet", chain_id="Q-main-net-1", rpc_url=None,
                   explorer_url="https://qvmscan.io", is_mainnet=True)

    @classmethod
    def for_url(cls, base):
        return cls(name="custom", chain_id=None, rpc_url=base, is_mainnet=False)


def _chain_id_looks_like_mainnet(chain_id):
    if not chain_id:
        return False
    return re.search(r"test|dev|local", str(chain_id), re.IGNORECASE) is None


class Client:
    def __init__(self, target, acknowledge_mainnet=False, network=None):
        self.acknowledge_mainnet = acknowledge_mainnet is True
        if isinstance(target, Network):
            self.network = target
            base = target.rpc_url
            if not base:
                raise ValueError(
                    f"the {target.name} network has no rpc endpoint yet, pass the endpoint "
                    "explicitly with Client(url)"
                )
            if target.is_mainnet and not self.acknowledge_mainnet:
                raise ValueError(
                    "refusing to open a mainnet client without acknowledge_mainnet True, a "
                    "mainnet transaction moves real value so the network must be chosen on purpose"
                )
        else:
            base = str(target)
            self.network = network if isinstance(network, Network) else Network.for_url(base)
        self.base = _require_safe_transport(base).rstrip("/")

    def _guard_mainnet(self, chain_id):
        on_mainnet = (self.network is not None and self.network.is_mainnet) or _chain_id_looks_like_mainnet(chain_id)
        if on_mainnet and not self.acknowledge_mainnet:
            label = chain_id or (self.network.chain_id if self.network else "")
            raise ValueError(
                f"refusing to sign for the mainnet chain {label} without acknowledge_mainnet "
                "True, pass it when you mean to move real value"
            )

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
        self._guard_mainnet(info.get("chain_id") if isinstance(info, dict) else None)
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
        self._guard_mainnet(info.get("chain_id") if isinstance(info, dict) else None)
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
        self._guard_mainnet(info.get("chain_id") if isinstance(info, dict) else None)
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
