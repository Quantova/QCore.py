# Copyright 2026 Quantova Inc
# SPDX-License-Identifier: Apache-2.0 OR MIT

"""The Quantova client core for Python."""

import ipaddress
import json
import secrets
import time
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
    build_typed_order_call,
    chain_id_from_name,
    local_chain_id,
    testnet_chain_id,
    mainnet_chain_id,
    submit_body,
    account_body,
    transaction_body,
    block_by_height_body,
)

def generate_seed():
    return secrets.token_bytes(32).hex()


def _is_mainnet_id(chain_id):
    return chain_id == mainnet_chain_id()


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
    "build_typed_order_call",
    "chain_id_from_name",
    "local_chain_id",
    "testnet_chain_id",
    "mainnet_chain_id",
    "submit_body",
    "account_body",
    "transaction_body",
    "block_by_height_body",
]

_MAX_RESPONSE = 8 * 1024 * 1024

_DEADLINE_SECONDS = 20.0


def _read_bounded(stream):
    # read1 returns after a single socket read, so a gateway dribbling a body under the socket
    # timeout is still cut off at the deadline. The reply and the error path both read through here.
    deadline = time.monotonic() + _DEADLINE_SECONDS
    raw = bytearray()
    while len(raw) <= _MAX_RESPONSE:
        if time.monotonic() > deadline:
            raise RuntimeError("the response did not arrive in time")
        chunk = stream.read1(min(65536, _MAX_RESPONSE + 1 - len(raw)))
        if not chunk:
            break
        raw.extend(chunk)
    if len(raw) > _MAX_RESPONSE:
        raise RuntimeError("the response is too large")
    return bytes(raw)


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


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError("an RPC endpoint has no reason to redirect")


_OPENER = urllib.request.build_opener(_SafeRedirectHandler())


def _check_amount(amount):
    # Match the JavaScript checkAmount. A Python int is already arbitrary precision, so it and a
    # decimal string are the only accepted forms. A float would truncate silently through int()
    # and sign a wrong amount, and a bool or anything else is not a whole number, so all are
    # refused before anything is signed.
    if isinstance(amount, bool) or not isinstance(amount, (int, str)):
        raise ValueError(
            "the amount must be a whole number int or a decimal string, never a float"
        )
    try:
        value = int(amount)
    except (TypeError, ValueError):
        raise ValueError("the amount must be an integer number of Quon")
    if value < 0:
        raise ValueError("the amount cannot be negative")


def _fee_ceiling(max_fee):
    # The same rule as the amount. A float ceiling would truncate through int() and could set the
    # ceiling higher than intended, so reject it and any non integer non string before the check.
    if isinstance(max_fee, bool) or not isinstance(max_fee, (int, str)):
        raise ValueError(
            "the maximum fee must be a whole number int or a decimal string, never a float"
        )
    try:
        ceiling = int(max_fee)
    except (TypeError, ValueError):
        raise ValueError("the maximum fee must be an integer number of Quon")
    if ceiling < 0:
        raise ValueError("the maximum fee cannot be negative")
    return ceiling


def _account_nonce(nonce):
    # The nonce is the one signing input taken from the gateway. A JSON fractional or exponent number
    # decodes to a float that int() would truncate into a different signed nonce, so a float is refused
    # rather than silently rounded, and anything outside the unsigned 64 bit range is refused too. A
    # Python int stays exact, so a legitimate nonce between 2^53 and 2^64 is still accepted.
    if isinstance(nonce, bool) or isinstance(nonce, float):
        raise RuntimeError("the gateway reported a nonce that is not a whole number")
    try:
        parsed = int(nonce)
    except (TypeError, ValueError):
        raise RuntimeError("the gateway reported a nonce that is not a whole number")
    if parsed < 0 or parsed > 0xFFFFFFFFFFFFFFFF:
        raise RuntimeError("the gateway reported a nonce outside the unsigned 64 bit range")
    return parsed


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


def _transfer_fee(info):
    fee_obj = info.get("fee") if isinstance(info, dict) else None
    if not isinstance(fee_obj, dict):
        raise RuntimeError("the gateway did not report a transfer fee")
    fee = fee_obj.get("transfer_quon")
    if fee is None:
        raise RuntimeError("the gateway did not report a transfer fee")
    return fee


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

    def _guard_mainnet(self):
        # The mainnet decision comes from the network this Client was configured with, never from
        # the gateway's self reported chain id, so a hostile gateway cannot suppress the prompt by
        # claiming to be a testnet.
        on_mainnet = self.network is not None and self.network.is_mainnet
        if on_mainnet and not self.acknowledge_mainnet:
            label = self.network.chain_id if self.network else ""
            raise ValueError(
                f"refusing to sign for the mainnet network {label or ''} without "
                "acknowledge_mainnet True, pass it when you mean to move real value"
            )

    def _signing_chain_id(self, info):
        # Bind the signature to the network the gateway says it serves, computed from the reported
        # name with the same hash the node uses, so the transaction is valid only on that network
        # and a rename is followed without a code change. When this Client was configured with a
        # known chain id, the reported name must match it, so a hostile gateway cannot bind a
        # signature to a network the caller did not choose and then replay it there.
        name = info.get("chain_id") if isinstance(info, dict) else None
        if not name:
            raise RuntimeError("the gateway did not report a chain id to bind the signature to")
        if not isinstance(name, str):
            raise RuntimeError(
                "the gateway reported a chain id that is not a string, refusing to bind a signature to it"
            )
        configured = self.network.chain_id if self.network else None
        if configured and name != configured:
            raise RuntimeError(
                f"the gateway reports chain {name} but this client is configured for {configured}; "
                "refusing to sign a transaction that would be valid on a network you did not choose"
            )
        cid = chain_id_from_name(name)
        if not self.acknowledge_mainnet and _is_mainnet_id(cid):
            raise ValueError(
                f"the gateway reports the mainnet chain {name}; "
                "refusing to sign a mainnet transaction without acknowledge_mainnet True"
            )
        return cid

    def _call(self, method, body):
        req = urllib.request.Request(
            f"{self.base}/v1/{method}",
            data=(body or "{}").encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with _OPENER.open(req, timeout=20) as res:
                return _loads(_read_bounded(res))
        except urllib.error.HTTPError as err:
            data = _loads(_read_bounded(err))
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
        _check_amount(amount)
        ceiling = _fee_ceiling(max_fee)
        info = self.node_info()
        self._guard_mainnet()
        chain_id = self._signing_chain_id(info)
        fee = _transfer_fee(info)
        if int(fee) > ceiling:
            raise ValueError(
                f"the gateway fee {fee} is above the maximum you allowed {max_fee}, refusing to sign"
            )
        sender = address(seed_hex, index)
        acct = self.account(sender)
        nonce = acct.get("nonce") if isinstance(acct, dict) else None
        if nonce is None:
            raise RuntimeError("the gateway did not report a nonce")
        signed = _loads(sign_transfer(seed_hex, index, to, int(amount), _account_nonce(nonce), int(fee), chain_id))
        outcome = self.submit(signed["tx_hex"])
        return signed, outcome

    def register(self, seed_hex, index, max_fee):
        ceiling = _fee_ceiling(max_fee)
        info = self.node_info()
        self._guard_mainnet()
        chain_id = self._signing_chain_id(info)
        fee = _transfer_fee(info)
        if int(fee) > ceiling:
            raise ValueError(
                f"the gateway fee {fee} is above the maximum you allowed {max_fee}, refusing to sign"
            )
        sender = address(seed_hex, index)
        acct = self.account(sender)
        nonce = acct.get("nonce") if isinstance(acct, dict) else None
        if nonce is None:
            raise RuntimeError("the gateway did not report a nonce")
        signed = _loads(sign_register(seed_hex, index, _account_nonce(nonce), int(fee), chain_id))
        outcome = self.submit(signed["tx_hex"])
        return signed, outcome

    def call(self, seed_hex, index, target, args_hex, meter_limit, max_fee):
        if not valid_address(target):
            raise ValueError("the target is not a Q1 address")
        ceiling = _fee_ceiling(max_fee)
        info = self.node_info()
        self._guard_mainnet()
        chain_id = self._signing_chain_id(info)
        fee = _transfer_fee(info)
        if int(fee) > ceiling:
            raise ValueError(
                f"the gateway fee {fee} is above the maximum you allowed {max_fee}, refusing to sign"
            )
        sender = address(seed_hex, index)
        acct = self.account(sender)
        nonce = acct.get("nonce") if isinstance(acct, dict) else None
        if nonce is None:
            raise RuntimeError("the gateway did not report a nonce")
        signed = _loads(sign_call(seed_hex, index, target, args_hex, _account_nonce(nonce), int(meter_limit), int(fee), chain_id))
        outcome = self.submit(signed["tx_hex"])
        return signed, outcome
