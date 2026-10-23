# Copyright 2026 Quantova Inc
# SPDX-License-Identifier: Apache-2.0 OR MIT


import importlib.metadata
import ipaddress
import json
import re
import unicodedata
import secrets
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from ._native import (
    SigningSession,
    address,
    valid_address,
    same_address,
    lookalike_of,
    mnemonic_from_seed,
    mnemonic_from_seed_text,
    seed_from_mnemonic,
    sign_transfer,
    sign_call,
    sign_payable_call,
    sign_asset_call,
    sign_register,
    build_typed_order_call,
    order_layout_hash,
    verify_finality,
    verify_event,
    verify_transaction,
    decode_event,
    vm_call_fee,
    deploy_fee_quon,
    check_valid_until,
    chain_id_from_name,
    local_chain_id,
    testnet_chain_id,
    mainnet_chain_id,
    submit_body,
    account_body,
    transaction_body,
    block_by_height_body,
    genesis_secs,
    head_ceiling,
    bounded_valid_until,
    check_gateway_json,
    check_endpoint,
    testnet_rpc_url,
    testnet_chain_name,
    gateway_protocol,
    roster_commitment,
    verify_next_roster,
    verify_account,
    testnet_roster_commitment,
    mainnet_roster_commitment,
    testnet_genesis_hash,
    mainnet_genesis_hash,
    validity_blocks,
    order_signer,
    vm_deploy_address,
    contract_address,
    nonce_slot_key,
    scalar_slot_key,
    map_slot_key,
    map_addr_word_key,
    name_key,
    token_decimals_slot,
    token_symbol_slot,
    pack_symbol,
    unpack_symbol,
    storage_body,
    events_body,
    asset_balance_body,
    asset_supply_body,
    storage_value,
    storage_value_reported,
    check_order_expiry,
    parse_events,
    verify_finality_in_epoch,
    header_height,
    transaction_kind,
    index_fits_path,
    testnet_epoch_length,
    mainnet_epoch_length,
    testnet_genesis_secs,
    testnet_blocks_per_sec,
    response_cap,
    bounded_valid_until_for,
)

def generate_seed():
    return bytearray(secrets.token_bytes(32))

def _is_mainnet_chain(name):
    return name.startswith("Q-main-net-")

def _is_public_chain(name):
    return name.startswith("Q-test-net-") or _is_mainnet_chain(name)

__all__ = [
    "Client",
    "Network",
    "SigningSession",
    "generate_seed",
    "address",
    "valid_address",
    "same_address",
    "lookalike_of",
    "mnemonic_from_seed",
    "mnemonic_from_seed_text",
    "seed_from_mnemonic",
    "sign_transfer",
    "sign_call",
    "sign_payable_call",
    "sign_asset_call",
    "sign_register",
    "build_typed_order_call",
    "order_layout_hash",
    "verify_finality",
    "verify_next_roster",
    "verify_account",
    "roster_commitment",
    "gateway_protocol",
    "testnet_roster_commitment",
    "mainnet_roster_commitment",
    "verify_event",
    "verify_transaction",
    "decode_event",
    "vm_call_fee",
    "deploy_fee_quon",
    "check_valid_until",
    "chain_id_from_name",
    "local_chain_id",
    "testnet_chain_id",
    "mainnet_chain_id",
    "submit_body",
    "account_body",
    "transaction_body",
    "block_by_height_body",
    "genesis_secs",
    "head_ceiling",
    "bounded_valid_until",
    "check_gateway_json",
    "check_endpoint",
    "testnet_rpc_url",
    "testnet_chain_name",
    "validity_blocks",
    "order_signer",
    "vm_deploy_address",
    "contract_address",
    "nonce_slot_key",
    "scalar_slot_key",
    "map_slot_key",
    "map_addr_word_key",
    "name_key",
    "token_decimals_slot",
    "token_symbol_slot",
    "pack_symbol",
    "unpack_symbol",
    "storage_body",
    "events_body",
    "asset_balance_body",
    "asset_supply_body",
    "storage_value",
    "storage_value_reported",
    "check_order_expiry",
    "parse_events",
    "verify_finality_in_epoch",
    "header_height",
    "transaction_kind",
    "index_fits_path",
    "bounded_valid_until_for",
]

_MAX_RESPONSE = 8 * 1024 * 1024

_DEADLINE_SECONDS = 20.0

def _read_bounded(stream):
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

def _decode(raw):
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise RuntimeError("the response is not UTF-8")

def _strict_loads(raw):
    text = _decode(raw)
    try:
        check_gateway_json(text)
    except ValueError as err:
        raise RuntimeError(str(err))
    return _loads(text)

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

try:
    _VERSION = importlib.metadata.version("quantova-qcore")
except importlib.metadata.PackageNotFoundError:
    _VERSION = "0"

_USER_AGENT = f"quantova-qcore/{_VERSION} (+https://quantova.org)"

_ACCOUNT_LOCKS = {}
_ACCOUNT_LOCKS_GUARD = threading.Lock()


def _shown(value):
    text = "".join(c for c in str(value) if unicodedata.category(c) not in ("Cc", "Cf", "Zl", "Zp", "Cs"))
    return text[:96] + "..." if len(text) > 96 else text


class _AccountLock:
    def __init__(self, key):
        self._key = key
        self._entry = None

    def __enter__(self):
        with _ACCOUNT_LOCKS_GUARD:
            entry = _ACCOUNT_LOCKS.get(self._key)
            if entry is None:
                entry = [threading.Lock(), 0]
                _ACCOUNT_LOCKS[self._key] = entry
            entry[1] += 1
        self._entry = entry
        entry[0].acquire()
        return self

    def __exit__(self, *exc):
        entry = self._entry
        entry[0].release()
        with _ACCOUNT_LOCKS_GUARD:
            entry[1] -= 1
            if entry[1] == 0 and _ACCOUNT_LOCKS.get(self._key) is entry:
                del _ACCOUNT_LOCKS[self._key]
        return False


def _tls_context():
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context

_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    urllib.request.HTTPSHandler(context=_tls_context()),
    _SafeRedirectHandler(),
)

def _whole(value, message):
    if isinstance(value, str):
        if not (value.isascii() and value.isdigit()):
            raise ValueError(message)
        return int(value)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(message)
    return value

def _check_amount(amount):
    if isinstance(amount, bool) or not isinstance(amount, (int, str)):
        raise ValueError(
            "the amount must be a whole number int or a decimal string, never a float"
        )
    value = _whole(amount, "the amount must be an integer number of Quon")
    if value < 0:
        raise ValueError("the amount cannot be negative")

def _fee_ceiling(max_fee):
    if isinstance(max_fee, bool) or not isinstance(max_fee, (int, str)):
        raise ValueError(
            "the maximum fee must be a whole number int or a decimal string, never a float"
        )
    ceiling = _whole(max_fee, "the maximum fee must be an integer number of Quon")
    if ceiling < 0:
        raise ValueError("the maximum fee cannot be negative")
    return ceiling

_VALIDITY_BLOCKS = validity_blocks()
_MAX_PLAUSIBLE_HEAD = 1 << 40
_U64_MAX = 0xFFFFFFFFFFFFFFFF
_U128_MAX = (1 << 128) - 1
_SAFE_INTEGER_LIMIT = 1 << 53

def _gateway_integer(value, label):
    if value is None:
        raise RuntimeError(f"the gateway did not report a {label}")
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value >= _SAFE_INTEGER_LIMIT:
        raise RuntimeError(f"the gateway reported a {label} that is not a whole number below 2^53")
    return value

def _gateway_decimal(value, label):
    if value is None:
        raise RuntimeError(f"the gateway did not report a {label}")
    if not isinstance(value, str) or not (value.isascii() and value.isdigit()):
        raise RuntimeError(f"the gateway reported a {label} that is not a string of decimal digits")
    parsed = int(value)
    if parsed > _U128_MAX:
        raise RuntimeError(f"the gateway reported a {label} outside the unsigned 128 bit range")
    return parsed

_SHARED_SESSION = SigningSession([])
_SHARED_SESSION_GUARD = threading.RLock()


def _optional_whole(value, label):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > _U64_MAX:
        raise ValueError(f"the {label} must be a whole number int")
    return value


def _valid_until(info):
    head = _gateway_integer(info.get("head_height") if isinstance(info, dict) else None, "head height")
    if head > _MAX_PLAUSIBLE_HEAD:
        raise RuntimeError("the gateway reported a head height past any height this chain can have reached")
    return head + _VALIDITY_BLOCKS

def _expected(value, label):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > _U64_MAX:
        raise ValueError(f"the {label} must be a whole number int in the unsigned 64 bit range")
    return value

DENOMINATION = "Quon"
DECIMALS = 6

def _pinned_genesis(value):
    if value is None:
        return None
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-fA-F]{64}", value) is None:
        raise ValueError("a pinned genesis hash must be 64 hex characters")
    return value.lower()


class Network:
    def __init__(self, name, chain_id=None, rpc_url=None, explorer_url=None,
                 denomination=DENOMINATION, decimals=DECIMALS, is_mainnet=False, genesis_hash=None,
                 roster_commitment=None, epoch_length=None, genesis_secs=None, blocks_per_sec=None):
        self.name = name
        self.chain_id = chain_id
        self.rpc_url = rpc_url
        self.explorer_url = explorer_url
        self.denomination = denomination
        self.decimals = decimals
        self.is_mainnet = is_mainnet is True
        self.genesis_hash = _pinned_genesis(genesis_hash)
        self.roster_commitment = _pinned_genesis(roster_commitment)
        self.epoch_length = _optional_whole(epoch_length, "epoch length")
        self.genesis_secs = _optional_whole(genesis_secs, "genesis time")
        self.blocks_per_sec = _optional_whole(blocks_per_sec, "block rate")
        if (self.genesis_secs is None) != (self.blocks_per_sec is None):
            raise ValueError("a network names a genesis time and a block rate together or neither")

    @classmethod
    def testnet(cls):
        return cls(name="testnet", chain_id=testnet_chain_name(),
                   rpc_url=testnet_rpc_url(),
                   explorer_url="https://qvmscan.io", is_mainnet=False,
                   genesis_hash=testnet_genesis_hash(),
                   roster_commitment=testnet_roster_commitment(),
                   epoch_length=testnet_epoch_length(),
                   genesis_secs=testnet_genesis_secs(),
                   blocks_per_sec=testnet_blocks_per_sec())

    @classmethod
    def mainnet(cls):
        return cls(name="mainnet", chain_id="Q-main-net-1", rpc_url=None,
                   explorer_url="https://qvmscan.io", is_mainnet=True,
                   genesis_hash=mainnet_genesis_hash(),
                   roster_commitment=mainnet_roster_commitment(),
                   epoch_length=mainnet_epoch_length())

    @classmethod
    def for_url(cls, base):
        return cls(name="custom", chain_id=None, rpc_url=base, is_mainnet=False)

def _transfer_fee(info):
    fee_obj = info.get("fee") if isinstance(info, dict) else None
    if not isinstance(fee_obj, dict):
        raise RuntimeError("the gateway did not report a transfer fee")
    return _gateway_decimal(fee_obj.get("transfer_quon"), "transfer fee")

class Client:
    def __init__(self, target, acknowledge_mainnet=False, network=None, address_book=None, genesis_hash=None):
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
        check_endpoint(self.base)
        self._pinned_chain = self.network.chain_id if self.network else None
        network_genesis = self.network.genesis_hash if self.network else None
        option_genesis = _pinned_genesis(genesis_hash)
        if network_genesis and option_genesis and network_genesis != option_genesis:
            raise ValueError("the genesis_hash argument differs from the genesis pinned in the network, refusing to open the client")
        self._pinned_genesis = network_genesis or option_genesis
        self._session = SigningSession([str(a) for a in (address_book or [])])
        self._nonces = _SHARED_SESSION

    def _sender_lock(self, sender):
        return _AccountLock(sender)

    def _guard_mainnet(self):
        on_mainnet = self.network is not None and self.network.is_mainnet
        if on_mainnet and not self.acknowledge_mainnet:
            label = self.network.chain_id if self.network else ""
            raise ValueError(
                f"refusing to sign for the mainnet network {label or ''} without "
                "acknowledge_mainnet True, pass it when you mean to move real value"
            )

    def _signing_chain_id(self, info):
        name = info.get("chain_id") if isinstance(info, dict) else None
        if not name:
            raise RuntimeError("the gateway did not report a chain id to bind the signature to")
        if not isinstance(name, str):
            raise RuntimeError(
                "the gateway reported a chain id that is not a string, refusing to bind a signature to it"
            )
        configured = self.network.chain_id if self.network else None
        mainnet = _is_mainnet_chain(name)
        if configured:
            if name != configured:
                raise RuntimeError(
                    f"the gateway reports chain {_shown(name)} but this client is configured for {configured}; "
                    "refusing to sign a transaction that would be valid on a network you did not choose"
                )
        elif _is_public_chain(name) and not (mainnet and self.acknowledge_mainnet):
            raise RuntimeError(
                f"the gateway reports the public chain {_shown(name)} but this client was opened for an unnamed "
                "network; configure the testnet or mainnet network before signing for it"
            )
        if mainnet and not self.acknowledge_mainnet:
            raise ValueError(
                f"the gateway reports the mainnet chain {_shown(name)}; "
                "refusing to sign a mainnet transaction without acknowledge_mainnet True"
            )
        if self._pinned_chain is not None and name != self._pinned_chain:
            raise RuntimeError(
                f"the gateway reports chain {_shown(name)} but this session is pinned to {self._pinned_chain}; "
                "refusing to switch the signing chain mid-session"
            )
        self._pinned_chain = name
        return chain_id_from_name(name)

    def _call(self, method, body, strict=False):
        req = urllib.request.Request(
            f"{self.base}/v1/{method}",
            data=(body or "{}").encode(),
            headers={"Content-Type": "application/json", "User-Agent": _USER_AGENT},
            method="POST",
        )
        try:
            with _OPENER.open(req, timeout=20) as res:
                raw = _read_bounded(res)
                if len(raw) > response_cap(method):
                    raise RuntimeError(f"the gateway answered {method} with {len(raw)} bytes, above what that answer can need, refusing to read it")
                if res.status != 200:
                    raise RuntimeError(f"status {res.status}")
                return _strict_loads(raw)
        except urllib.error.HTTPError as err:
            data = _loads(_decode(_read_bounded(err)))
            message = data.get("message") or data.get("error") if isinstance(data, dict) else None
            raise RuntimeError(_shown(message) if message else f"status {err.code}")

    def node_info(self):
        info = self._call("node_info", "{}", strict=True)
        reported = info.get("protocol") if isinstance(info, dict) else None
        if reported is None:
            raise ValueError("the gateway does not report its protocol version, refusing to use it")
        if isinstance(reported, bool) or reported != gateway_protocol():
            raise ValueError(f"the gateway speaks protocol {reported!r} but this client supports protocol {gateway_protocol()}, refusing to use it")
        return info

    def head(self):
        return self._call("head", "{}")

    def account(self, addr):
        acct = self._call("get_account", account_body(addr), strict=True)
        answered = acct.get("address") if isinstance(acct, dict) else None
        if answered != addr:
            raise RuntimeError(
                f"the gateway answered for {_shown(answered)} when asked about {addr}, refusing to trust it"
            )
        return acct

    def _vet(self, sender, targets):
        self._session.remember_address(sender)
        for target in targets:
            self._session.check_target(target)

    def _remember_targets(self, targets):
        for target in targets:
            self._session.remember_address(target)

    def _account_slot(self, info, sender, expected_nonce):
        acct = self.account(sender)
        reported = _gateway_integer(acct.get("nonce"), "nonce")
        key = f"{info.get('chain_id')}/{sender}"
        with _SHARED_SESSION_GUARD:
            nonce = self._nonces.slot(key, reported, _expected(expected_nonce, "expected nonce"), False)
        return key, nonce

    def _released(self, slots, sign):
        try:
            return sign()
        except Exception:
            with _SHARED_SESSION_GUARD:
                for key, slot in slots:
                    self._nonces.release(key, slot)
            raise

    def _submit_held(self, slots, tx_hex):
        with _SHARED_SESSION_GUARD:
            for key, slot in slots:
                self._nonces.signed(key, slot)
        outcome = self.submit(tx_hex)
        verdict = outcome.get("verdict") if isinstance(outcome, dict) else None
        if verdict not in ("accepted", "rejected"):
            raise RuntimeError(f"unknown verdict {_shown(verdict)}")
        with _SHARED_SESSION_GUARD:
            for key, slot in slots:
                self._nonces.outcome(key, slot, verdict == "accepted")
        return outcome

    def trust_roster(self, genesis_hash, roster):
        self.trust_roster_at(genesis_hash, 0, roster)

    def trust_roster_at(self, genesis_hash, epoch, roster):
        if not isinstance(genesis_hash, str) or re.fullmatch(r"[0-9a-fA-F]{64}", genesis_hash) is None:
            raise ValueError("the genesis hash you trust must be 64 hex characters")
        if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
            raise ValueError("the roster epoch must be a whole number")
        roster_json = roster if isinstance(roster, str) else json.dumps(roster)
        try:
            members = json.loads(roster_json)
        except ValueError:
            raise ValueError("the trusted validator roster is not valid JSON")
        if not isinstance(members, list) or not members:
            raise ValueError("a trusted validator roster must be a non empty list")
        self._trusted_rosters = {epoch: roster_json}
        self._trusted_genesis = genesis_hash.lower()

    def _anchor_pinned_roster(self):
        if getattr(self, "_trusted_rosters", None) is not None:
            return True
        network = self.network
        if network is None or network.genesis_hash is None or getattr(network, "roster_commitment", None) is None:
            return False
        answer = self._call("get_roster_proof", json.dumps({"epoch": 0}), strict=True)
        members = json.dumps(answer.get("members") if isinstance(answer, dict) else None)
        if roster_commitment(0, members) != network.roster_commitment:
            raise RuntimeError("the gateway offers a genesis roster other than the one pinned for this network, refusing to trust it")
        self.trust_roster_at(network.genesis_hash, 0, members)
        return True

    def _epoch_length(self):
        length = getattr(self.network, "epoch_length", None) if self.network is not None else None
        if not length:
            name = self.network.name if self.network is not None else "custom"
            raise RuntimeError(
                f"no epoch length is pinned for the {name} network, so the validator roster for a height cannot be "
                "chosen without trusting the gateway; set the network epoch_length"
            )
        return length

    def _epoch_of_header(self, header_hex, reported):
        height = header_height(header_hex)
        epoch = height // self._epoch_length()
        if reported is not None and _gateway_integer(reported, "epoch") != epoch:
            raise RuntimeError(
                f"the gateway names epoch {_shown(reported)} for height {height}, which lies in epoch {epoch}, "
                "refusing to choose a roster on its word"
            )
        return height, epoch

    def _checked_chain(self, info):
        name = info.get("chain_id") if isinstance(info, dict) and isinstance(info.get("chain_id"), str) else ""
        configured = self.network.chain_id if self.network else None
        if configured and name != configured:
            raise RuntimeError(f"the gateway reports chain {_shown(name)} but this client is configured for {configured}")
        return chain_id_from_name(name)

    def _roster_for_epoch(self, chain_id, epoch):
        if not self._anchor_pinned_roster():
            return None
        known = [e for e in self._trusted_rosters if e <= epoch]
        if not known:
            raise RuntimeError(f"the trusted roster starts after epoch {epoch}, so that epoch cannot be checked")
        length = self._epoch_length()
        current = max(known)
        roster = self._trusted_rosters[current]
        while current < epoch:
            nxt = current + 1
            answer = self._call("get_roster_proof", json.dumps({"epoch": nxt}), strict=True)
            if not isinstance(answer, dict) or not all(isinstance(answer.get(k), str) for k in ("header_bytes", "certificate", "proof")):
                raise RuntimeError(f"the gateway gave no roster proof for epoch {nxt}")
            if answer.get("epoch") != nxt:
                raise RuntimeError(f"the gateway answered a roster proof for another epoch when asked for epoch {nxt}")
            members = json.dumps(answer.get("members"))
            verify_next_roster(chain_id, self._trusted_genesis, length, current, roster, answer["header_bytes"], answer["certificate"], members, answer["proof"])
            current = nxt
            roster = members
            self._trusted_rosters[current] = roster
            while len(self._trusted_rosters) > 32:
                del self._trusted_rosters[sorted(self._trusted_rosters)[1]]
        return roster

    def _certified_at(self, height):
        finality = self._call("get_finality", json.dumps({"height": height}), strict=True)
        if not isinstance(finality, dict) or not isinstance(finality.get("header_bytes"), str) or not isinstance(finality.get("certificate"), str):
            raise RuntimeError(f"the gateway gave no finality proof for height {height}")
        at, epoch = self._epoch_of_header(finality["header_bytes"], finality.get("epoch"))
        if at != height:
            raise RuntimeError(f"the gateway answered a finality proof for another height when asked for height {height}")
        return epoch, finality["header_bytes"], finality["certificate"]

    def _verify_head(self, info):
        if not self._anchor_pinned_roster():
            reported = info.get("chain_id") if isinstance(info, dict) and isinstance(info.get("chain_id"), str) else ""
            configured = (self.network.chain_id if self.network is not None else None) or ""
            if (self.network is not None and self.network.is_mainnet) or _is_mainnet_chain(reported) or _is_mainnet_chain(configured):
                raise RuntimeError(
                    "a mainnet client needs a trusted validator roster to check the head it signs against, call trust_roster first"
                )
            return False
        head = _gateway_integer(info.get("head_height") if isinstance(info, dict) else None, "head height")
        name = info.get("chain_id") if isinstance(info.get("chain_id"), str) else ""
        chain_id = chain_id_from_name(name)
        epoch, header, certificate = self._certified_at(head)
        roster = self._roster_for_epoch(chain_id, epoch)
        verified = _loads(verify_finality_in_epoch(chain_id, self._trusted_genesis, self._epoch_length(), epoch, header, certificate, roster))
        if int(verified["height"]) != head:
            raise RuntimeError(
                f"the gateway reports head {head} but its finality proof is for height {verified['height']}, refusing to sign"
            )
        return True

    def verified_account(self, address):
        if not isinstance(address, str):
            raise ValueError("the address must be a string")
        info = self.node_info()
        chain_id = self._checked_chain(info)
        answer = self._call("get_account_proof", json.dumps({"address": address}), strict=True)
        if not isinstance(answer, dict) or not all(isinstance(answer.get(k), str) for k in ("header_bytes", "certificate", "proof")):
            raise RuntimeError("the gateway gave no account proof")
        _, epoch = self._epoch_of_header(answer["header_bytes"], answer.get("epoch"))
        roster = self._roster_for_epoch(chain_id, epoch)
        if roster is None:
            raise RuntimeError("a verified balance needs a trusted validator roster, call trust_roster first")
        verified = _loads(verify_account(chain_id, self._trusted_genesis, self._epoch_length(), epoch, roster, address, answer["header_bytes"], answer["certificate"], answer["proof"]))
        return {"address": verified["address"], "height": int(verified["height"]), "exists": verified["exists"] is True,
                "balance": int(verified["balance"]), "nonce": int(verified["nonce"])}

    def _inclusion(self, tx_id, trusted):
        if not isinstance(tx_id, str):
            raise ValueError("the transaction id must be a string")
        info = self.node_info()
        chain_id = self._checked_chain(info)
        proof = self._call("get_transaction_proof", json.dumps({"tx_id": tx_id}), strict=True)
        if not isinstance(proof, dict) or not isinstance(proof.get("leaf"), str):
            raise RuntimeError("the transaction proof carries no leaf")
        height = _gateway_integer(proof.get("height"), "proof height")
        index = _gateway_integer(proof.get("index"), "proof index")
        steps = json.dumps(proof.get("steps"))
        epoch, header, certificate = self._certified_at(height)
        if trusted is not None:
            genesis, epoch, roster = trusted
        else:
            roster = self._roster_for_epoch(chain_id, epoch)
            if roster is None:
                raise RuntimeError("a verified confirmation needs a trusted validator roster, call trust_roster first")
            genesis = self._trusted_genesis
        verified = _loads(verify_finality_in_epoch(chain_id, genesis, self._epoch_length(), epoch, header, certificate, roster))
        if int(verified["height"]) != height:
            raise RuntimeError("the finalized header is not at the height the proof names")
        if not verify_transaction(verified["transaction_root"], tx_id, proof["leaf"], steps):
            raise RuntimeError("the transaction is not proven inside the finalized block")
        if not index_fits_path(index, steps):
            raise RuntimeError(f"the gateway names position {index} for the transaction, which its verified inclusion path cannot reach")
        kind = transaction_kind(proof["leaf"])
        return {"tx_id": tx_id, "height": height, "index": index, "header": verified, "kind": kind,
                "outcome": "applied" if kind == "transfer" else "included outcome unproven"}

    def confirm_inclusion(self, tx_id, genesis_hash, roster, epoch=0):
        if not isinstance(genesis_hash, str) or re.fullmatch(r"[0-9a-fA-F]{64}", genesis_hash) is None:
            raise ValueError("the genesis hash you trust must be 64 hex characters")
        if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
            raise ValueError("the roster epoch must be a whole number")
        roster_json = roster if isinstance(roster, str) else json.dumps(roster)
        return self._inclusion(tx_id, (genesis_hash.lower(), epoch, roster_json))

    def confirm_inclusion_trusted(self, tx_id):
        return self._inclusion(tx_id, None)

    @staticmethod
    def _settled(confirmed):
        if confirmed["kind"] != "transfer":
            raise RuntimeError(
                f"{confirmed['tx_id']} is a contract call, which the chain includes and charges even when it reverts, so "
                "inclusion does not prove it ran; prove the event it emits with confirm_call_event, or use confirm_inclusion "
                "for inclusion alone"
            )
        return confirmed

    def confirm_transaction(self, tx_id, genesis_hash, roster, epoch=0):
        return self._settled(self.confirm_inclusion(tx_id, genesis_hash, roster, epoch))

    def confirm_transaction_trusted(self, tx_id):
        return self._settled(self.confirm_inclusion_trusted(tx_id))

    def confirm_call_event(self, tx_id, contract, selector_hex, data_hex=None):
        if not isinstance(contract, str) or not isinstance(selector_hex, str):
            raise ValueError("the contract and selector must be strings")
        if data_hex is not None and not isinstance(data_hex, str):
            raise ValueError("the event data must be a hex string")
        confirmed = self.confirm_inclusion_trusted(tx_id)
        height = confirmed["height"]
        listed = json.loads(parse_events(json.dumps(self.events(height))))
        selector = selector_hex.lower()
        data = data_hex.lower() if data_hex is not None else None
        for position, event in enumerate(listed):
            if not same_address(event["contract"], contract) or event["selector"] != selector or (data is not None and event["data"] != data):
                continue
            answer = self._call("get_event_proof", json.dumps({"height": height, "index": position}), strict=True)
            if not isinstance(answer, dict) or not isinstance(answer.get("leaf"), str):
                continue
            if not verify_event(confirmed["header"]["event_root"], answer["leaf"], json.dumps(answer.get("steps"))):
                continue
            proven = json.loads(decode_event(answer["leaf"]))
            if same_address(proven["contract"], contract) and proven["selector"] == selector and (data is None or proven["data"] == data):
                return dict(confirmed, outcome="event proven", event_index=position)
        raise RuntimeError(
            f"the block that holds {tx_id} carries no proven event of that contract and selector, so the call is not shown to have run"
        )

    def _validity(self, info, verified=False):
        head = _gateway_integer(info.get("head_height") if isinstance(info, dict) else None, "head height")
        chain = info.get("chain_id") if isinstance(info.get("chain_id"), str) else ""
        if not verified and ((self.network is not None and self.network.is_mainnet) or _is_public_chain(chain)):
            raise RuntimeError(
                f"the head of the public chain {_shown(chain)} must be verified against a trusted validator roster before signing, "
                "pin the network roster commitment or call trust_roster"
            )
        genesis = info.get("genesis_hash") if isinstance(info, dict) else None
        if not isinstance(genesis, str) or re.fullmatch(r"[0-9a-fA-F]{64}", genesis) is None:
            raise RuntimeError("the gateway reports a genesis hash that is not 32 bytes of hex, refusing to sign")
        reported = genesis.lower()
        trusted = getattr(self, "_trusted_genesis", None)
        if trusted is not None and trusted != reported:
            raise RuntimeError("the gateway reports a genesis hash other than the one whose validator roster this client trusts, refusing to sign")
        if self._pinned_genesis is not None:
            if self._pinned_genesis != reported:
                raise RuntimeError("the gateway reports a genesis hash other than the one pinned for this network, refusing to sign")
        elif _is_public_chain(chain):
            raise RuntimeError(f"no genesis hash is pinned for the public chain {_shown(chain)}, pin the network genesis before signing")
        genesis_secs = getattr(self.network, "genesis_secs", None) if self.network is not None else None
        blocks_per_sec = getattr(self.network, "blocks_per_sec", None) if self.network is not None else None
        if genesis_secs is None and chain == testnet_chain_name():
            genesis_secs, blocks_per_sec = testnet_genesis_secs(), testnet_blocks_per_sec()
        wall = max(int(time.time()), 0)
        with _SHARED_SESSION_GUARD:
            floor = self._nonces.head_floor(chain)
            age = wall - floor[1] if floor is not None and wall > floor[1] else 0
            try:
                until = bounded_valid_until_for(genesis_secs, blocks_per_sec, verified is True, head, wall, floor[0] if floor else None, age)
            except ValueError as err:
                raise RuntimeError(str(err))
            self._nonces.note_head(chain, head, wall)
        return until, head, trusted or reported

    def _call_fee(self, info, meter, ceiling, max_fee, deploy=False):
        transfer_fee = _transfer_fee(info)
        fee = vm_call_fee(transfer_fee, meter)
        if deploy:
            fee += deploy_fee_quon(json.dumps(info))
        if fee > ceiling:
            raise ValueError(
                f"the fee {fee} is above the maximum you allowed {max_fee}, refusing to sign"
            )
        return transfer_fee, fee

    def transaction(self, tx_id):
        status = self._call("get_transaction", transaction_body(tx_id))
        if not isinstance(status, dict) or status.get("status") != "finalised":
            return status
        if self._anchor_pinned_roster():
            confirmed = self.confirm_inclusion_trusted(tx_id)
            return dict(status, height=confirmed["height"], block=confirmed["header"]["hash"], verified=True)
        configured_mainnet = (self.network is not None and self.network.is_mainnet) or _is_mainnet_chain((self.network.chain_id if self.network else None) or "")
        if configured_mainnet or _is_mainnet_chain(str(self.node_info().get("chain_id") or "")):
            raise RuntimeError(
                "a mainnet transaction status needs a trusted validator roster, the gateway's word alone is not proof of finality, call trust_roster first"
            )
        return dict(status, status="unverified", reported_status="finalised", verified=False)

    def save_session(self):
        with _SHARED_SESSION_GUARD:
            return self._nonces.export_state()

    def restore_session(self, state):
        if not isinstance(state, str):
            raise ValueError("the saved session must be the string save_session returned")
        with _SHARED_SESSION_GUARD:
            self._nonces.import_state(state)

    def block(self, height):
        return self._call("get_block", block_by_height_body(height))

    def submit(self, tx_hex):
        return self._call("submit_transaction", submit_body(tx_hex), strict=True)

    def storage(self, contract):
        return self._call("get_storage", storage_body(contract))

    def events(self, height):
        return self._call("get_events", events_body(_whole(height, "the height must be a whole number")))

    def _slot_value(self, contract, key):
        resp = self._call("get_storage_at", json.dumps({"address": contract, "keys": [key]}), strict=True)
        value = storage_value_reported(json.dumps(resp), key)
        if value is None:
            raise ValueError("the gateway did not report the requested storage slot")
        return value

    def contract_nonce(self, contract, signer_hex):
        return self._slot_value(contract, nonce_slot_key(signer_hex))

    def contract_scalar(self, contract, slot):
        return self._slot_value(contract, scalar_slot_key(_whole(slot, "the slot must be a whole number")))

    def contract_map(self, contract, map_domain_tag, key_hex):
        tag = _whole(map_domain_tag, "the map domain tag must be a whole number")
        return self._slot_value(contract, map_slot_key(tag, key_hex))

    def asset_balance(self, issuer, holder):
        if not valid_address(issuer) or not valid_address(holder):
            raise ValueError("the issuer or holder is not a Q1 address")
        resp = self._call("get_asset_balance", asset_balance_body(issuer, holder), strict=True)
        return _gateway_decimal(resp.get("balance") if isinstance(resp, dict) else None, "balance")

    def address(self, seed, index):
        return address(seed, index)

    def transfer(self, seed, index, to, amount, max_fee, expected_nonce=None):
        if not valid_address(to):
            raise ValueError("the recipient is not a Q1 address")
        _check_amount(amount)
        ceiling = _fee_ceiling(max_fee)
        sender = address(seed, index)
        with self._sender_lock(sender):
            self._vet(sender, [to])
            info = self.node_info()
            self._guard_mainnet()
            chain_id = self._signing_chain_id(info)
            fee = _transfer_fee(info)
            if fee > ceiling:
                raise ValueError(
                    f"the gateway fee {fee} is above the maximum you allowed {max_fee}, refusing to sign"
                )
            verified = self._verify_head(info)
            until, head, genesis = self._validity(info, verified)
            key, nonce = self._account_slot(info, sender, expected_nonce)
            signed = self._released([(key, nonce)], lambda: _loads(
                sign_transfer(seed, index, to, _whole(amount, "the amount must be an integer number of Quon"), nonce, fee, chain_id, until, head, genesis)
            ))
            self._remember_targets([to])
            outcome = self._submit_held([(key, nonce)], signed["tx_hex"])
            return signed, outcome

    def register(self, seed, index, max_fee, expected_nonce=None):
        ceiling = _fee_ceiling(max_fee)
        sender = address(seed, index)
        with self._sender_lock(sender):
            self._vet(sender, [])
            info = self.node_info()
            self._guard_mainnet()
            chain_id = self._signing_chain_id(info)
            fee = _transfer_fee(info)
            if fee > ceiling:
                raise ValueError(
                    f"the gateway fee {fee} is above the maximum you allowed {max_fee}, refusing to sign"
                )
            verified = self._verify_head(info)
            until, head, genesis = self._validity(info, verified)
            key, nonce = self._account_slot(info, sender, expected_nonce)
            signed = self._released([(key, nonce)], lambda: _loads(sign_register(seed, index, nonce, fee, chain_id, until, head, genesis)))
            outcome = self._submit_held([(key, nonce)], signed["tx_hex"])
            return signed, outcome

    def _signed_call(self, seed, index, targets, meter_limit, max_fee, expected_nonce, sign):
        ceiling = _fee_ceiling(max_fee)
        meter = _whole(meter_limit, "the meter limit must be a whole number")
        sender = address(seed, index)
        with self._sender_lock(sender):
            self._vet(sender, targets)
            info = self.node_info()
            self._guard_mainnet()
            chain_id = self._signing_chain_id(info)
            deploy = bool(targets) and same_address(targets[0], vm_deploy_address())
            transfer_fee, fee = self._call_fee(info, meter, ceiling, max_fee, deploy)
            verified = self._verify_head(info)
            until, head, genesis = self._validity(info, verified)
            key, nonce = self._account_slot(info, sender, expected_nonce)
            signed = self._released([(key, nonce)], lambda: _loads(sign(nonce, meter, fee, chain_id, until, transfer_fee, head, genesis)))
            self._remember_targets(targets)
            outcome = self._submit_held([(key, nonce)], signed["tx_hex"])
            return signed, outcome

    def call(self, seed, index, target, args_hex, meter_limit, max_fee, expected_nonce=None):
        if not valid_address(target):
            raise ValueError("the target is not a Q1 address")
        return self._signed_call(
            seed, index, [target], meter_limit, max_fee, expected_nonce,
            lambda nonce, meter, fee, chain_id, until, transfer_fee, head, genesis: sign_call(
                seed, index, target, args_hex, nonce, meter, fee, chain_id, until, transfer_fee,
                head, genesis,
            ),
        )

    def payable_call(self, seed, index, target, args_hex, value, meter_limit, max_fee, expected_nonce=None):
        if not valid_address(target):
            raise ValueError("the target is not a Q1 address")
        _check_amount(value)
        amount = _whole(value, "the value must be an integer number of Quon")
        return self._signed_call(
            seed, index, [target], meter_limit, max_fee, expected_nonce,
            lambda nonce, meter, fee, chain_id, until, transfer_fee, head, genesis: sign_payable_call(
                seed, index, target, args_hex, nonce, meter, fee, amount, chain_id, until,
                transfer_fee, head, genesis,
            ),
        )

    def asset_call(self, seed, index, target, args_hex, asset_issuer, amount, meter_limit, max_fee, expected_nonce=None):
        if not valid_address(target):
            raise ValueError("the target is not a Q1 address")
        if not valid_address(asset_issuer):
            raise ValueError("the asset issuer is not a Q1 address")
        _check_amount(amount)
        moved = _whole(amount, "the amount must be an integer number of Quon")
        return self._signed_call(
            seed, index, [target, asset_issuer], meter_limit, max_fee, expected_nonce,
            lambda nonce, meter, fee, chain_id, until, transfer_fee, head, genesis: sign_asset_call(
                seed, index, target, args_hex, asset_issuer, moved, nonce, meter, fee,
                chain_id, until, transfer_fee, head, genesis,
            ),
        )

    def call_typed_order(self, caller_seed, caller_index, contract, selector_hex, order_spec, owner_seed, owner_index,
                         meter_limit, max_fee, expected_order_nonce=None, expected_nonce=None):
        if not valid_address(contract):
            raise ValueError("the contract is not a Q1 address")
        if not isinstance(order_spec, dict) or not isinstance(order_spec.get("layout_hash"), str):
            raise ValueError("the order spec needs the layout hash the compiler emits for this entry")
        expiry = _whole(order_spec.get("expiry"), "the order expiry must be a whole number")
        check_order_expiry(expiry, int(time.time()))
        ceiling = _fee_ceiling(max_fee)
        meter = _whole(meter_limit, "the meter limit must be a whole number")
        caller = address(caller_seed, caller_index)
        with self._sender_lock(caller):
            self._vet(caller, [contract])
            info = self.node_info()
            self._guard_mainnet()
            chain_id = self._signing_chain_id(info)
            transfer_fee, fee = self._call_fee(info, meter, ceiling, max_fee, False)
            verified = self._verify_head(info)
            until, head, genesis = self._validity(info, verified)
            signer = order_signer(owner_seed, owner_index)
            order_key = f"{info.get('chain_id')}/{contract.upper()}/{signer}"
            reported = self.contract_nonce(contract, signer)
            with _SHARED_SESSION_GUARD:
                nonce = self._nonces.slot(order_key, reported, _expected(expected_order_nonce, "expected order nonce"), True)
            slots = [(order_key, nonce)]
            try:
                order = _loads(build_typed_order_call(
                    chain_id, genesis, contract, selector_hex, order_spec["layout_hash"],
                    _whole(order_spec.get("scheme_off"), "the scheme offset must be a whole number"),
                    _whole(order_spec.get("ptr_off"), "the pointer offset must be a whole number"),
                    _whole(order_spec.get("expiry_off"), "the expiry offset must be a whole number"),
                    _whole(order_spec.get("region_off", 0), "the region offset must be a whole number"),
                    json.dumps(order_spec.get("fields") or []), owner_seed, owner_index, nonce, expiry,
                    resign=expected_order_nonce is not None,
                ))
                key, account_nonce = self._account_slot(info, caller, expected_nonce)
                slots.append((key, account_nonce))
                signed = _loads(sign_call(caller_seed, caller_index, contract, order["call_args"], account_nonce, meter, fee,
                                          chain_id, until, transfer_fee, head, genesis))
            except Exception:
                with _SHARED_SESSION_GUARD:
                    for slot_key, slot in slots:
                        self._nonces.release(slot_key, slot)
                raise
            self._remember_targets([contract])
            outcome = self._submit_held(slots, signed["tx_hex"])
            return order, signed, outcome
