# QCore.py

The Quantova post quantum client core for Python. It is the Rust core QCore.rs built as a native extension with pyo3, so the key derivation, the post quantum signing, and every RPC request body are the core's and are never rewritten in Python. This package does the HTTP and reads the documented response fields, and the core does everything that has to be exactly right. A second implementation of the signing would be a second chance to be wrong with a user's money, so there is only ever the one.

One core with one binding for each language. QCore.rs is the Rust core. QCore.js is the JavaScript binding over it. QCore.py is this Python binding over it. It imports as qcore.

## What this library is for

Any Python program that holds a Quantova account, reads the chain, and sends signed transactions. A backend service, an indexer, an explorer, a faucet, a validator tool, or a script. Your code drives the flow it wants and QCore.py derives the key, signs the transaction, and builds the request body, so nothing about the cryptography or the byte layout of a transaction is written in Python.

## The post quantum cryptography it handles

Quantova is post quantum from the ground. There is no elliptic curve anywhere in it, no secp256k1, no ECDSA, no Ethereum address, and no Substrate envelope. Every primitive below is Quantova's own from scratch implementation in the Q Crypto library, carrying no third party cryptography dependency, compiled into the native extension that ships with this package.

1. Key derivation. Your program holds one master seed of thirty two bytes. QCore.py grows a per account seed from it with SHAKE256 over the master seed, the scheme byte, and the account index, then derives a module lattice key pair from that seed. The node runs the identical derivation, so the account a key signs from is the account that holds the funds.

2. The signing scheme. The default is the module lattice signature ML-DSA-65 as standardised in FIPS 204, carried on the wire as scheme one. The hash based signature SLH-DSA as standardised in FIPS 205 is scheme two. Signing is deterministic, so one transaction body always signs to one exact run of bytes, which makes a signed transaction reproducible and testable.

3. The address. A Quantova address is the Bech32m q1 string that renders the SHA3 256 hash of the scheme byte together with the whole module lattice public key of one thousand nine hundred fifty two bytes. The entire public key is bound into the address. Nothing is truncated to a twenty byte hash and there is no key recovery from a signature, so one address names exactly one post quantum key.

4. The transaction. A transaction body carries the sender, the nonce, the meter limit, the fee, and the call. The bytes a signature stands over are the SHA3 256 hash of the canonical body followed by a fixed Quantova transaction domain tag, so a transaction signature can never be replayed as another kind of signed message. QCore.py assembles the body, signs the digest inside the native extension, and returns the wrapper bytes and the transaction id ready for the gateway.

## How it is customised to Quantova and inherits nothing from the industry

Quantova shares no wire, no address, and no unit with any other chain, and QCore.py speaks only Quantova. The address is a q1 Bech32m string over a full post quantum key, never a hex twenty byte address and never an SS58 string. Money is counted in Quon, the smallest unit, at one million Quon to one QTOV, and it comes back as a decimal string that you convert with int only where a whole number is needed. The wire is the Quantova gateway, an HTTP POST to a named method under a version prefix with a flat JSON body, not Ethereum JSON RPC and not a Substrate WebSocket. The transaction encoding is Quantova's own canonical codec, not RLP and not SCALE. The signatures come from Q Crypto, Quantova's own implementation of the lattice and hash standards written from scratch, not a borrowed library.

## Creating a wallet

```python
import qcore

seed = qcore.generate_seed()             # thirty two random bytes as hex from the platform source
phrase = qcore.mnemonic_from_seed(seed)  # the only backup, shown once and kept on the device
```

## Using it

```python
import qcore

client = qcore.Client("http://127.0.0.1:8645")
seed = "0b" * 32
to = client.address(seed, 1)

# Reads the fee and the nonce, signs inside the core, and submits. Nothing is
# signed or built in Python. The last argument is the highest fee you will accept,
# and the core refuses to sign a fee the gateway reports above it, so a gateway
# cannot inflate the fee and drain the account.
info = client.node_info()
signed, outcome = client.transfer(seed, 0, to, 1000, info["fee"]["transfer_quon"])
status = client.transaction(signed["tx_id"])
```

## Building

```
maturin develop
```

The build needs maturin, which you install into a virtual environment with pip. Use maturin build for a release wheel.

## A note on releases

Nothing here is published to a registry without an explicit release. This package handles a user's keys and a published version cannot be taken back.

## Ownership and license

QCore.py is built and owned by Quantova Inc and is generated over the Rust core QCore.rs, so the signing lives in one place and is never rewritten in Python. It carries none of the industry stack and inherits nothing from it. It is released under the Apache 2.0 and MIT licenses so any wallet, explorer, or service may build on it, and the copyright stays with Quantova Inc.
