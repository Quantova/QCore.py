// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use qtv_wipe::{Zeroize, Zeroizing};

fn seed(seed_hex: &str) -> PyResult<Zeroizing<[u8; 32]>> {
    let mut bytes = qcore::json::from_hex(seed_hex).map_err(PyValueError::new_err)?;
    if bytes.len() != 32 {
        bytes.zeroize();
        return Err(PyValueError::new_err("a seed is 32 bytes of hex"));
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&bytes);
    bytes.zeroize();
    Ok(seed)
}

#[pyfunction]
fn address(seed_hex: &str, index: u64) -> PyResult<String> {
    Ok(qcore::account_address(&*seed(seed_hex)?, index))
}

#[pyfunction]
fn valid_address(address: &str) -> bool {
    qcore::valid_address(address)
}

#[pyfunction]
fn mnemonic_from_seed(seed_hex: &str) -> PyResult<String> {
    Ok(qcore::mnemonic_from_seed(&*seed(seed_hex)?))
}

#[pyfunction]
fn seed_from_mnemonic(phrase: &str) -> PyResult<String> {
    let seed = qcore::seed_from_mnemonic(phrase).map_err(PyValueError::new_err)?;
    Ok(qcore::json::to_hex(&seed[..]))
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn sign_transfer(
    seed_hex: &str,
    index: u64,
    to: &str,
    amount: u64,
    nonce: u64,
    fee: u128,
    chain_id: u64,
) -> PyResult<String> {
    if !qcore::valid_address(to) {
        return Err(PyValueError::new_err("the recipient is not a Q1 address"));
    }
    let signed = qcore::sign_transfer(&*seed(seed_hex)?, index, to, amount, nonce, fee, chain_id)
        .map_err(PyValueError::new_err)?;
    Ok(qcore::json::object(vec![
        ("from", qcore::json::Json::str(signed.from)),
        ("tx_id", qcore::json::Json::str(signed.tx_id)),
        (
            "tx_hex",
            qcore::json::Json::str(qcore::json::to_hex(&signed.tx_bytes)),
        ),
    ])
    .render())
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn sign_call(
    seed_hex: &str,
    index: u64,
    target: &str,
    args_hex: &str,
    nonce: u64,
    meter_limit: u64,
    fee: u128,
    chain_id: u64,
) -> PyResult<String> {
    if !qcore::valid_address(target) {
        return Err(PyValueError::new_err("the target is not a Q1 address"));
    }
    let args = qcore::json::from_hex(args_hex).map_err(PyValueError::new_err)?;
    let signed = qcore::sign_call(
        &*seed(seed_hex)?,
        index,
        target,
        args,
        nonce,
        meter_limit,
        fee,
        chain_id,
    )
    .map_err(PyValueError::new_err)?;
    Ok(qcore::json::object(vec![
        ("from", qcore::json::Json::str(signed.from)),
        ("tx_id", qcore::json::Json::str(signed.tx_id)),
        (
            "tx_hex",
            qcore::json::Json::str(qcore::json::to_hex(&signed.tx_bytes)),
        ),
    ])
    .render())
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn sign_payable_call(
    seed_hex: &str,
    index: u64,
    target: &str,
    args_hex: &str,
    nonce: u64,
    meter_limit: u64,
    fee: u128,
    value: u64,
    chain_id: u64,
) -> PyResult<String> {
    if !qcore::valid_address(target) {
        return Err(PyValueError::new_err("the target is not a Q1 address"));
    }
    let args = qcore::json::from_hex(args_hex).map_err(PyValueError::new_err)?;
    let sender = qtv_account::derive(&*seed(seed_hex)?, index);
    let call = qtv_tx::Call::new(target.to_string(), args);
    let body = qtv_tx::Body::with_context(
        sender.address(),
        nonce,
        meter_limit,
        fee,
        call,
        value,
        chain_id,
    );
    let wrapper = qtv_tx::sign(&sender, &body);
    let tx_bytes = qtv_codec::to_bytes(&wrapper);
    Ok(qcore::json::object(vec![
        ("from", qcore::json::Json::str(sender.address())),
        ("tx_id", qcore::json::Json::str(wrapper.id())),
        (
            "tx_hex",
            qcore::json::Json::str(qcore::json::to_hex(&tx_bytes)),
        ),
    ])
    .render())
}

#[pyfunction]
fn sign_register(
    seed_hex: &str,
    index: u64,
    nonce: u64,
    fee: u128,
    chain_id: u64,
) -> PyResult<String> {
    let signed = qcore::sign_register(&*seed(seed_hex)?, index, nonce, fee, chain_id)
        .map_err(PyValueError::new_err)?;
    Ok(qcore::json::object(vec![
        ("from", qcore::json::Json::str(signed.from)),
        ("tx_id", qcore::json::Json::str(signed.tx_id)),
        (
            "tx_hex",
            qcore::json::Json::str(qcore::json::to_hex(&signed.tx_bytes)),
        ),
    ])
    .render())
}

#[pyfunction]
fn chain_id_from_name(name: &str) -> u64 {
    qtv_tx::chain_id_from_name(name)
}

#[pyfunction]
fn local_chain_id() -> u64 {
    qtv_tx::LOCAL_CHAIN_ID
}

#[pyfunction]
fn testnet_chain_id() -> u64 {
    qtv_tx::TESTNET_CHAIN_ID
}

#[pyfunction]
fn mainnet_chain_id() -> u64 {
    qtv_tx::MAINNET_CHAIN_ID
}

#[pyfunction]
fn submit_body(tx_hex: &str) -> PyResult<String> {
    let bytes = qcore::json::from_hex(tx_hex).map_err(PyValueError::new_err)?;
    Ok(qcore::submit_body(&bytes))
}

#[pyfunction]
fn account_body(address: &str) -> String {
    qcore::account_body(address)
}

#[pyfunction]
fn transaction_body(tx_id: &str) -> String {
    qcore::transaction_body(tx_id)
}

#[pyfunction]
fn block_by_height_body(height: u64) -> String {
    qcore::block_by_height_body(height)
}

fn parse_typed_fields(fields_json: &str) -> PyResult<Vec<qcore::contract::TypedField>> {
    let parsed = qcore::json::parse(fields_json).map_err(PyValueError::new_err)?;
    let items = match &parsed {
        qcore::json::Json::Array(items) => items,
        _ => {
            return Err(PyValueError::new_err(
                "the signed order fields must be a JSON array",
            ))
        }
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let offset = item
            .get("offset")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| PyValueError::new_err("a signed order field needs a numeric offset"))?;
        let width = item
            .get("width")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| PyValueError::new_err("a signed order field needs a numeric width"))?;
        let value = item
            .get("value")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PyValueError::new_err("a signed order field needs a string value"))?
            .to_string();
        out.push(qcore::contract::TypedField {
            offset,
            width,
            value,
        });
    }
    Ok(out)
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn build_typed_order_call(
    chain_id: u64,
    contract: &str,
    selector_hex: &str,
    scheme_off: u64,
    ptr_off: u64,
    region_off: u64,
    fields_json: &str,
    owner_seed_hex: &str,
    owner_index: u64,
    nonce: u64,
) -> PyResult<String> {
    let selector: [u8; 4] = qcore::json::from_hex(selector_hex)
        .map_err(PyValueError::new_err)?
        .try_into()
        .map_err(|_| PyValueError::new_err("the selector is 4 bytes of hex"))?;
    let fields = parse_typed_fields(fields_json)?;
    let order = qcore::contract::build_order_from_typed(
        chain_id,
        contract,
        selector,
        scheme_off,
        ptr_off,
        region_off,
        &fields,
        &*seed(owner_seed_hex)?,
        owner_index,
        nonce,
    )
    .map_err(PyValueError::new_err)?;
    Ok(qcore::json::object(vec![
        (
            "call_args",
            qcore::json::Json::str(qcore::json::to_hex(&order.call_args)),
        ),
        (
            "message",
            qcore::json::Json::str(qcore::json::to_hex(&order.message)),
        ),
        (
            "signature",
            qcore::json::Json::str(qcore::json::to_hex(&order.signature)),
        ),
        (
            "public_key",
            qcore::json::Json::str(qcore::json::to_hex(&order.public_key)),
        ),
        (
            "signer",
            qcore::json::Json::str(qcore::json::to_hex(&order.signer)),
        ),
        ("nonce", qcore::json::Json::Int(order.nonce)),
    ])
    .render())
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(address, m)?)?;
    m.add_function(wrap_pyfunction!(valid_address, m)?)?;
    m.add_function(wrap_pyfunction!(mnemonic_from_seed, m)?)?;
    m.add_function(wrap_pyfunction!(seed_from_mnemonic, m)?)?;
    m.add_function(wrap_pyfunction!(sign_transfer, m)?)?;
    m.add_function(wrap_pyfunction!(sign_call, m)?)?;
    m.add_function(wrap_pyfunction!(sign_payable_call, m)?)?;
    m.add_function(wrap_pyfunction!(sign_register, m)?)?;
    m.add_function(wrap_pyfunction!(build_typed_order_call, m)?)?;
    m.add_function(wrap_pyfunction!(chain_id_from_name, m)?)?;
    m.add_function(wrap_pyfunction!(local_chain_id, m)?)?;
    m.add_function(wrap_pyfunction!(testnet_chain_id, m)?)?;
    m.add_function(wrap_pyfunction!(mainnet_chain_id, m)?)?;
    m.add_function(wrap_pyfunction!(submit_body, m)?)?;
    m.add_function(wrap_pyfunction!(account_body, m)?)?;
    m.add_function(wrap_pyfunction!(transaction_body, m)?)?;
    m.add_function(wrap_pyfunction!(block_by_height_body, m)?)?;
    Ok(())
}
