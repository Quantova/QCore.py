// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes, PyString};
use qtv_wipe::Zeroizing;

fn genesis(hex: &str) -> PyResult<[u8; 32]> {
    qcore::json::from_hex(hex)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| PyValueError::new_err("the genesis hash must be 32 bytes of hex"))
}

fn seed(seed_bytes: &Bound<'_, PyAny>) -> PyResult<Zeroizing<[u8; 32]>> {
    if seed_bytes.cast::<PyBytes>().is_ok() {
        return Err(PyValueError::new_err(
            "a seed must be a bytearray you can wipe after use, an immutable bytes object stays in memory",
        ));
    }
    if let Ok(array) = seed_bytes.cast::<PyByteArray>() {
        let copied = Zeroizing::new(array.to_vec());
        return copy_seed(&copied);
    }
    copy_seed(&[])
}

fn copy_seed(seed_bytes: &[u8]) -> PyResult<Zeroizing<[u8; 32]>> {
    if seed_bytes.len() != 32 {
        return Err(PyValueError::new_err(
            "a seed is 32 raw bytes (pass a bytearray you can wipe, not a hex string)",
        ));
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(seed_bytes);
    Ok(seed)
}

#[pyfunction]
fn address(seed_bytes: &Bound<'_, PyAny>, index: u64) -> PyResult<String> {
    Ok(qcore::account_address(&*seed(seed_bytes)?, index))
}

#[pyfunction]
fn valid_address(address: &str) -> bool {
    qcore::valid_address(address)
}

#[pyfunction]
fn same_address(a: &str, b: &str) -> bool {
    qcore::same_address(a, b)
}

#[pyfunction]
fn lookalike_of(candidate: &str, known: Vec<String>) -> Option<String> {
    qcore::lookalike_of(candidate, &known)
}

#[pyfunction]
fn mnemonic_from_seed<'py>(
    py: Python<'py>,
    seed_bytes: &Bound<'_, PyAny>,
) -> PyResult<Bound<'py, PyByteArray>> {
    let phrase = qcore::mnemonic_bytes_from_seed(&*seed(seed_bytes)?);
    Ok(PyByteArray::new(py, &phrase))
}

#[pyfunction]
fn mnemonic_from_seed_text<'py>(
    py: Python<'py>,
    seed_bytes: &Bound<'_, PyAny>,
) -> PyResult<Bound<'py, PyString>> {
    let phrase = qcore::mnemonic_from_seed(&*seed(seed_bytes)?);
    Ok(PyString::new(py, &phrase))
}

#[pyfunction]
fn seed_from_mnemonic<'py>(
    py: Python<'py>,
    phrase: &Bound<'_, PyAny>,
) -> PyResult<Bound<'py, PyByteArray>> {
    let seed = if let Ok(text) = phrase.cast::<PyString>() {
        let owned = Zeroizing::new(text.to_cow()?.into_owned());
        qcore::seed_from_mnemonic(&owned)
    } else if let Ok(bytes) = phrase.cast::<PyBytes>() {
        qcore::seed_from_mnemonic_bytes(bytes.as_bytes())
    } else if let Ok(array) = phrase.cast::<PyByteArray>() {
        let copied = Zeroizing::new(array.to_vec());
        qcore::seed_from_mnemonic_bytes(&copied)
    } else {
        return Err(PyValueError::new_err(
            "the recovery phrase must be a str, bytes or bytearray",
        ));
    }
    .map_err(PyValueError::new_err)?;
    Ok(PyByteArray::new(py, &seed[..]))
}

#[pyfunction]
fn genesis_secs(chain_name: &str) -> u64 {
    qcore::genesis_secs(chain_name)
}

#[pyfunction]
fn head_ceiling(chain_name: &str, wall_secs: u64) -> u64 {
    qcore::head_ceiling(chain_name, wall_secs)
}

#[pyfunction]
#[pyo3(signature = (chain_name, head, wall_secs, floor, floor_age_secs))]
fn bounded_valid_until(
    chain_name: &str,
    head: u64,
    wall_secs: u64,
    floor: Option<u64>,
    floor_age_secs: u64,
) -> PyResult<u64> {
    qcore::bounded_valid_until(chain_name, head, wall_secs, floor, floor_age_secs)
        .map_err(PyValueError::new_err)
}

#[pyfunction]
fn check_gateway_json(response: &str) -> PyResult<()> {
    qcore::check_gateway_json(response).map_err(PyValueError::new_err)
}

#[pyfunction]
fn check_endpoint(base: &str) -> PyResult<()> {
    qcore::check_endpoint(base).map_err(PyValueError::new_err)
}

#[pyfunction]
fn testnet_rpc_url() -> &'static str {
    qcore::TESTNET_RPC_URL
}

#[pyfunction]
fn gateway_protocol() -> u32 {
    qcore::GATEWAY_PROTOCOL
}

#[pyfunction]
fn testnet_genesis_hash() -> Option<String> {
    qcore::TESTNET_GENESIS_HASH.map(|hash| qcore::json::to_hex(&hash))
}

#[pyfunction]
fn mainnet_genesis_hash() -> Option<String> {
    qcore::MAINNET_GENESIS_HASH.map(|hash| qcore::json::to_hex(&hash))
}

#[pyfunction]
fn testnet_chain_name() -> &'static str {
    qcore::TESTNET_CHAIN_NAME
}

#[pyfunction]
fn validity_blocks() -> u64 {
    qcore::DEFAULT_VALIDITY_BLOCKS
}

#[pyclass(name = "SigningSession")]
struct SigningSession(qcore::SigningSession);

#[pymethods]
impl SigningSession {
    #[new]
    #[pyo3(signature = (book = Vec::new()))]
    fn new(book: Vec<String>) -> PyResult<SigningSession> {
        qcore::SigningSession::with_address_book(&book)
            .map(SigningSession)
            .map_err(PyValueError::new_err)
    }

    fn remember_address(&mut self, address: &str) {
        self.0.remember_address(address)
    }

    fn check_target(&self, address: &str) -> PyResult<()> {
        self.0.check_target(address).map_err(PyValueError::new_err)
    }

    #[pyo3(signature = (key, reported, expected, order))]
    fn slot(
        &mut self,
        key: &str,
        reported: u64,
        expected: Option<u64>,
        order: bool,
    ) -> PyResult<u64> {
        self.0
            .slot(key, reported, expected, order)
            .map_err(PyRuntimeError::new_err)
    }

    fn signed(&mut self, key: &str, slot: u64) {
        self.0.signed(key, slot)
    }

    fn release(&mut self, key: &str, slot: u64) {
        self.0.release(key, slot)
    }

    fn export_state(&self) -> String {
        self.0.export_state()
    }

    fn import_state(&mut self, state: &str) -> PyResult<()> {
        self.0.import_state(state).map_err(PyValueError::new_err)
    }

    fn release_pending(&mut self, key: &str) {
        self.0.release_pending(key)
    }

    fn outcome(&mut self, key: &str, slot: u64, accepted: bool) {
        self.0.outcome(key, slot, accepted)
    }

    fn next_nonce(&self, key: &str) -> Option<u64> {
        self.0.next_nonce(key)
    }

    fn is_held(&self, key: &str, slot: u64) -> bool {
        self.0.is_held(key, slot)
    }

    fn head_floor(&self, chain: &str) -> Option<(u64, u64)> {
        self.0.head_floor(chain)
    }

    fn note_head(&mut self, chain: &str, height: u64, wall_secs: u64) {
        self.0.note_head(chain, height, wall_secs)
    }
}

fn addr32(hex: &str) -> PyResult<[u8; 32]> {
    qcore::json::from_hex(hex)
        .map_err(PyValueError::new_err)?
        .try_into()
        .map_err(|_| PyValueError::new_err("expected 32 bytes of hex"))
}

#[pyfunction]
fn order_signer(seed_bytes: &Bound<'_, PyAny>, index: u64) -> PyResult<String> {
    Ok(qcore::json::to_hex(&qcore::contract::order_signer(
        &*seed(seed_bytes)?,
        index,
    )))
}

#[pyfunction]
fn vm_deploy_address() -> String {
    qcore::vm_deploy_address()
}

#[pyfunction]
fn contract_address(deployer: &str, nonce: u64) -> Option<String> {
    qcore::contract_address(deployer, nonce)
}

#[pyfunction]
fn nonce_slot_key(signer_hex: &str) -> PyResult<String> {
    Ok(qcore::json::to_hex(&qcore::contract::nonce_slot_key(
        &addr32(signer_hex)?,
    )))
}

#[pyfunction]
fn scalar_slot_key(slot: u64) -> String {
    qcore::json::to_hex(&qcore::contract::scalar_slot_key(slot))
}

#[pyfunction]
fn map_slot_key(map_domain_tag: u64, key_address_hex: &str) -> PyResult<String> {
    Ok(qcore::json::to_hex(&qcore::contract::map_slot_key(
        map_domain_tag,
        &addr32(key_address_hex)?,
    )))
}

#[pyfunction]
fn map_addr_word_key(map_domain_tag: u64, key32_hex: &str, word: u64) -> PyResult<String> {
    Ok(qcore::json::to_hex(&qcore::contract::map_addr_word_key(
        map_domain_tag,
        &addr32(key32_hex)?,
        word,
    )))
}

#[pyfunction]
fn name_key(label: &str) -> String {
    qcore::json::to_hex(&qcore::contract::name_key(label))
}

#[pyfunction]
fn token_decimals_slot() -> u64 {
    qcore::contract::TOKEN_DECIMALS_SLOT
}

#[pyfunction]
fn token_symbol_slot() -> u64 {
    qcore::contract::TOKEN_SYMBOL_SLOT
}

#[pyfunction]
fn pack_symbol(symbol: &str) -> u64 {
    qcore::contract::pack_symbol(symbol)
}

#[pyfunction]
fn unpack_symbol(word: u64) -> String {
    qcore::contract::unpack_symbol(word)
}

#[pyfunction]
fn storage_body(contract: &str) -> String {
    qcore::contract::storage_body(contract)
}

#[pyfunction]
fn events_body(height: u64) -> String {
    qcore::contract::events_body(height)
}

#[pyfunction]
fn asset_balance_body(issuer: &str, holder: &str) -> String {
    qcore::contract::asset_balance_body(issuer, holder)
}

#[pyfunction]
fn asset_supply_body(issuer: &str) -> String {
    qcore::contract::asset_supply_body(issuer)
}

#[pyfunction]
fn storage_value(response: &str, slot_key_hex: &str) -> PyResult<u64> {
    let slots = qcore::contract::parse_storage(response).map_err(PyValueError::new_err)?;
    Ok(qcore::contract::storage_value(
        &slots,
        &addr32(slot_key_hex)?,
    ))
}

#[pyfunction]
fn storage_value_reported(response: &str, slot_key_hex: &str) -> PyResult<Option<u64>> {
    let slots = qcore::contract::parse_storage(response).map_err(PyValueError::new_err)?;
    Ok(qcore::contract::storage_value_reported(
        &slots,
        &addr32(slot_key_hex)?,
    ))
}

#[pyfunction]
fn check_order_expiry(expiry: u64, now_secs: u64) -> PyResult<()> {
    qcore::contract::check_order_expiry(expiry, now_secs).map_err(PyValueError::new_err)
}

#[pyfunction]
fn parse_events(response: &str) -> PyResult<String> {
    let events = qcore::contract::parse_events(response).map_err(PyValueError::new_err)?;
    let items: Vec<qcore::json::Json> = events
        .iter()
        .map(|event| {
            let mut fields = vec![
                ("contract", qcore::json::Json::str(event.contract.clone())),
                (
                    "selector",
                    qcore::json::Json::str(qcore::json::to_hex(&event.selector)),
                ),
                (
                    "data",
                    qcore::json::Json::str(qcore::json::to_hex(&event.data)),
                ),
            ];
            if let Some(word) = qcore::contract::event_word(&event.data) {
                fields.push(("value", qcore::json::Json::str(word.to_string())));
            }
            qcore::json::object(fields)
        })
        .collect();
    Ok(qcore::json::Json::Array(items).render())
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn sign_transfer(
    seed_bytes: &Bound<'_, PyAny>,
    index: u64,
    to: &str,
    amount: u64,
    nonce: u64,
    fee: u128,
    chain_id: u64,
    valid_until: u64,
    head: u64,
    genesis_hex: &str,
) -> PyResult<String> {
    if !qcore::valid_address(to) {
        return Err(PyValueError::new_err("the recipient is not a Q1 address"));
    }
    let signed = qcore::sign_transfer(
        &*seed(seed_bytes)?,
        index,
        to,
        amount,
        nonce,
        fee,
        chain_id,
        valid_until,
        head,
        &genesis(genesis_hex)?,
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
fn sign_call(
    seed_bytes: &Bound<'_, PyAny>,
    index: u64,
    target: &str,
    args_hex: &str,
    nonce: u64,
    meter_limit: u64,
    fee: u128,
    chain_id: u64,
    valid_until: u64,
    transfer_fee: u128,
    head: u64,
    genesis_hex: &str,
) -> PyResult<String> {
    if !qcore::valid_address(target) {
        return Err(PyValueError::new_err("the target is not a Q1 address"));
    }
    let args = qcore::json::from_hex(args_hex).map_err(PyValueError::new_err)?;
    let signed = qcore::sign_call(
        &*seed(seed_bytes)?,
        index,
        target,
        args,
        nonce,
        meter_limit,
        fee,
        chain_id,
        valid_until,
        transfer_fee,
        head,
        &genesis(genesis_hex)?,
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
    seed_bytes: &Bound<'_, PyAny>,
    index: u64,
    target: &str,
    args_hex: &str,
    nonce: u64,
    meter_limit: u64,
    fee: u128,
    value: u64,
    chain_id: u64,
    valid_until: u64,
    transfer_fee: u128,
    head: u64,
    genesis_hex: &str,
) -> PyResult<String> {
    if !qcore::valid_address(target) {
        return Err(PyValueError::new_err("the target is not a Q1 address"));
    }
    let args = qcore::json::from_hex(args_hex).map_err(PyValueError::new_err)?;
    let signed = qcore::sign_payable_call(
        &*seed(seed_bytes)?,
        index,
        target,
        args,
        value,
        nonce,
        meter_limit,
        fee,
        chain_id,
        valid_until,
        transfer_fee,
        head,
        &genesis(genesis_hex)?,
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
fn sign_asset_call(
    seed_bytes: &Bound<'_, PyAny>,
    index: u64,
    target: &str,
    args_hex: &str,
    asset_issuer: &str,
    amount: u64,
    nonce: u64,
    meter_limit: u64,
    fee: u128,
    chain_id: u64,
    valid_until: u64,
    transfer_fee: u128,
    head: u64,
    genesis_hex: &str,
) -> PyResult<String> {
    let args = qcore::json::from_hex(args_hex).map_err(PyValueError::new_err)?;
    let signed = qcore::sign_asset_call(
        &*seed(seed_bytes)?,
        index,
        target,
        args,
        asset_issuer,
        amount,
        nonce,
        meter_limit,
        fee,
        chain_id,
        valid_until,
        transfer_fee,
        head,
        &genesis(genesis_hex)?,
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
fn sign_register(
    seed_bytes: &Bound<'_, PyAny>,
    index: u64,
    nonce: u64,
    fee: u128,
    chain_id: u64,
    valid_until: u64,
    head: u64,
    genesis_hex: &str,
) -> PyResult<String> {
    let signed = qcore::sign_register(
        &*seed(seed_bytes)?,
        index,
        nonce,
        fee,
        chain_id,
        valid_until,
        head,
        &genesis(genesis_hex)?,
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
fn deploy_fee_quon(node_info: &str) -> PyResult<u128> {
    let info = qcore::parse_node_info(node_info).map_err(PyValueError::new_err)?;
    qcore::deploy_fee_of(&info).map_err(PyValueError::new_err)
}

#[pyfunction]
fn vm_call_fee(transfer_fee: u128, meter_limit: u64) -> u128 {
    qcore::vm_call_fee(transfer_fee, meter_limit)
}

#[pyfunction]
fn check_valid_until(valid_until: u64, head: u64) -> PyResult<()> {
    qcore::check_valid_until(valid_until, head).map_err(PyValueError::new_err)
}

#[pyfunction]
fn chain_id_from_name(name: &str) -> PyResult<u64> {
    qcore::checked_chain_id(name).map_err(PyValueError::new_err)
}

#[pyfunction]
fn local_chain_id() -> u64 {
    qcore::LOCAL_CHAIN_ID
}

#[pyfunction]
fn testnet_chain_id() -> u64 {
    qcore::testnet_chain_id()
}

#[pyfunction]
fn mainnet_chain_id() -> u64 {
    qcore::MAINNET_CHAIN_ID
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
fn order_layout_hash(selector_hex: &str, fields_json: &str) -> PyResult<String> {
    let selector: [u8; 4] = qcore::json::from_hex(selector_hex)
        .map_err(PyValueError::new_err)?
        .try_into()
        .map_err(|_| PyValueError::new_err("the selector is 4 bytes of hex"))?;
    let parsed = qcore::json::parse(fields_json).map_err(PyValueError::new_err)?;
    let items = match &parsed {
        qcore::json::Json::Array(items) => items,
        _ => {
            return Err(PyValueError::new_err(
                "the order layout must be a JSON array",
            ))
        }
    };
    let mut fields = Vec::with_capacity(items.len());
    for item in items {
        let name = item
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PyValueError::new_err("an order layout field needs a string name"))?;
        let ty = item
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PyValueError::new_err("an order layout field needs a string type"))?;
        let width = item
            .get("width")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| PyValueError::new_err("an order layout field needs a numeric width"))?;
        fields.push(qcore::contract::OrderLayoutField {
            name: name.to_string(),
            ty: ty.to_string(),
            width,
        });
    }
    Ok(qcore::json::to_hex(&qcore::contract::order_layout_hash(
        selector, &fields,
    )))
}

fn signed_orders() -> std::sync::MutexGuard<'static, std::collections::HashMap<String, Vec<u8>>> {
    static SIGNED: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
    > = std::sync::OnceLock::new();
    SIGNED
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[pyfunction]
#[pyo3(signature = (chain_id, genesis_hex, contract, selector_hex, layout_hash_hex, scheme_off, ptr_off, expiry_off, region_off, fields_json, owner_seed_bytes, owner_index, nonce, expiry, resign = false))]
#[allow(clippy::too_many_arguments)]
fn build_typed_order_call(
    chain_id: u64,
    genesis_hex: &str,
    contract: &str,
    selector_hex: &str,
    layout_hash_hex: &str,
    scheme_off: u64,
    ptr_off: u64,
    expiry_off: u64,
    region_off: u64,
    fields_json: &str,
    owner_seed_bytes: &Bound<'_, PyAny>,
    owner_index: u64,
    nonce: u64,
    expiry: u64,
    resign: bool,
) -> PyResult<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| PyRuntimeError::new_err("the system clock is before 1970"))?
        .as_secs();
    qcore::contract::check_order_expiry(expiry, now).map_err(PyValueError::new_err)?;
    let owner = seed(owner_seed_bytes)?;
    if !qcore::valid_address(contract) {
        return Err(PyValueError::new_err("the contract is not a Q1 address"));
    }
    let canonical = contract.to_ascii_uppercase();
    let signer = qcore::json::to_hex(&qcore::contract::order_signer(&owner, owner_index));
    let genesis = genesis(genesis_hex)?;
    let order_key = format!(
        "{chain_id}/{}/{canonical}/{signer}/{nonce}",
        qcore::json::to_hex(&genesis)
    );
    let selector: [u8; 4] = qcore::json::from_hex(selector_hex)
        .map_err(PyValueError::new_err)?
        .try_into()
        .map_err(|_| PyValueError::new_err("the selector is 4 bytes of hex"))?;
    let layout_hash =
        qcore::contract::layout_hash_from_hex(layout_hash_hex).map_err(PyValueError::new_err)?;
    let fields = parse_typed_fields(fields_json)?;
    let order = qcore::contract::build_order_from_typed(
        chain_id,
        &genesis,
        contract,
        selector,
        &layout_hash,
        scheme_off,
        ptr_off,
        expiry_off,
        region_off,
        &fields,
        &owner,
        owner_index,
        nonce,
        expiry,
    )
    .map_err(PyValueError::new_err)?;
    {
        let mut signed = signed_orders();
        match signed.get(&order_key) {
            Some(message) if *message != order.message && !resign => {
                return Err(PyRuntimeError::new_err(format!(
                    "an order with other terms was already signed at order nonce {nonce} for this contract and signer, one order nonce carries one order, pass resign=True only when the first can never be used"
                )))
            }
            _ => {
                signed.insert(order_key, order.message.clone());
            }
        }
    }
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
        ("expiry", qcore::json::Json::Int(order.expiry)),
    ])
    .render())
}

fn parse_roster(roster_json: &str) -> Result<Vec<qcore::finality::RosterMember>, String> {
    qcore::finality::parse_roster(roster_json)
}

fn parse_steps(steps_json: &str) -> Result<Vec<([u8; 32], bool)>, String> {
    let parsed = qcore::json::parse(steps_json)?;
    let items = match &parsed {
        qcore::json::Json::Array(items) => items,
        _ => return Err("the proof steps must be a JSON array".to_string()),
    };
    let mut steps = Vec::with_capacity(items.len());
    for item in items {
        let sibling = item
            .get("sibling")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "a proof step needs a sibling".to_string())?;
        let left = match item.get("left") {
            Some(qcore::json::Json::Bool(b)) => *b,
            _ => return Err("a proof step needs a boolean left".to_string()),
        };
        let bytes: [u8; 32] = qcore::json::from_hex(sibling)?
            .try_into()
            .map_err(|_| "a proof sibling is 32 bytes of hex".to_string())?;
        steps.push((bytes, left));
    }
    Ok(steps)
}

fn finalized_json(h: &qcore::finality::FinalizedHeader) -> String {
    qcore::json::object(vec![
        ("height", qcore::json::Json::str(h.height.to_string())),
        ("hash", qcore::json::Json::str(qcore::json::to_hex(&h.hash))),
        (
            "parent_hash",
            qcore::json::Json::str(qcore::json::to_hex(&h.parent_hash)),
        ),
        (
            "q_root",
            qcore::json::Json::str(qcore::json::to_hex(&h.q_root)),
        ),
        (
            "transaction_root",
            qcore::json::Json::str(qcore::json::to_hex(&h.transaction_root)),
        ),
        (
            "event_root",
            qcore::json::Json::str(qcore::json::to_hex(&h.event_root)),
        ),
        ("time", qcore::json::Json::str(h.time.to_string())),
        (
            "signed_stake",
            qcore::json::Json::str(h.signed_stake.to_string()),
        ),
        (
            "total_stake",
            qcore::json::Json::str(h.total_stake.to_string()),
        ),
    ])
    .render()
}

fn hash32(hex: &str, what: &str) -> PyResult<[u8; 32]> {
    qcore::json::from_hex(hex)
        .map_err(PyValueError::new_err)?
        .try_into()
        .map_err(|_| PyValueError::new_err(format!("the {what} must be 32 bytes of hex")))
}

#[pyfunction]
pub fn roster_commitment(epoch: u64, roster_json: &str) -> PyResult<String> {
    let roster = parse_roster(roster_json).map_err(PyValueError::new_err)?;
    Ok(qcore::json::to_hex(&qcore::finality::roster_commitment_of(
        epoch, &roster,
    )))
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
pub fn verify_next_roster(
    chain_id: u64,
    genesis_hex: &str,
    epoch_length: u64,
    current_epoch: u64,
    current_roster_json: &str,
    header_hex: &str,
    certificate_hex: &str,
    next_roster_json: &str,
    proof_hex: &str,
) -> PyResult<u64> {
    let current = qcore::finality::VerifiedRoster {
        epoch: current_epoch,
        members: parse_roster(current_roster_json).map_err(PyValueError::new_err)?,
    };
    let next = qcore::finality::verify_next_roster(
        chain_id,
        &hash32(genesis_hex, "genesis hash")?,
        epoch_length,
        &current,
        &qcore::json::from_hex(header_hex).map_err(PyValueError::new_err)?,
        &qcore::json::from_hex(certificate_hex).map_err(PyValueError::new_err)?,
        parse_roster(next_roster_json).map_err(PyValueError::new_err)?,
        &qcore::json::from_hex(proof_hex).map_err(PyValueError::new_err)?,
    )
    .map_err(PyValueError::new_err)?;
    Ok(next.epoch)
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
pub fn verify_account(
    chain_id: u64,
    genesis_hex: &str,
    epoch_length: u64,
    epoch: u64,
    roster_json: &str,
    address: &str,
    header_hex: &str,
    certificate_hex: &str,
    proof_hex: &str,
) -> PyResult<String> {
    let roster = qcore::finality::VerifiedRoster {
        epoch,
        members: parse_roster(roster_json).map_err(PyValueError::new_err)?,
    };
    let verified = qcore::finality::verify_account(
        chain_id,
        &hash32(genesis_hex, "genesis hash")?,
        epoch_length,
        &roster,
        address,
        &qcore::json::from_hex(header_hex).map_err(PyValueError::new_err)?,
        &qcore::json::from_hex(certificate_hex).map_err(PyValueError::new_err)?,
        &qcore::json::from_hex(proof_hex).map_err(PyValueError::new_err)?,
    )
    .map_err(PyValueError::new_err)?;
    let (exists, balance, nonce) = match &verified.account {
        Some(account) => (true, account.balance, account.nonce),
        None => (false, 0, 0),
    };
    Ok(qcore::json::object(vec![
        ("address", qcore::json::Json::str(&verified.address)),
        ("height", qcore::json::Json::Int(verified.header.height)),
        ("exists", qcore::json::Json::Bool(exists)),
        ("balance", qcore::json::Json::str(balance.to_string())),
        ("nonce", qcore::json::Json::str(nonce.to_string())),
    ])
    .render())
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
pub fn verify_finality_in_epoch(
    chain_id: u64,
    genesis_hex: &str,
    epoch_length: u64,
    epoch: u64,
    header_hex: &str,
    certificate_hex: &str,
    roster_json: &str,
) -> PyResult<String> {
    let roster = qcore::finality::VerifiedRoster {
        epoch,
        members: parse_roster(roster_json).map_err(PyValueError::new_err)?,
    };
    let verified = qcore::finality::verify_finality_in_epoch(
        chain_id,
        &hash32(genesis_hex, "genesis hash")?,
        epoch_length,
        &roster,
        &qcore::json::from_hex(header_hex).map_err(PyValueError::new_err)?,
        &qcore::json::from_hex(certificate_hex).map_err(PyValueError::new_err)?,
    )
    .map_err(PyValueError::new_err)?;
    Ok(finalized_json(&verified))
}

#[pyfunction]
fn header_height(header_hex: &str) -> PyResult<u64> {
    let header = qcore::json::from_hex(header_hex).map_err(PyValueError::new_err)?;
    qcore::finality::header_height(&header).map_err(PyValueError::new_err)
}

#[pyfunction]
fn transaction_kind(leaf_hex: &str) -> PyResult<&'static str> {
    let leaf = qcore::json::from_hex(leaf_hex).map_err(PyValueError::new_err)?;
    Ok(
        match qcore::finality::transaction_kind(&leaf).map_err(PyValueError::new_err)? {
            qcore::finality::TxKind::Transfer => "transfer",
            qcore::finality::TxKind::Call => "call",
        },
    )
}

#[pyfunction]
fn index_fits_path(index: u64, steps_json: &str) -> PyResult<bool> {
    let steps = parse_steps(steps_json).map_err(PyValueError::new_err)?;
    Ok(qcore::finality::index_fits_path(index, &steps))
}

#[pyfunction]
fn testnet_epoch_length() -> Option<u64> {
    qcore::TESTNET_EPOCH_LENGTH
}

#[pyfunction]
fn mainnet_epoch_length() -> Option<u64> {
    qcore::MAINNET_EPOCH_LENGTH
}

#[pyfunction]
fn testnet_genesis_secs() -> u64 {
    qcore::TESTNET_GENESIS_SECS
}

#[pyfunction]
fn testnet_blocks_per_sec() -> u64 {
    qcore::TESTNET_BLOCKS_PER_SEC
}

#[pyfunction]
fn response_cap(method: &str) -> usize {
    qcore::response_cap(method)
}

#[pyfunction]
#[pyo3(signature = (genesis_secs, blocks_per_sec, verified, head, wall_secs, floor, floor_age_secs))]
fn bounded_valid_until_for(
    genesis_secs: Option<u64>,
    blocks_per_sec: Option<u64>,
    verified: bool,
    head: u64,
    wall_secs: u64,
    floor: Option<u64>,
    floor_age_secs: u64,
) -> PyResult<u64> {
    let clock = match (genesis_secs, blocks_per_sec) {
        (Some(genesis), Some(rate)) => {
            Some(qcore::ChainClock::new(genesis, rate).map_err(PyValueError::new_err)?)
        }
        (None, None) => None,
        _ => {
            return Err(PyValueError::new_err(
                "a chain clock needs both a genesis time and a block rate",
            ))
        }
    };
    qcore::bounded_valid_until_for(
        clock.as_ref(),
        verified,
        head,
        wall_secs,
        floor,
        floor_age_secs,
    )
    .map_err(PyValueError::new_err)
}

#[pyfunction]
fn testnet_roster_commitment() -> Option<String> {
    qcore::TESTNET_ROSTER_COMMITMENT.map(|hash| qcore::json::to_hex(&hash))
}

#[pyfunction]
fn mainnet_roster_commitment() -> Option<String> {
    qcore::MAINNET_ROSTER_COMMITMENT.map(|hash| qcore::json::to_hex(&hash))
}

#[pyfunction]
pub fn verify_finality(
    chain_id: u64,
    genesis_hex: &str,
    header_hex: &str,
    certificate_hex: &str,
    roster_json: &str,
) -> PyResult<String> {
    let header = qcore::json::from_hex(header_hex).map_err(PyValueError::new_err)?;
    let certificate = qcore::json::from_hex(certificate_hex).map_err(PyValueError::new_err)?;
    let roster = parse_roster(roster_json).map_err(PyValueError::new_err)?;
    let genesis: [u8; 32] = qcore::json::from_hex(genesis_hex)
        .map_err(PyValueError::new_err)?
        .try_into()
        .map_err(|_| PyValueError::new_err("the genesis hash must be 32 bytes of hex"))?;
    let verified =
        qcore::finality::verify_finality(chain_id, &genesis, &header, &certificate, &roster)
            .map_err(PyValueError::new_err)?;
    Ok(finalized_json(&verified))
}

#[pyfunction]
pub fn verify_event(event_root_hex: &str, leaf_hex: &str, steps_json: &str) -> PyResult<bool> {
    let root: [u8; 32] = qcore::json::from_hex(event_root_hex)
        .map_err(PyValueError::new_err)?
        .try_into()
        .map_err(|_| PyValueError::new_err("the event root is 32 bytes of hex"))?;
    let leaf = qcore::json::from_hex(leaf_hex).map_err(PyValueError::new_err)?;
    let steps = parse_steps(steps_json).map_err(PyValueError::new_err)?;
    Ok(qcore::finality::verify_event(&root, &leaf, &steps))
}

#[pyfunction]
pub fn verify_transaction(
    transaction_root_hex: &str,
    tx_id: &str,
    leaf_hex: &str,
    steps_json: &str,
) -> PyResult<bool> {
    let root: [u8; 32] = qcore::json::from_hex(transaction_root_hex)
        .map_err(PyValueError::new_err)?
        .try_into()
        .map_err(|_| PyValueError::new_err("the transaction root is 32 bytes of hex"))?;
    let leaf = qcore::json::from_hex(leaf_hex).map_err(PyValueError::new_err)?;
    let steps = parse_steps(steps_json).map_err(PyValueError::new_err)?;
    Ok(qcore::finality::verify_transaction(
        &root, tx_id, &leaf, &steps,
    ))
}

#[pyfunction]
pub fn decode_event(leaf_hex: &str) -> PyResult<String> {
    let leaf = qcore::json::from_hex(leaf_hex).map_err(PyValueError::new_err)?;
    let event = qcore::finality::decode_event(&leaf).map_err(PyValueError::new_err)?;
    Ok(qcore::json::object(vec![
        ("contract", qcore::json::Json::str(event.contract)),
        (
            "selector",
            qcore::json::Json::str(qcore::json::to_hex(&event.selector)),
        ),
        (
            "data",
            qcore::json::Json::str(qcore::json::to_hex(&event.data)),
        ),
    ])
    .render())
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(address, m)?)?;
    m.add_function(wrap_pyfunction!(valid_address, m)?)?;
    m.add_function(wrap_pyfunction!(same_address, m)?)?;
    m.add_function(wrap_pyfunction!(lookalike_of, m)?)?;
    m.add_function(wrap_pyfunction!(mnemonic_from_seed, m)?)?;
    m.add_function(wrap_pyfunction!(mnemonic_from_seed_text, m)?)?;
    m.add_function(wrap_pyfunction!(genesis_secs, m)?)?;
    m.add_function(wrap_pyfunction!(head_ceiling, m)?)?;
    m.add_function(wrap_pyfunction!(bounded_valid_until, m)?)?;
    m.add_function(wrap_pyfunction!(check_gateway_json, m)?)?;
    m.add_function(wrap_pyfunction!(check_endpoint, m)?)?;
    m.add_function(wrap_pyfunction!(testnet_rpc_url, m)?)?;
    m.add_function(wrap_pyfunction!(testnet_chain_name, m)?)?;
    m.add_function(wrap_pyfunction!(gateway_protocol, m)?)?;
    m.add_function(wrap_pyfunction!(roster_commitment, m)?)?;
    m.add_function(wrap_pyfunction!(verify_next_roster, m)?)?;
    m.add_function(wrap_pyfunction!(verify_account, m)?)?;
    m.add_function(wrap_pyfunction!(testnet_roster_commitment, m)?)?;
    m.add_function(wrap_pyfunction!(mainnet_roster_commitment, m)?)?;
    m.add_function(wrap_pyfunction!(testnet_genesis_hash, m)?)?;
    m.add_function(wrap_pyfunction!(mainnet_genesis_hash, m)?)?;
    m.add_function(wrap_pyfunction!(validity_blocks, m)?)?;
    m.add_class::<SigningSession>()?;
    m.add_function(wrap_pyfunction!(order_signer, m)?)?;
    m.add_function(wrap_pyfunction!(vm_deploy_address, m)?)?;
    m.add_function(wrap_pyfunction!(contract_address, m)?)?;
    m.add_function(wrap_pyfunction!(nonce_slot_key, m)?)?;
    m.add_function(wrap_pyfunction!(scalar_slot_key, m)?)?;
    m.add_function(wrap_pyfunction!(map_slot_key, m)?)?;
    m.add_function(wrap_pyfunction!(map_addr_word_key, m)?)?;
    m.add_function(wrap_pyfunction!(name_key, m)?)?;
    m.add_function(wrap_pyfunction!(token_decimals_slot, m)?)?;
    m.add_function(wrap_pyfunction!(token_symbol_slot, m)?)?;
    m.add_function(wrap_pyfunction!(pack_symbol, m)?)?;
    m.add_function(wrap_pyfunction!(unpack_symbol, m)?)?;
    m.add_function(wrap_pyfunction!(storage_body, m)?)?;
    m.add_function(wrap_pyfunction!(events_body, m)?)?;
    m.add_function(wrap_pyfunction!(asset_balance_body, m)?)?;
    m.add_function(wrap_pyfunction!(asset_supply_body, m)?)?;
    m.add_function(wrap_pyfunction!(storage_value, m)?)?;
    m.add_function(wrap_pyfunction!(storage_value_reported, m)?)?;
    m.add_function(wrap_pyfunction!(check_order_expiry, m)?)?;
    m.add_function(wrap_pyfunction!(parse_events, m)?)?;
    m.add_function(wrap_pyfunction!(seed_from_mnemonic, m)?)?;
    m.add_function(wrap_pyfunction!(sign_transfer, m)?)?;
    m.add_function(wrap_pyfunction!(sign_call, m)?)?;
    m.add_function(wrap_pyfunction!(sign_payable_call, m)?)?;
    m.add_function(wrap_pyfunction!(sign_asset_call, m)?)?;
    m.add_function(wrap_pyfunction!(sign_register, m)?)?;
    m.add_function(wrap_pyfunction!(build_typed_order_call, m)?)?;
    m.add_function(wrap_pyfunction!(order_layout_hash, m)?)?;
    m.add_function(wrap_pyfunction!(verify_finality, m)?)?;
    m.add_function(wrap_pyfunction!(verify_finality_in_epoch, m)?)?;
    m.add_function(wrap_pyfunction!(header_height, m)?)?;
    m.add_function(wrap_pyfunction!(transaction_kind, m)?)?;
    m.add_function(wrap_pyfunction!(index_fits_path, m)?)?;
    m.add_function(wrap_pyfunction!(testnet_epoch_length, m)?)?;
    m.add_function(wrap_pyfunction!(mainnet_epoch_length, m)?)?;
    m.add_function(wrap_pyfunction!(testnet_genesis_secs, m)?)?;
    m.add_function(wrap_pyfunction!(testnet_blocks_per_sec, m)?)?;
    m.add_function(wrap_pyfunction!(response_cap, m)?)?;
    m.add_function(wrap_pyfunction!(bounded_valid_until_for, m)?)?;
    m.add_function(wrap_pyfunction!(verify_event, m)?)?;
    m.add_function(wrap_pyfunction!(verify_transaction, m)?)?;
    m.add_function(wrap_pyfunction!(decode_event, m)?)?;
    m.add_function(wrap_pyfunction!(vm_call_fee, m)?)?;
    m.add_function(wrap_pyfunction!(deploy_fee_quon, m)?)?;
    m.add_function(wrap_pyfunction!(check_valid_until, m)?)?;
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
