//! The Python binding for the Quantova client core.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

fn seed(seed_hex: &str) -> PyResult<[u8; 32]> {
    let bytes = qcore::json::from_hex(seed_hex).map_err(PyValueError::new_err)?;
    bytes
        .try_into()
        .map_err(|_| PyValueError::new_err("a seed is 32 bytes of hex"))
}

/// The address of the account derived from a master seed and an index.
#[pyfunction]
fn address(seed_hex: &str, index: u64) -> PyResult<String> {
    Ok(qcore::account_address(&seed(seed_hex)?, index))
}

/// Build and sign a native transfer. Returns a JSON string with the sender, the id, and
#[pyfunction]
fn sign_transfer(
    seed_hex: &str,
    index: u64,
    to: &str,
    amount: u64,
    nonce: u64,
    fee: u128,
) -> PyResult<String> {
    let signed = qcore::sign_transfer(&seed(seed_hex)?, index, to, amount, nonce, fee);
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

/// Build and sign a call to a target with its arguments already encoded as hex. A contract
#[pyfunction]
fn sign_call(
    seed_hex: &str,
    index: u64,
    target: &str,
    args_hex: &str,
    nonce: u64,
    meter_limit: u64,
    fee: u128,
) -> PyResult<String> {
    let args = qcore::json::from_hex(args_hex).map_err(PyValueError::new_err)?;
    let signed = qcore::sign_call(&seed(seed_hex)?, index, target, args, nonce, meter_limit, fee);
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

/// The request body for submit_transaction, from the transaction hex.
#[pyfunction]
fn submit_body(tx_hex: &str) -> PyResult<String> {
    let bytes = qcore::json::from_hex(tx_hex).map_err(PyValueError::new_err)?;
    Ok(qcore::submit_body(&bytes))
}

/// The request body for get_account.
#[pyfunction]
fn account_body(address: &str) -> String {
    qcore::account_body(address)
}

/// The request body for get_transaction.
#[pyfunction]
fn transaction_body(tx_id: &str) -> String {
    qcore::transaction_body(tx_id)
}

/// The request body for get_block by height.
#[pyfunction]
fn block_by_height_body(height: u64) -> String {
    qcore::block_by_height_body(height)
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(address, m)?)?;
    m.add_function(wrap_pyfunction!(sign_transfer, m)?)?;
    m.add_function(wrap_pyfunction!(sign_call, m)?)?;
    m.add_function(wrap_pyfunction!(submit_body, m)?)?;
    m.add_function(wrap_pyfunction!(account_body, m)?)?;
    m.add_function(wrap_pyfunction!(transaction_body, m)?)?;
    m.add_function(wrap_pyfunction!(block_by_height_body, m)?)?;
    Ok(())
}
