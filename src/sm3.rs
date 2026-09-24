//! SM3 原语。

use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// SM3 摘要，返回 32 字节。
#[pyfunction]
pub fn sm3<'py>(py: Python<'py>, data: &[u8]) -> Bound<'py, PyBytes> {
    PyBytes::new(py, &gmssl_rs::Sm3::digest(data))
}

/// HMAC-SM3，返回 32 字节。
#[pyfunction]
pub fn sm3_hmac<'py>(py: Python<'py>, key: &[u8], data: &[u8]) -> Bound<'py, PyBytes> {
    PyBytes::new(py, &gmssl_rs::Sm3Hmac::mac(key, data))
}

/// PBKDF2-HMAC-SM3 密钥派生。
///
/// GmSSL 约束：`salt` ≤ 64 字节、`iterations` ≥ 10000，违反时抛 `GmsslValueError`。
#[pyfunction]
pub fn sm3_pbkdf2<'py>(
    py: Python<'py>,
    password: &[u8],
    salt: &[u8],
    iterations: usize,
    dklen: usize,
) -> PyResult<Bound<'py, PyBytes>> {
    let mut out = vec![0u8; dklen];
    gmssl_rs::sm3::sm3_pbkdf2(password, salt, iterations, &mut out)
        .map_err(crate::errors::to_py_err)?;
    Ok(PyBytes::new(py, &out))
}
