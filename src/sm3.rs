//! SM3 原语。

use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// SM3 摘要，返回 32 字节。
#[pyfunction]
pub fn sm3<'py>(py: Python<'py>, data: &[u8]) -> Bound<'py, PyBytes> {
    PyBytes::new(py, &gmssl_rs::Sm3::digest(data))
}
