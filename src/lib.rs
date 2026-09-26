//! gmssl-fast 的 Rust 核心（Python 模块名 `gmssl_fast._core`）。
//!
//! 本层**只做算法原语与参数转换**，算法实现全部来自 `gmssl-rs`（静态链接的 GmSSL 3.1.1）。
//! 面向使用者的友好 API 与 drop-in 门面在 `python/gmssl_fast/` 下用 Python 实现。

mod errors;
mod sm2;
pub mod sm2_fmt;
mod sm3;
mod sm4;

use pyo3::prelude::*;

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sm2::sm2_generate, m)?)?;
    m.add_class::<sm2::Sm2KeyHandle>()?;

    m.add_function(wrap_pyfunction!(sm3::sm3, m)?)?;
    m.add_function(wrap_pyfunction!(sm3::sm3_hmac, m)?)?;
    m.add_function(wrap_pyfunction!(sm3::sm3_pbkdf2, m)?)?;

    m.add_function(wrap_pyfunction!(sm4::sm4_cbc_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(sm4::sm4_cbc_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(sm4::sm4_ecb_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(sm4::sm4_ecb_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(sm4::sm4_ctr_xor, m)?)?;
    m.add_function(wrap_pyfunction!(sm4::sm4_gcm_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(sm4::sm4_gcm_decrypt, m)?)?;

    let py = m.py();
    m.add("GmsslError", py.get_type::<errors::GmsslError>())?;
    m.add("GmsslValueError", py.get_type::<errors::GmsslValueError>())?;
    m.add("GmsslAuthError", py.get_type::<errors::GmsslAuthError>())?;
    m.add(
        "GmsslVerificationError",
        py.get_type::<errors::GmsslVerificationError>(),
    )?;
    Ok(())
}
