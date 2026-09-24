//! `GmsslError` → Python 异常的**唯一映射点**。
//!
//! 异常层次：
//! - `GmsslError(Exception)`：库错误基类（校验失败/验签失败等）
//! - `GmsslValueError(ValueError)`：参数非法。**是内建 `ValueError` 的子类**，
//!   以保证 `except ValueError` 仍然生效（消费方兼容）。
//! - `GmsslAuthError(GmsslError)`：GCM 完整性校验失败
//! - `GmsslVerificationError(GmsslError)`：签名校验失败

use gmssl_rs::GmsslError as LibError;
use pyo3::PyErr;

pyo3::create_exception!(_core, GmsslError, pyo3::exceptions::PyException);
pyo3::create_exception!(_core, GmsslValueError, pyo3::exceptions::PyValueError);
pyo3::create_exception!(_core, GmsslAuthError, GmsslError);
pyo3::create_exception!(_core, GmsslVerificationError, GmsslError);

/// 把上游错误翻译成 Python 异常。
///
/// 注意：上游 `GmsslError` 的变体很粗（`LibraryError(&'static str)` 只带一个
/// 调用点名字），拿不到更细的原因码，因此消息会比较泛化——这是上游的限制。
pub fn to_py_err(e: LibError) -> PyErr {
    match e {
        LibError::InvalidKey(msg) | LibError::InvalidInput(msg) => GmsslValueError::new_err(msg),
        LibError::VerificationFailed => GmsslVerificationError::new_err("签名校验失败"),
        LibError::DecryptionFailed => GmsslAuthError::new_err("解密失败或完整性校验不通过"),
        LibError::LibraryError(ctx) => GmsslValueError::new_err(format!("GmSSL 库错误：{ctx}")),
        LibError::IoError(err) => GmsslError::new_err(err.to_string()),
    }
}
