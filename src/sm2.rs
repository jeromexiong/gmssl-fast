//! SM2 原语。
//!
//! 对外**只使用裸格式**（密文裸 C1C3C2、签名裸 r‖s）；DER 由 [`crate::sm2_fmt`] 在内部转换。
//!
//! 密钥导入导出走 PKCS#8 / SPKI DER：`gmssl-rs` 没有暴露「直接导入裸标量 / 裸公钥点」
//! 的接口（`gmssl-rs-sys` 未包含 `sm2_private_key_from_der` 等），所以由本层按 GmSSL
//! 的 DER 模板构造（模板见测试 `dump_der_templates`）。
//!
//! **本模块的纯 Rust 核心函数不依赖 pyo3**（只有下面的 `#[pyfunction]` 是薄包装），
//! 因此 `cargo test` 可以直接验证算法与 DER 逻辑，无需 Python 解释器。

use gmssl_rs::{GmsslError, Sm2Key, Sm2Signer, Sm2Verifier};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::errors::to_py_err;
use crate::errors::GmsslValueError;
use crate::sm2_fmt;

const SCALAR_BYTES: usize = 32;
const POINT_BYTES: usize = 65;

fn invalid(msg: &'static str) -> GmsslError {
    GmsslError::InvalidInput(msg)
}

fn from_hex(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if text.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for chunk in text.as_bytes().chunks_exact(2) {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// 解析 32 字节私钥标量（64 个十六进制字符）。
pub(crate) fn parse_scalar(hex: &str) -> Result<[u8; SCALAR_BYTES], GmsslError> {
    let raw = from_hex(hex).ok_or_else(|| invalid("SM2 私钥不是合法十六进制"))?;
    raw.try_into()
        .map_err(|_| invalid("SM2 私钥必须是 64 个十六进制字符（32 字节标量）"))
}

/// 解析未压缩公钥点，接受 128（`X‖Y`）或 130（`04‖X‖Y`）字符。
pub(crate) fn parse_point(hex: &str) -> Result<[u8; POINT_BYTES], GmsslError> {
    let trimmed = hex.trim();
    let normalized = if trimmed.len() == 128 {
        format!("04{trimmed}")
    } else {
        trimmed.to_string()
    };
    let raw = from_hex(&normalized).ok_or_else(|| invalid("SM2 公钥不是合法十六进制"))?;
    let point: [u8; POINT_BYTES] = raw
        .try_into()
        .map_err(|_| invalid("SM2 公钥必须是 128 或 130 个十六进制字符（未压缩点）"))?;
    if point[0] != 0x04 {
        return Err(invalid("SM2 公钥必须以 04 开头（未压缩点）"));
    }
    Ok(point)
}

/// 由私钥标量构造密钥；`point` 为公钥点时会写入 PKCS#8 的 `[1]` 字段
/// （GmSSL 会校验其与标量是否匹配）。
pub(crate) fn scalar_key(
    scalar: &[u8; SCALAR_BYTES],
    point: Option<&[u8; POINT_BYTES]>,
) -> Result<Sm2Key, GmsslError> {
    let der = sm2_fmt::pkcs8_private_der(scalar, point);
    Sm2Key::from_private_key_der(&der)
}

/// 由公钥点构造密钥。
pub(crate) fn point_key(point: &[u8; POINT_BYTES]) -> Result<Sm2Key, GmsslError> {
    let der = sm2_fmt::spki_public_der(point);
    Sm2Key::from_public_key_der(&der)
}

/// 取出密钥的公钥点（`04‖X‖Y`）。
pub(crate) fn key_point(key: &Sm2Key) -> Result<[u8; POINT_BYTES], GmsslError> {
    let der = key.to_public_key_der()?;
    sm2_fmt::spki_point(&der)
}

/// 生成密钥对：`(private_key_hex, 130 字符公钥 hex)`。
pub(crate) fn generate() -> Result<(String, String), GmsslError> {
    let key = Sm2Key::generate()?;
    let private_der = key.to_private_key_der()?;
    let scalar = sm2_fmt::pkcs8_scalar(&private_der)?;
    Ok((to_hex(&scalar), to_hex(&key_point(&key)?)))
}

fn private_key(private_key_hex: &str, public_key_hex: Option<&str>) -> Result<Sm2Key, GmsslError> {
    let scalar = parse_scalar(private_key_hex)?;
    let point = public_key_hex.map(parse_point).transpose()?;
    scalar_key(&scalar, point.as_ref())
}

/// 加密，返回**裸 C1C3C2**；明文上限 255 字节。
pub(crate) fn encrypt_raw(public_key_hex: &str, data: &[u8]) -> Result<Vec<u8>, GmsslError> {
    encrypt_with_key(&point_key(&parse_point(public_key_hex)?)?, data)
}

/// 加密（已解析的密钥）——供句柄复用，省掉每次调用的 SPKI 解析。
pub(crate) fn encrypt_with_key(key: &Sm2Key, data: &[u8]) -> Result<Vec<u8>, GmsslError> {
    let der = gmssl_rs::sm2::sm2_encrypt(key, data)?;
    sm2_fmt::ct_der_to_raw(&der)
}

/// 解密裸 C1C3C2。
///
/// **两候选试解**：先按原样解，失败再剥掉首字节重试（部分前端会在 C1 前加 `04`
/// 非压缩前缀）。⚠️ 不做「首字节是 0x04 就剥离」的启发式——裸格式 x 坐标首字节
/// 本身就可能等于 0x04（约 1/256），那样会让合法密文随机解密失败。
pub(crate) fn decrypt_raw(
    private_key_hex: &str,
    public_key_hex: Option<&str>,
    ciphertext: &[u8],
) -> Result<Vec<u8>, GmsslError> {
    decrypt_with_key(&private_key(private_key_hex, public_key_hex)?, ciphertext)
}

/// 解密（已解析的密钥）；两候选试解的逻辑与 [`decrypt_raw`] 完全一致。
pub(crate) fn decrypt_with_key(key: &Sm2Key, ciphertext: &[u8]) -> Result<Vec<u8>, GmsslError> {
    let mut candidates: Vec<&[u8]> = vec![ciphertext];
    if ciphertext.first() == Some(&0x04) {
        candidates.push(&ciphertext[1..]);
    }

    let mut last_error = None;
    for candidate in candidates {
        match sm2_fmt::ct_raw_to_der(candidate) {
            Ok(der) => match gmssl_rs::sm2::sm2_decrypt(key, &der) {
                Ok(plain) => return Ok(plain),
                Err(err) => last_error = Some(err),
            },
            Err(err) => last_error = Some(err),
        }
    }
    Err(last_error.unwrap_or_else(|| invalid("SM2 密文长度不足")))
}

/// 签名，返回**裸 r‖s**（64 字节）。
pub(crate) fn sign_raw(
    private_key_hex: &str,
    public_key_hex: Option<&str>,
    data: &[u8],
) -> Result<Vec<u8>, GmsslError> {
    sign_with_key(&private_key(private_key_hex, public_key_hex)?, data)
}

/// 签名（已解析的密钥）。
pub(crate) fn sign_with_key(key: &Sm2Key, data: &[u8]) -> Result<Vec<u8>, GmsslError> {
    let der = Sm2Signer::sign(key, None, data)?;
    sm2_fmt::sig_der_to_raw(&der).map(|raw| raw.to_vec())
}

/// 校验裸 r‖s 签名。
pub(crate) fn verify_raw(
    public_key_hex: &str,
    data: &[u8],
    signature: &[u8],
) -> Result<bool, GmsslError> {
    verify_with_key(&point_key(&parse_point(public_key_hex)?)?, data, signature)
}

/// 校验裸 r‖s 签名（已解析的密钥）。
pub(crate) fn verify_with_key(
    key: &Sm2Key,
    data: &[u8],
    signature: &[u8],
) -> Result<bool, GmsslError> {
    let der = sm2_fmt::sig_raw_to_der(signature)?;
    Sm2Verifier::verify(key, None, data, &der)
}

// ------------------------------------------------------------------ pyo3 包装

/// 生成密钥对，返回 `(private_key_hex, public_key_hex)`。
#[pyfunction]
pub fn sm2_generate() -> PyResult<(String, String)> {
    generate().map_err(to_py_err)
}

/// SM2 加密，返回裸 C1C3C2。
#[pyfunction]
pub fn sm2_encrypt_raw<'py>(
    py: Python<'py>,
    public_key_hex: &str,
    data: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let raw = encrypt_raw(public_key_hex, data).map_err(to_py_err)?;
    Ok(PyBytes::new(py, &raw))
}

/// SM2 解密裸 C1C3C2（两候选试解）。
#[pyfunction]
pub fn sm2_decrypt_raw<'py>(
    py: Python<'py>,
    private_key_hex: &str,
    public_key_hex: Option<&str>,
    ciphertext: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let plain = decrypt_raw(private_key_hex, public_key_hex, ciphertext).map_err(to_py_err)?;
    Ok(PyBytes::new(py, &plain))
}

/// SM2 签名，返回裸 r‖s。
#[pyfunction]
pub fn sm2_sign_raw<'py>(
    py: Python<'py>,
    private_key_hex: &str,
    public_key_hex: Option<&str>,
    data: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let raw = sign_raw(private_key_hex, public_key_hex, data).map_err(to_py_err)?;
    Ok(PyBytes::new(py, &raw))
}

/// 校验裸 r‖s 签名。
#[pyfunction]
pub fn sm2_verify_raw(public_key_hex: &str, data: &[u8], signature: &[u8]) -> PyResult<bool> {
    verify_raw(public_key_hex, data, signature).map_err(to_py_err)
}

/// 已解析的 SM2 密钥句柄（**性能关键**）。
///
/// 存在的唯一理由：把 PKCS#8 / SPKI 的解析从「每次调用」挪到「构造一次」。
/// GmSSL 解析 PKCS#8 时会**校验 `[1]` 公钥字段与标量是否匹配**（一次额外的 EC 乘法），
/// 所以每次签名都重建私钥是纯浪费：实测签名吞吐 1395 → ~2500 ops/s
/// （复现：`python benches/bench.py`）。
///
/// Python 侧由 `gmssl_fast.SM2` 与 `gmssl_fast.compat` 各缓存一份，使用者无需接触本类型。
#[pyclass(module = "gmssl_fast._core", frozen)]
pub struct Sm2KeyHandle {
    key: Sm2Key,
    has_private: bool,
}

#[pymethods]
impl Sm2KeyHandle {
    #[new]
    #[pyo3(signature = (private_key_hex=None, public_key_hex=None))]
    fn new(private_key_hex: Option<&str>, public_key_hex: Option<&str>) -> PyResult<Self> {
        let scalar = private_key_hex
            .map(parse_scalar)
            .transpose()
            .map_err(to_py_err)?;
        let point = public_key_hex
            .map(parse_point)
            .transpose()
            .map_err(to_py_err)?;
        let key = match (&scalar, &point) {
            (Some(scalar), _) => scalar_key(scalar, point.as_ref()).map_err(to_py_err)?,
            (None, Some(point)) => point_key(point).map_err(to_py_err)?,
            (None, None) => return Err(GmsslValueError::new_err("SM2 密钥句柄至少需要私钥或公钥")),
        };
        Ok(Self {
            key,
            has_private: scalar.is_some(),
        })
    }

    /// 加密，返回裸 C1C3C2（只需公钥）。
    fn encrypt<'py>(&self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let raw = encrypt_with_key(&self.key, data).map_err(to_py_err)?;
        Ok(PyBytes::new(py, &raw))
    }

    /// 解密裸 C1C3C2（两候选试解）。
    fn decrypt<'py>(&self, py: Python<'py>, ciphertext: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        self.require_private()?;
        let plain = decrypt_with_key(&self.key, ciphertext).map_err(to_py_err)?;
        Ok(PyBytes::new(py, &plain))
    }

    /// 签名，返回裸 r‖s（64 字节）。
    fn sign<'py>(&self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        self.require_private()?;
        let raw = sign_with_key(&self.key, data).map_err(to_py_err)?;
        Ok(PyBytes::new(py, &raw))
    }

    /// 校验裸 r‖s 签名。
    fn verify(&self, data: &[u8], signature: &[u8]) -> PyResult<bool> {
        verify_with_key(&self.key, data, signature).map_err(to_py_err)
    }
}

impl Sm2KeyHandle {
    fn require_private(&self) -> PyResult<()> {
        if self.has_private {
            Ok(())
        } else {
            Err(GmsslValueError::new_err(
                "该 SM2 句柄只有公钥，不能做私钥操作（签名 / 解密）",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 逐字来自 fastapiadmin `tests/core/test_sm_crypto.py` 的 golden 密钥对。
    const GOLDEN_SCALAR: &str = "fef1cd14d44d8a57afa854312a2fb11155638a9d6444d8a35db0e75cf4949246";
    const GOLDEN_POINT: &str = "046574bf3f968a9fc217ce48f65543c64be1a6a8dc8325ffed3125e425fb09626\
b3996ca6e16bc109c3e43a1133a2c16485f4f67dd0d8dded6b837f4e9dca2ea21";

    fn golden_scalar() -> [u8; SCALAR_BYTES] {
        parse_scalar(GOLDEN_SCALAR).unwrap()
    }

    #[test]
    fn with_public_key_field_derives_matching_point() {
        let scalar = golden_scalar();
        let point = parse_point(GOLDEN_POINT).unwrap();
        let key = scalar_key(&scalar, Some(&point)).unwrap();
        assert_eq!(to_hex(&key_point(&key).unwrap()), GOLDEN_POINT);
    }

    #[test]
    fn without_public_key_field_is_rejected_by_gmssl() {
        // 实测：GmSSL 的 PKCS#8 解析**要求** [1] 公钥字段存在（否则 DER decoding failed），
        // 且没有暴露「由标量派生公钥」的接口。因此 Python 侧的私钥操作必须同时给出公钥。
        let err = scalar_key(&golden_scalar(), None)
            .expect_err("GmSSL 竟然接受了不带公钥的 PKCS#8，请更新本测试与 Python 侧校验");
        let message = format!("{err}");
        assert!(
            message.contains("DER decoding failed"),
            "实际错误：{message}"
        );
    }

    #[test]
    fn golden_public_key_roundtrips_through_spki() {
        let point = parse_point(GOLDEN_POINT).unwrap();
        let key = point_key(&point).unwrap();
        assert_eq!(to_hex(&key_point(&key).unwrap()), GOLDEN_POINT);
    }

    #[test]
    fn public_key_hex_accepts_128_and_130_chars() {
        assert_eq!(
            parse_point(GOLDEN_POINT).unwrap(),
            parse_point(&GOLDEN_POINT[2..]).unwrap()
        );
    }

    #[test]
    fn raw_ciphertext_matches_length_rule() {
        let point = parse_point(GOLDEN_POINT).unwrap();
        let key = point_key(&point).unwrap();
        let message = b"hello";
        let der = gmssl_rs::sm2::sm2_encrypt(&key, message).unwrap();
        let raw = sm2_fmt::ct_der_to_raw(&der).unwrap();
        assert_eq!(raw.len(), 96 + message.len());
        // 「没被 DER 包装」用长度判：DER 至少多出 SEQUENCE/INTEGER/OCTET STRING 的头与长度
        // （≥ 10 字节）——这是确定性判据。
        assert!(der.len() > raw.len());
        // ⚠️ **不要用首字节判**：裸格式 x 坐标首字节本身就是 0x30 的概率约 1/256，
        //    CI 上真因此假失败过（固定向量的首字节断言另说，见 tests/golden.py）。
    }

    /// 打印 GmSSL 自身产出的 DER 模板（手工构造 DER 的校准依据）。
    #[test]
    fn dump_der_templates() {
        let key = Sm2Key::generate().unwrap();
        println!("PRIV_DER={}", to_hex(&key.to_private_key_der().unwrap()));
        println!("PUB_DER={}", to_hex(&key.to_public_key_der().unwrap()));
    }
}
