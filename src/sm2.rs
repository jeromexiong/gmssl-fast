//! SM2 原语。
//!
//! 对外**只使用裸格式**（密文裸 C1C3C2、签名裸 r‖s）；DER 由 [`crate::sm2_fmt`] 在内部转换。
//!
//! 密钥导入导出走 PKCS#8 / SPKI DER：`gmssl-rs` 没有暴露「直接导入裸标量 / 裸公钥点」
//! 的接口（`gmssl-rs-sys` 未包含 `sm2_private_key_from_der` 等），所以由本层按 GmSSL
//! 的 DER 模板构造（模板见测试 `dump_der_templates`）。
//!
//! **只给私钥时**：GmSSL 的 PKCS#8 解析要求 `[1]` 公钥字段存在（实测缺字段会
//! `DER decoding failed`），所以本层先用 GmSSL 的 `sm2_point_mul_generator` 算出
//! `d·G`（见 [`point_from_scalar`]）再构造 DER —— 调用方因此可以只提供私钥。
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
/// 明文上限：GmSSL 的 `SM2_CIPHERTEXT` 用固定缓冲（`uint8_t ciphertext[255]`，见 `sm2.h`）。
/// ⚠️ 这是 **GmSSL API 的限制**，不是裸 C1C3C2 格式的限制（纯 Python 实现如 pysmx 不受限）。
const MAX_PLAINTEXT_BYTES: usize = 255;

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

/// GmSSL 的 `SM2_POINT`（`sm2.h`）：`typedef struct { uint8_t x[32]; uint8_t y[32]; }`。
///
/// 只当不透明缓冲区传给 C（从不读字段），尺寸与头文件一致（64 字节）。
#[repr(C)]
struct Sm2Point {
    x: [u8; 32],
    y: [u8; 32],
}

// GmSSL 的 EC 原语（实现在 `sm2_alg.c`，随静态库链接进来；`gmssl-rs` 未暴露它们）。
// 「由标量派生公钥」是「只给私钥」时构造 PKCS#8 的必要步骤，故在此直接声明。
// 两个函数都不依赖一次性初始化（`sm2_point_mul_generator` 内部自行准备）。
extern "C" {
    fn sm2_point_mul_generator(r: *mut Sm2Point, k: *const u8) -> std::ffi::c_int;
    fn sm2_point_to_uncompressed_octets(p: *const Sm2Point, out: *mut u8);
}

/// 由私钥标量派生公钥点（`d·G`），返回 `04‖X‖Y`（65 字节）。
///
/// 用于「只给了私钥」的场景：GmSSL 的 PKCS#8 解析要求公钥字段存在，而我们无法从
/// `sm2_private_key_info_from_der` 得到省略字段时的派生行为（实测直接报错）。
pub(crate) fn point_from_scalar(
    scalar: &[u8; SCALAR_BYTES],
) -> Result<[u8; POINT_BYTES], GmsslError> {
    let mut point = Sm2Point {
        x: [0; 32],
        y: [0; 32],
    };
    let mut octets = [0u8; POINT_BYTES];
    unsafe {
        if sm2_point_mul_generator(&mut point, scalar.as_ptr()) != 1 {
            return Err(invalid("SM2 私钥无效：无法由标量派生公钥"));
        }
        sm2_point_to_uncompressed_octets(&point, octets.as_mut_ptr());
    }
    if octets[0] != 0x04 {
        return Err(invalid("SM2 私钥无效：派生出的公钥不是合法点"));
    }
    Ok(octets)
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

/// 加密（已解析的密钥）——供句柄复用，省掉每次调用的 SPKI 解析。
pub(crate) fn encrypt_with_key(key: &Sm2Key, data: &[u8]) -> Result<Vec<u8>, GmsslError> {
    // 在这里显式拦下超长明文：否则 GmSSL 只会报一句无从下手的 "sm2_encrypt"。
    if data.len() > MAX_PLAINTEXT_BYTES {
        return Err(invalid(
            "SM2 明文上限 255 字节（GmSSL 的 SM2_CIPHERTEXT 固定缓冲，非裸格式限制）",
        ));
    }
    let der = gmssl_rs::sm2::sm2_encrypt(key, data)?;
    sm2_fmt::ct_der_to_raw(&der)
}

/// 解密（已解析的密钥）；两候选试解的逻辑见上。
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

/// 签名（已解析的密钥）。
pub(crate) fn sign_with_key(key: &Sm2Key, data: &[u8]) -> Result<Vec<u8>, GmsslError> {
    let der = Sm2Signer::sign(key, None, data)?;
    sm2_fmt::sig_der_to_raw(&der).map(|raw| raw.to_vec())
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
        let has_private = scalar.is_some();
        let key = match scalar {
            Some(scalar) => {
                // 只给私钥时由标量派生（GmSSL 的 PKCS#8 解析要求 `[1]` 公钥字段存在）。
                let point = match point {
                    Some(point) => point,
                    None => point_from_scalar(&scalar).map_err(to_py_err)?,
                };
                scalar_key(&scalar, Some(&point)).map_err(to_py_err)?
            }
            None => match point {
                Some(point) => point_key(&point).map_err(to_py_err)?,
                None => {
                    return Err(GmsslValueError::new_err("SM2 密钥句柄至少需要私钥或公钥"));
                }
            },
        };
        Ok(Self { key, has_private })
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
        // 实测：GmSSL 的 PKCS#8 解析**要求** [1] 公钥字段存在（否则 DER decoding failed）。
        // 这正是本层需要在缺公钥时先派生 `d·G`（见 `derives_public_key_from_scalar`）的原因。
        let err = scalar_key(&golden_scalar(), None)
            .expect_err("GmSSL 竟然接受了不带公钥的 PKCS#8，请更新本测试与 Python 侧校验");
        let message = format!("{err}");
        assert!(
            message.contains("DER decoding failed"),
            "实际错误：{message}"
        );
    }

    #[test]
    fn derives_public_key_from_scalar() {
        // d·G 必须与 golden 密钥对的公钥逐字节一致（决定「只给私钥」的正确性）。
        let point = point_from_scalar(&golden_scalar()).unwrap();
        assert_eq!(to_hex(&point), GOLDEN_POINT);
    }

    #[test]
    fn private_key_only_can_encrypt_decrypt_and_sign() {
        // 只给私钥：派生公钥 → 自洽的密钥 → 加解密与签名验签全通。
        let key = private_key(GOLDEN_SCALAR, None).unwrap();
        assert_eq!(to_hex(&key_point(&key).unwrap()), GOLDEN_POINT);

        let message = b"private-key-only";
        let der = gmssl_rs::sm2::sm2_encrypt(&key, message).unwrap();
        let raw = sm2_fmt::ct_der_to_raw(&der).unwrap();
        assert_eq!(decrypt_with_key(&key, &raw).unwrap(), message);

        let signature = sign_with_key(&key, message).unwrap();
        assert!(verify_with_key(&key, message, &signature).unwrap());
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

    #[test]
    fn plaintext_limit_is_255_bytes_with_clear_error() {
        // GmSSL 的 `SM2_CIPHERTEXT` 用固定 255 字节缓冲（`sm2.h`），所以明文上限是 255。
        // ⚠️ 这是 **GmSSL API 的限制**，不是裸 C1C3C2 格式的限制（pysmx 等纯 Python
        //    实现不受此限；fastapiadmin 的契约测试里那条 512 字节用例因此改为「已知限制」）。
        let point = parse_point(GOLDEN_POINT).unwrap();
        let public_key = point_key(&point).unwrap();
        let private_key = scalar_key(&golden_scalar(), Some(&point)).unwrap();

        // 边界内（255）必须可用
        let message = vec![0x5au8; MAX_PLAINTEXT_BYTES];
        let der = gmssl_rs::sm2::sm2_encrypt(&public_key, &message).unwrap();
        let raw = sm2_fmt::ct_der_to_raw(&der).unwrap();
        assert_eq!(raw.len(), 96 + message.len());
        assert_eq!(decrypt_with_key(&private_key, &raw).unwrap(), message);

        // 越界必须给出可读原因，而不是 GmSSL 的 "sm2_encrypt"
        let err = encrypt_with_key(&public_key, &vec![0u8; MAX_PLAINTEXT_BYTES + 1]).unwrap_err();
        let message = format!("{err}");
        assert!(message.contains("255 字节"), "实际错误：{message}");
    }
}
