//! SM4 原语（CBC / CTR / GCM / ECB）。
//!
//! ## 安全门（不得放宽）
//!
//! - **GCM 的 tag 长度硬编码 16 字节**，绝不暴露给调用方：GmSSL 只校验 taglen 的
//!   上界（`sm4_modes.c`），随后仅 `memcmp` 前 `taglen` 个字节——若允许调用方传短
//!   tag，1 字节 tag 即可伪造（约 1/256），AEAD 完整性会被击穿。
//! - **GCM 的 nonce 强制 12 字节**：GmSSL 完全不校验 ivlen（实测 1/8/16 字节都放行），
//!   非 12 字节会导致 IV 复用与跨库不互通。
//!
//! ECB 上游没有封装，这里用块级原语自拼 PKCS7（纯安全 Rust）。

use gmssl_rs::{Sm4Cbc, Sm4Ctr, Sm4Gcm, Sm4Key};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::errors::{to_py_err, GmsslAuthError, GmsslValueError};

const BLOCK: usize = 16;
const GCM_TAG_LEN: usize = 16;
const GCM_NONCE_LEN: usize = 12;

fn key16(key: &[u8]) -> PyResult<[u8; BLOCK]> {
    key.try_into()
        .map_err(|_| GmsslValueError::new_err("SM4 密钥必须是 16 字节"))
}

fn block16(value: &[u8], what: &str) -> PyResult<[u8; BLOCK]> {
    value
        .try_into()
        .map_err(|_| GmsslValueError::new_err(format!("{what} 必须是 16 字节")))
}

fn pkcs7_pad(data: &[u8]) -> Vec<u8> {
    let pad = BLOCK - (data.len() % BLOCK);
    let mut out = Vec::with_capacity(data.len() + pad);
    out.extend_from_slice(data);
    out.resize(out.len() + pad, pad as u8);
    out
}

fn pkcs7_unpad(data: &[u8]) -> PyResult<&[u8]> {
    let n = data.len();
    if n == 0 || n % BLOCK != 0 {
        return Err(GmsslValueError::new_err(
            "密文长度不是 SM4 分组（16 字节）的整数倍",
        ));
    }
    let pad = data[n - 1] as usize;
    let valid = pad > 0
        && pad <= BLOCK
        && pad <= n
        && data[n - pad..].iter().all(|&byte| byte as usize == pad);
    if !valid {
        return Err(GmsslValueError::new_err("PKCS7 填充非法"));
    }
    Ok(&data[..n - pad])
}

/// SM4-CBC 加密（PKCS7 填充）。
#[pyfunction]
pub fn sm4_cbc_encrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let key = key16(key)?;
    let iv = block16(iv, "IV")?;
    let out = Sm4Cbc::encrypt(&key, &iv, plaintext).map_err(to_py_err)?;
    Ok(PyBytes::new(py, &out))
}

/// SM4-CBC 解密（校验并去除 PKCS7 填充）。
#[pyfunction]
pub fn sm4_cbc_decrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let key = key16(key)?;
    let iv = block16(iv, "IV")?;
    let out = Sm4Cbc::decrypt(&key, &iv, ciphertext).map_err(to_py_err)?;
    Ok(PyBytes::new(py, &out))
}

/// SM4-ECB 加密（PKCS7 填充；上游未封装，用块级原语自拼）。
#[pyfunction]
pub fn sm4_ecb_encrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    plaintext: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let key = Sm4Key::new(&key16(key)?);
    let padded = pkcs7_pad(plaintext);
    let mut out = Vec::with_capacity(padded.len());
    for chunk in padded.chunks_exact(BLOCK) {
        let mut block = [0u8; BLOCK];
        block.copy_from_slice(chunk);
        out.extend_from_slice(&key.encrypt_block(&block));
    }
    Ok(PyBytes::new(py, &out))
}

/// SM4-ECB 解密（校验并去除 PKCS7 填充）。
#[pyfunction]
pub fn sm4_ecb_decrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    ciphertext: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let key = Sm4Key::new(&key16(key)?);
    if ciphertext.is_empty() || ciphertext.len() % BLOCK != 0 {
        return Err(GmsslValueError::new_err(
            "密文长度不是 SM4 分组（16 字节）的整数倍",
        ));
    }
    let mut out = Vec::with_capacity(ciphertext.len());
    for chunk in ciphertext.chunks_exact(BLOCK) {
        let mut block = [0u8; BLOCK];
        block.copy_from_slice(chunk);
        out.extend_from_slice(&key.decrypt_block(&block));
    }
    Ok(PyBytes::new(py, pkcs7_unpad(&out)?))
}

/// SM4-CTR（加密与解密是同一操作）。
#[pyfunction]
pub fn sm4_ctr_xor<'py>(
    py: Python<'py>,
    key: &[u8],
    ctr: &[u8],
    data: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let key = key16(key)?;
    let ctr = block16(ctr, "CTR 初始值")?;
    let out = Sm4Ctr::encrypt(&key, &ctr, data).map_err(to_py_err)?;
    Ok(PyBytes::new(py, &out))
}

/// SM4-GCM 加密，返回 `(ciphertext, tag)`；**tag 固定 16 字节**。
#[pyfunction]
pub fn sm4_gcm_encrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let key = key16(key)?;
    if nonce.len() != GCM_NONCE_LEN {
        return Err(GmsslValueError::new_err("SM4-GCM 的 nonce 必须是 12 字节"));
    }
    let result = Sm4Gcm::encrypt(&key, nonce, aad, plaintext, GCM_TAG_LEN).map_err(to_py_err)?;
    Ok((
        PyBytes::new(py, &result.ciphertext),
        PyBytes::new(py, &result.tag),
    ))
}

/// SM4-GCM 解密；**tag 必须 16 字节**，校验失败抛 `GmsslAuthError`。
#[pyfunction]
pub fn sm4_gcm_decrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let key = key16(key)?;
    if nonce.len() != GCM_NONCE_LEN {
        return Err(GmsslValueError::new_err("SM4-GCM 的 nonce 必须是 12 字节"));
    }
    if tag.len() != GCM_TAG_LEN {
        return Err(GmsslValueError::new_err("SM4-GCM 的 tag 必须是 16 字节"));
    }
    // AEAD 语义：任何失败都等价于认证失败
    let out = Sm4Gcm::decrypt(&key, nonce, aad, tag, ciphertext)
        .map_err(|_| GmsslAuthError::new_err("SM4-GCM 完整性校验失败"))?;
    Ok(PyBytes::new(py, &out))
}
