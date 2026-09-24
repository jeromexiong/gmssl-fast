//! SM2 **裸格式** ↔ GmSSL **DER** 的编解码（内部使用，不暴露给 Python）。
//!
//! # 为什么需要这一层
//!
//! GmSSL 的 `sm2_encrypt` / `sm2_sign` 产出 ASN.1 DER：
//!
//! - 密文：`SEQUENCE { INTEGER x, INTEGER y, OCTET STRING C3(32), OCTET STRING C2(n) }`
//!   （`src/sm2_lib.c:695` `sm2_ciphertext_to_der`）
//! - 签名：`SEQUENCE { INTEGER r, INTEGER s }`
//!   （`src/sm2_lib.c:161` `sm2_signature_to_der`）
//!
//! 而前端（`sm-crypto` / `gm_crypto`）与既有存量数据用的是**裸格式**：
//!
//! - 密文：`x(32) ‖ y(32) ‖ C3(32) ‖ C2(n)`，长度 `96 + n`
//! - 签名：`r(32) ‖ s(32)`，64 字节
//!
//! `gmssl-rs-sys` **没有**暴露 `sm2_do_encrypt` / `sm2_ciphertext_to_der` /
//! `sm2_signature_to_der`（GmSSL C 层有，Rust 绑层没包），因此这里用**纯安全 Rust**
//! 手写 DER 编解码，不引入 unsafe、不依赖未暴露符号。
//!
//! # 必须处理好的 DER 细节
//!
//! - **INTEGER 前导 `0x00`**：x/y/r/s 首字节高位为 1 时 DER 会补一个 `0x00`，
//!   回读时必须去掉并左补零到 32 字节（DER 也允许冗余前导零，同样归一化）
//! - **长形式长度**：C2 最长 255 字节，DER 会用到 `0x81` / `0x82`
//! - 反向组装时对高位为 1 的值补 `0x00`，避免被解释成负数

use gmssl_rs::GmsslError;

type Result<T> = std::result::Result<T, GmsslError>;

const TAG_SEQUENCE: u8 = 0x30;
const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
/// 坐标 / r / s 的固定字节长度
const SCALAR_BYTES: usize = 32;
/// C3（SM3 摘要）固定 32 字节
const C3_BYTES: usize = 32;
/// 裸签名长度 `r‖s`
const RAW_SIG_BYTES: usize = SCALAR_BYTES * 2;
/// 裸密文最小长度 `x‖y‖C3`
const RAW_CT_MIN: usize = SCALAR_BYTES * 2 + C3_BYTES;

fn invalid(msg: &'static str) -> GmsslError {
    GmsslError::InvalidInput(msg)
}

// ------------------------------------------------------------------ DER 读取

/// 读取一个 TLV 并返回其内容（tag 必须匹配）。
fn read_tlv<'a>(input: &'a [u8], pos: &mut usize, tag: u8) -> Result<&'a [u8]> {
    let actual = *input.get(*pos).ok_or_else(|| invalid("DER 数据不完整"))?;
    if actual != tag {
        return Err(invalid("DER tag 不符合预期"));
    }
    *pos += 1;

    let len = read_len(input, pos)?;
    let end = (*pos)
        .checked_add(len)
        .ok_or_else(|| invalid("DER 长度溢出"))?;
    let body = input
        .get(*pos..end)
        .ok_or_else(|| invalid("DER 长度越界"))?;
    *pos = end;
    Ok(body)
}

/// 读取 DER 长度（短形式与 `0x81` / `0x82` 长形式）。
fn read_len(input: &[u8], pos: &mut usize) -> Result<usize> {
    let first = *input.get(*pos).ok_or_else(|| invalid("DER 长度缺失"))?;
    *pos += 1;
    if first < 0x80 {
        return Ok(first as usize);
    }

    let count = (first & 0x7f) as usize;
    if count == 0 || count > 4 {
        // 0x80 表示不定长，DER 不允许
        return Err(invalid("DER 长度编码不支持"));
    }
    let mut len = 0usize;
    for _ in 0..count {
        let byte = *input.get(*pos).ok_or_else(|| invalid("DER 长度不完整"))?;
        *pos += 1;
        len = (len << 8) | byte as usize;
    }
    Ok(len)
}

/// 读取一个 INTEGER，归一化为固定 `SCALAR_BYTES` 字节大端表示。
fn read_scalar(input: &[u8], pos: &mut usize) -> Result<[u8; SCALAR_BYTES]> {
    let body = read_tlv(input, pos, TAG_INTEGER)?;
    // ⚠️ 必须**先去前导零再判长度**：高位为 1 的值 DER 会补一个 0x00，
    // 合法的 32 字节标量在 DER 里是 33 字节。
    let body = trim_leading_zeros(body);
    if body.len() > SCALAR_BYTES {
        return Err(invalid("DER INTEGER 超过 32 字节"));
    }

    let mut out = [0u8; SCALAR_BYTES];
    if !body.is_empty() {
        out[SCALAR_BYTES - body.len()..].copy_from_slice(body);
    }
    Ok(out)
}

/// 去掉前导零（DER 最多允许一个，这里一并归一化）。
fn trim_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[start..]
}

// ------------------------------------------------------------------ DER 写入

fn write_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xff {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xff) as u8);
    }
}

/// 写入 INTEGER：首字节高位为 1 时补 `0x00`，否则会被解释成负数。
fn write_scalar(out: &mut Vec<u8>, value: &[u8]) {
    let trimmed = trim_leading_zeros(value);
    // 全零时 DER 表示为一个字节 0x00
    let body = if trimmed.is_empty() {
        &value[value.len() - 1..]
    } else {
        trimmed
    };
    let pad = body.first().is_some_and(|b| b & 0x80 != 0);

    out.push(TAG_INTEGER);
    write_len(out, body.len() + usize::from(pad));
    if pad {
        out.push(0x00);
    }
    out.extend_from_slice(body);
}

fn write_octet_string(out: &mut Vec<u8>, value: &[u8]) {
    out.push(TAG_OCTET_STRING);
    write_len(out, value.len());
    out.extend_from_slice(value);
}

fn write_sequence(out: &mut Vec<u8>, body: &[u8]) {
    out.push(TAG_SEQUENCE);
    write_len(out, body.len());
    out.extend_from_slice(body);
}

// ------------------------------------------------------------------ 对外接口

/// DER 签名（`SEQUENCE{INTEGER r, INTEGER s}`）→ 裸 `r‖s`（64 字节）。
pub fn sig_der_to_raw(der: &[u8]) -> Result<[u8; RAW_SIG_BYTES]> {
    let mut pos = 0;
    let seq = read_tlv(der, &mut pos, TAG_SEQUENCE)?;
    if pos != der.len() {
        return Err(invalid("DER 签名尾部有多余数据"));
    }

    let mut inner = 0;
    let r = read_scalar(seq, &mut inner)?;
    let s = read_scalar(seq, &mut inner)?;
    if inner != seq.len() {
        return Err(invalid("DER 签名结构不符合预期"));
    }

    let mut out = [0u8; RAW_SIG_BYTES];
    out[..SCALAR_BYTES].copy_from_slice(&r);
    out[SCALAR_BYTES..].copy_from_slice(&s);
    Ok(out)
}

/// 裸 `r‖s`（64 字节）→ DER 签名。
pub fn sig_raw_to_der(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() != RAW_SIG_BYTES {
        return Err(invalid("裸签名必须是 64 字节（r‖s）"));
    }

    let mut body = Vec::with_capacity(RAW_SIG_BYTES + 8);
    write_scalar(&mut body, &raw[..SCALAR_BYTES]);
    write_scalar(&mut body, &raw[SCALAR_BYTES..]);

    let mut out = Vec::with_capacity(body.len() + 4);
    write_sequence(&mut out, &body);
    Ok(out)
}

/// DER 密文（`SEQUENCE{INTEGER x, INTEGER y, OCTET STRING C3, OCTET STRING C2}`）
/// → 裸 `x‖y‖C3‖C2`（长度 `96 + n`）。
pub fn ct_der_to_raw(der: &[u8]) -> Result<Vec<u8>> {
    let mut pos = 0;
    let seq = read_tlv(der, &mut pos, TAG_SEQUENCE)?;
    if pos != der.len() {
        return Err(invalid("DER 密文尾部有多余数据"));
    }

    let mut inner = 0;
    let x = read_scalar(seq, &mut inner)?;
    let y = read_scalar(seq, &mut inner)?;
    let c3 = read_tlv(seq, &mut inner, TAG_OCTET_STRING)?;
    if c3.len() != C3_BYTES {
        return Err(invalid("DER 密文中的 C3 必须是 32 字节"));
    }
    let c2 = read_tlv(seq, &mut inner, TAG_OCTET_STRING)?;
    if c2.is_empty() {
        return Err(invalid("DER 密文中的 C2 不能为空"));
    }
    if inner != seq.len() {
        return Err(invalid("DER 密文结构不符合预期"));
    }

    let mut out = Vec::with_capacity(RAW_CT_MIN + c2.len());
    out.extend_from_slice(&x);
    out.extend_from_slice(&y);
    out.extend_from_slice(c3);
    out.extend_from_slice(c2);
    Ok(out)
}

/// 裸 `x‖y‖C3‖C2` → DER 密文。
pub fn ct_raw_to_der(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() < RAW_CT_MIN {
        return Err(invalid("裸密文至少 96 字节（x‖y‖C3）"));
    }
    let c2 = &raw[RAW_CT_MIN..];
    if c2.is_empty() {
        return Err(invalid("裸密文缺少 C2"));
    }

    let mut body = Vec::with_capacity(raw.len() + 12);
    write_scalar(&mut body, &raw[..SCALAR_BYTES]);
    write_scalar(&mut body, &raw[SCALAR_BYTES..SCALAR_BYTES * 2]);
    write_octet_string(&mut body, &raw[SCALAR_BYTES * 2..RAW_CT_MIN]);
    write_octet_string(&mut body, c2);

    let mut out = Vec::with_capacity(body.len() + 4);
    write_sequence(&mut out, &body);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个覆盖各类字节的 64 字节裸签名。
    fn sample_raw_sig() -> [u8; 64] {
        let mut raw = [0u8; 64];
        for (i, byte) in raw.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(7).wrapping_add(1);
        }
        raw
    }

    #[test]
    fn sig_roundtrip() {
        let raw = sample_raw_sig();
        let der = sig_raw_to_der(&raw).unwrap();
        assert_eq!(sig_der_to_raw(&der).unwrap(), raw);
    }

    #[test]
    fn sig_integer_with_leading_zero() {
        // r 首字节高位为 1 → DER INTEGER 必须补 0x00 前导，否则被当成负数
        let mut raw = [0u8; 64];
        raw[0] = 0xff;
        raw[63] = 0x01;

        let der = sig_raw_to_der(&raw).unwrap();
        assert_eq!(der[0], 0x30); // SEQUENCE
        assert_eq!(der[2], 0x02); // INTEGER
        assert_eq!(der[3], 33); // 长度 = 32 + 1 个前导零
        assert_eq!(der[4], 0x00); // 前导零
        assert_eq!(der[5], 0xff);
        assert_eq!(sig_der_to_raw(&der).unwrap(), raw);
    }

    #[test]
    fn sig_rejects_wrong_length() {
        assert!(sig_raw_to_der(&[0u8; 63]).is_err());
        assert!(sig_raw_to_der(&[0u8; 65]).is_err());
    }

    #[test]
    fn ct_roundtrip_for_various_c2_lengths() {
        for c2_len in [1usize, 16, 127, 128, 200, 255] {
            let mut raw = vec![0x11u8; 96];
            raw.extend_from_slice(&vec![0x22u8; c2_len]);
            let der = ct_raw_to_der(&raw).unwrap();
            assert_eq!(der[0], 0x30, "C2 长度 {c2_len} 时首字节应为 SEQUENCE");
            assert_eq!(
                ct_der_to_raw(&der).unwrap(),
                raw,
                "C2 长度 {c2_len} 往返失败"
            );
        }
    }

    #[test]
    fn ct_handles_long_form_length() {
        // x 首字节 0x80（高位为 1）且 C2 = 200 字节，DER 里会同时出现前导零与长形式长度
        let mut raw = vec![0u8; 96];
        raw[0] = 0x80;
        raw.extend_from_slice(&[0x33u8; 200]);

        let der = ct_raw_to_der(&raw).unwrap();
        assert!(
            der.windows(2).any(|w| w[0] == 0x81 && w[1] == 200),
            "C2 的 OCTET STRING 应使用 0x81 长形式长度"
        );
        assert_eq!(ct_der_to_raw(&der).unwrap(), raw);
    }

    #[test]
    fn ct_rejects_too_short_raw() {
        assert!(ct_raw_to_der(&[0u8; 95]).is_err());
    }

    #[test]
    fn ct_rejects_malformed_der() {
        // 不是 SEQUENCE
        assert!(ct_der_to_raw(&[0x02, 0x01, 0x00]).is_err());
        // 长度声明越界
        assert!(ct_der_to_raw(&[0x30, 0x7f]).is_err());
        // INTEGER 超过 32 字节
        let mut oversized = vec![0x02, 0x21];
        oversized.extend_from_slice(&[0x01u8; 33]);
        let mut seq = vec![0x30];
        seq.push(oversized.len() as u8);
        seq.extend_from_slice(&oversized);
        assert!(ct_der_to_raw(&seq).is_err());
    }
}
