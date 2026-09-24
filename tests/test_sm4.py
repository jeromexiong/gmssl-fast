"""SM4 公开 API 测试。

标准向量：GM/T 0002-2012（SM4 分组密码算法）。

对外约定（与 fastapiadmin 既有实现一致）：
- ``SM4.encrypt()`` 返回 ``iv(16)‖ciphertext``；ECB 模式无 IV 前缀
- 使用 PKCS7 填充
"""

import pytest

import gmssl_fast

KEY = bytes.fromhex("0123456789abcdeffedcba9876543210")
# GM/T 0002 分组向量：key = plaintext = 0123456789abcdeffedcba9876543210
BLOCK_VECTOR = bytes.fromhex("681edf34d206965e86b3e94f536e4246")
PLAINTEXT = "hello 国密".encode("utf-8")


def test_ecb_matches_block_vector() -> None:
    # 16 字节输入被 PKCS7 填成 2 块，首块即分组向量
    assert gmssl_fast.SM4(KEY, mode="ecb").encrypt(KEY)[:16] == BLOCK_VECTOR


def test_cbc_with_zero_iv_first_block_equals_block_vector() -> None:
    # 全零 IV 下 CBC 首块 == ECB(明文块)，是与实现无关的已知答案
    blob = gmssl_fast.SM4(KEY, mode="cbc", iv=bytes(16)).encrypt(KEY)
    assert blob[16:32] == BLOCK_VECTOR


def test_cbc_roundtrip_and_iv_prefix() -> None:
    assert len(PLAINTEXT) == 12  # "hello " + 2 个汉字(3 字节各)
    blob = gmssl_fast.SM4(KEY).encrypt(PLAINTEXT)
    assert len(blob) == 16 + 16  # 16B IV + 一个 16B 填充块
    assert blob[:16] != bytes(16)
    assert gmssl_fast.SM4(KEY).decrypt(blob) == PLAINTEXT


def test_ctr_roundtrip_and_no_padding() -> None:
    sm4 = gmssl_fast.SM4(KEY, mode="ctr")
    blob = sm4.encrypt(b"hello")
    assert len(blob) == 16 + 5  # 流模式不填充
    assert sm4.decrypt(blob) == b"hello"


def test_cbc_rejects_non_block_aligned_ciphertext() -> None:
    blob = gmssl_fast.SM4(KEY).encrypt(b"x")
    with pytest.raises(gmssl_fast.GmsslValueError):
        gmssl_fast.SM4(KEY).decrypt(blob[:20])


def test_decrypt_rejects_too_short_input() -> None:
    with pytest.raises(ValueError):
        gmssl_fast.SM4(KEY).decrypt(b"\x00" * 16)


def test_gcm_roundtrip_and_rejects_tampering() -> None:
    gcm = gmssl_fast.SM4GCM(KEY, bytes(12))
    ct, tag = gcm.encrypt(b"secret", aad=b"hdr")
    assert len(ct) == len(b"secret")
    assert len(tag) == 16
    assert gcm.decrypt(ct, tag, aad=b"hdr") == b"secret"

    bad = bytearray(tag)
    bad[0] ^= 1
    with pytest.raises(gmssl_fast.GmsslAuthError):
        gcm.decrypt(ct, bytes(bad), aad=b"hdr")
    with pytest.raises(gmssl_fast.GmsslAuthError):
        gcm.decrypt(ct, tag, aad=b"other")


def test_gcm_rejects_wrong_nonce_length() -> None:
    # 上游不校验 ivlen（实测 1/8/16 字节都放行），库必须拦下
    with pytest.raises(ValueError):
        gmssl_fast.SM4GCM(KEY, bytes(1))
    with pytest.raises(ValueError):
        gmssl_fast.SM4GCM(KEY, bytes(16))


def test_gcm_rejects_wrong_tag_length() -> None:
    gcm = gmssl_fast.SM4GCM(KEY, bytes(12))
    ct, tag = gcm.encrypt(b"x")
    with pytest.raises(ValueError):
        gcm.decrypt(ct, tag[:8])


def test_rejects_wrong_key_length() -> None:
    with pytest.raises(ValueError):
        gmssl_fast.SM4(b"short")
