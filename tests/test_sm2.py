"""SM2 公开 API 测试。

## 契约（冻结，见设计 §4.1 / §7）

- 密文：**裸 C1C3C2** = ``x(32) ‖ y(32) ‖ C3(32) ‖ C2(n)``，长度 ``96 + n``，首字节 ≠ 0x30
- 签名：**裸 r‖s** = 64 字节，首字节 ≠ 0x30
- 公钥：接受 128（无 04 前缀）与 130（含 04 前缀）字符两种输入
- 解密：不做「首字节是 0x04 就剥离」的启发式，而是**两候选逐个试解**

下面的 GOLDEN_* 常量逐字复制自
``fastapiadmin/backend/tests/core/test_sm_crypto.py``（2026-09 快照），
用于证明存量密文/签名在新库上依然可用。
"""

import pytest

import gmssl_fast

GOLDEN_SM2_PRIV = "fef1cd14d44d8a57afa854312a2fb11155638a9d6444d8a35db0e75cf4949246"
GOLDEN_SM2_PUB = (
    "046574bf3f968a9fc217ce48f65543c64be1a6a8dc8325ffed3125e425fb09626"
    "b3996ca6e16bc109c3e43a1133a2c16485f4f67dd0d8dded6b837f4e9dca2ea21"
)
GOLDEN_SM2_MSG = "fastapiadmin-国密契约"
GOLDEN_SM2_CT = bytes.fromhex(
    "5e2ad5aa14c202bcb8653d1edcb4c13a89a7c959a50d6056679ccc8229b69ce0"
    "4cd1df4597e9bdfb05007785a514af83a70f09a66767784522b18da00fe9a75a"
    "f2262f8d9d6b18a303953eb121947f8540dbeef01003e6dc09f9aa6850929245"
    "a6b8b306e770b524180f61aebfb1e2c151918747d7a401c8a6"
)
GOLDEN_SM2_SIG = bytes.fromhex(
    "6512c757cb3e105aac6e6d9ca66f9d9b9badaba2eb45ec04768df6be2ed37e0e"
    "45619e22909951cc909fbe8e5ca2acc47b22a44b35e99856e8e4f3daf947e6ce"
)
# 首字节恰为 0x04 的**合法裸**密文：x 坐标首字节本身就是 0x04。
# 用于锁定「按首字节剥离 04 前缀」这个启发式的回归（会把真正的 x 首字节吃掉）。
GOLDEN_SM2_CT_LEADING_04 = bytes.fromhex(
    "044a6aab51879c22a823c7e9c305978679fbe222f37f8492c25b61fd295e7621"
    "0274dadbe2d1585ab5266e54661c02fd5f839e90b1f74e16ff7c369059417052"
    "d7d3498ea4527a2ccb9772694461a9c1778df1948e9f95b27af0942997c58446"
    "d5ca11a5bcfcbc29b4a7ffe4483cc3373f5928198b3bd9b0e0"
)


def test_golden_ciphertext_is_raw_c1c3c2() -> None:
    msg = GOLDEN_SM2_MSG.encode("utf-8")
    assert len(GOLDEN_SM2_CT) == 96 + len(msg)
    assert GOLDEN_SM2_CT[0] != 0x30  # 0x30 说明被 ASN.1 包装


def test_encrypt_produces_raw_c1c3c2() -> None:
    sm2 = gmssl_fast.SM2(public_key=GOLDEN_SM2_PUB)
    msg = GOLDEN_SM2_MSG.encode("utf-8")
    ct = sm2.encrypt(msg)
    assert len(ct) == 96 + len(msg)
    assert ct[0] != 0x30


def test_decrypts_golden_ciphertext() -> None:
    sm2 = gmssl_fast.SM2(private_key=GOLDEN_SM2_PRIV, public_key=GOLDEN_SM2_PUB)
    assert sm2.decrypt(GOLDEN_SM2_CT).decode("utf-8") == GOLDEN_SM2_MSG


def test_decrypts_golden_ciphertext_whose_x_starts_with_0x04() -> None:
    assert GOLDEN_SM2_CT_LEADING_04[:1] == b"\x04"  # 样本前提
    sm2 = gmssl_fast.SM2(private_key=GOLDEN_SM2_PRIV, public_key=GOLDEN_SM2_PUB)
    assert sm2.decrypt(GOLDEN_SM2_CT_LEADING_04).decode("utf-8") == GOLDEN_SM2_MSG


def test_decrypts_ciphertext_with_leading_04_prefix() -> None:
    # Flutter gm_crypto 会在 C1 前多加一个 04 前缀
    sm2 = gmssl_fast.SM2(private_key=GOLDEN_SM2_PRIV, public_key=GOLDEN_SM2_PUB)
    assert sm2.decrypt(b"\x04" + GOLDEN_SM2_CT).decode("utf-8") == GOLDEN_SM2_MSG


def test_verifies_golden_signature() -> None:
    sm2 = gmssl_fast.SM2(public_key=GOLDEN_SM2_PUB)
    assert sm2.verify(GOLDEN_SM2_MSG.encode("utf-8"), GOLDEN_SM2_SIG) is True


def test_golden_signature_is_raw_rs() -> None:
    assert len(GOLDEN_SM2_SIG) == 64
    assert GOLDEN_SM2_SIG[0] != 0x30


def test_sign_produces_raw_rs_and_verifies() -> None:
    sm2 = gmssl_fast.SM2(private_key=GOLDEN_SM2_PRIV, public_key=GOLDEN_SM2_PUB)
    msg = GOLDEN_SM2_MSG.encode("utf-8")
    sig = sm2.sign(msg)
    assert len(sig) == 64
    assert sig[0] != 0x30
    assert sm2.verify(msg, sig) is True
    assert sm2.verify(b"other", sig) is False
    tampered = bytearray(sig)
    tampered[10] ^= 1
    assert sm2.verify(msg, bytes(tampered)) is False
    # 用 golden 私钥签出的新签名，公钥必须认得
    assert gmssl_fast.SM2(public_key=GOLDEN_SM2_PUB).verify(msg, sig) is True


def test_generate_then_roundtrip() -> None:
    sm2 = gmssl_fast.SM2.generate()
    assert len(sm2.private_key_hex) == 64
    assert len(sm2.public_key_hex) == 130
    assert sm2.public_key_hex.startswith("04")

    restored = gmssl_fast.SM2(
        private_key=sm2.private_key_hex, public_key=sm2.public_key_hex
    )
    msg = b"round-trip"
    assert restored.decrypt(restored.encrypt(msg)) == msg
    assert restored.verify(msg, restored.sign(msg)) is True


def test_public_key_accepts_128_and_130_chars() -> None:
    msg = b"x"
    assert gmssl_fast.SM2(public_key=GOLDEN_SM2_PUB).encrypt(msg)
    assert gmssl_fast.SM2(public_key=GOLDEN_SM2_PUB[2:]).encrypt(msg)


def test_rejects_plaintext_over_255_bytes() -> None:
    sm2 = gmssl_fast.SM2(public_key=GOLDEN_SM2_PUB)
    with pytest.raises(gmssl_fast.GmsslValueError):
        sm2.encrypt(bytes(256))
    assert len(sm2.encrypt(bytes(255))) == 96 + 255


def test_rejects_bad_key_length() -> None:
    with pytest.raises(ValueError):
        gmssl_fast.SM2(private_key="ab" * 31)  # 62 字符
    with pytest.raises(ValueError):
        gmssl_fast.SM2(public_key="ab" * 63)  # 126 字符
    with pytest.raises(ValueError):
        gmssl_fast.SM2(public_key="zz" * 64)  # 非十六进制


def test_private_key_requires_public_key() -> None:
    # GmSSL 的 PKCS#8 解析要求公钥字段，且无「由标量派生公钥」接口（已实测）
    with pytest.raises(ValueError):
        gmssl_fast.SM2(private_key=GOLDEN_SM2_PRIV)


def test_encrypt_requires_public_key() -> None:
    with pytest.raises(ValueError):
        gmssl_fast.SM2(private_key=GOLDEN_SM2_PRIV).encrypt(b"x")
