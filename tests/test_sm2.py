"""SM2 公开 API 测试。

## 契约（冻结，见设计 §4.1 / §7）

- 密文：**裸 C1C3C2** = ``x(32) ‖ y(32) ‖ C3(32) ‖ C2(n)``，长度 ``96 + n``
- 签名：**裸 r‖s** = 64 字节
- 「没被 DER 包装」用**长度**判定（DER 至少多 10 字节）；
  ⚠️ **不要对随机数据判首字节 ≠ 0x30**：裸格式 x 坐标首字节本身可能就是 0x30
  （概率约 1/256），CI 上真因此假失败过；固定 Golden 向量判首字节则没问题
- 公钥：接受 128（无 04 前缀）与 130（含 04 前缀）字符两种输入
- 解密：不做「首字节是 0x04 就剥离」的启发式，而是**两候选逐个试解**

GOLDEN_* 常量集中定义在 ``tests/golden.py``（逐字复制自
``fastapiadmin/backend/tests/core/test_sm_crypto.py`` 的 2026-09 快照），
用于证明存量密文/签名在新库上依然可用。
"""

import pytest

import gmssl_fast
from golden import (
    GOLDEN_SM2_CT,
    GOLDEN_SM2_CT_LEADING_04,
    GOLDEN_SM2_MSG,
    GOLDEN_SM2_PRIV,
    GOLDEN_SM2_PUB,
    GOLDEN_SM2_SIG,
)


def test_golden_ciphertext_is_raw_c1c3c2() -> None:
    msg = GOLDEN_SM2_MSG.encode("utf-8")
    assert len(GOLDEN_SM2_CT) == 96 + len(msg)
    assert GOLDEN_SM2_CT[0] != 0x30  # 0x30 说明被 ASN.1 包装


def test_encrypt_produces_raw_c1c3c2() -> None:
    sm2 = gmssl_fast.SM2(public_key=GOLDEN_SM2_PUB)
    msg = GOLDEN_SM2_MSG.encode("utf-8")
    ct = sm2.encrypt(msg)
    # 长度是确定性的「未包装」判据（DER 会多出 10 字节以上）
    assert len(ct) == 96 + len(msg)


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
    # DER 签名为 70～72 字节，长度即可确定性地区分裸 r‖s
    assert len(sig) == 64
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


# ---------------------------------------------------------------- 密钥句柄（性能路径）
def test_key_handle_matches_free_functions() -> None:
    """缓存句柄（快路径）必须与「每次重新解析密钥」的自由函数语义完全等价。"""
    core = gmssl_fast._core  # noqa: SLF001 - 正是要验证这层内部实现
    msg = GOLDEN_SM2_MSG.encode("utf-8")
    handle = core.Sm2KeyHandle(GOLDEN_SM2_PRIV, GOLDEN_SM2_PUB)

    # 签名：双向互认
    from_handle = handle.sign(msg)
    assert len(from_handle) == 64
    assert core.sm2_verify_raw(GOLDEN_SM2_PUB, msg, from_handle) is True
    assert handle.verify(msg, core.sm2_sign_raw(GOLDEN_SM2_PRIV, GOLDEN_SM2_PUB, msg)) is True

    # 加解密：双向互通
    assert core.sm2_decrypt_raw(GOLDEN_SM2_PRIV, GOLDEN_SM2_PUB, handle.encrypt(msg)) == msg
    assert handle.decrypt(core.sm2_encrypt_raw(GOLDEN_SM2_PUB, msg)) == msg

    # 两候选试解在句柄里同样生效（老实现的 04 前缀 + 首字节本身就是 0x04 的合法密文）
    assert handle.decrypt(b"\x04" + GOLDEN_SM2_CT) == msg
    assert handle.decrypt(GOLDEN_SM2_CT_LEADING_04) == msg


def test_key_handle_needs_a_key_and_private_ops_need_private() -> None:
    core = gmssl_fast._core  # noqa: SLF001
    with pytest.raises(ValueError, match="至少需要私钥或公钥"):
        core.Sm2KeyHandle()

    public_only = core.Sm2KeyHandle(None, GOLDEN_SM2_PUB)
    assert public_only.encrypt(b"x")  # 公钥操作可用
    with pytest.raises(ValueError, match="只有公钥"):
        public_only.sign(b"x")
    with pytest.raises(ValueError, match="只有公钥"):
        public_only.decrypt(GOLDEN_SM2_CT)


def test_sm2_object_builds_the_handle_once() -> None:
    """优化契约：同一个 SM2 实例只解析密钥一次（签名吞吐 1395 → ~2500 ops/s 的来源）。"""
    sm2 = gmssl_fast.SM2(private_key=GOLDEN_SM2_PRIV, public_key=GOLDEN_SM2_PUB)
    assert sm2._key() is sm2._key()  # noqa: SLF001
    assert len(sm2.encrypt(bytes(255))) == 96 + 255


def test_rejects_bad_key_length() -> None:
    with pytest.raises(ValueError):
        gmssl_fast.SM2(private_key="ab" * 31)  # 62 字符
    with pytest.raises(ValueError):
        gmssl_fast.SM2(public_key="ab" * 63)  # 126 字符
    with pytest.raises(ValueError):
        gmssl_fast.SM2(public_key="zz" * 64)  # 非十六进制


def test_private_key_only_derives_public_key() -> None:
    """只给私钥时由 d·G 派生公钥（GmSSL 的 PKCS#8 解析要求公钥字段，缺字段会直接报错）。"""
    sm2 = gmssl_fast.SM2(private_key=GOLDEN_SM2_PRIV)

    # 派生结果必须就是 golden 公钥：存量密文的两种前缀形态与存量签名都要能过
    assert sm2.decrypt(GOLDEN_SM2_CT).decode() == GOLDEN_SM2_MSG
    assert sm2.decrypt(b"\x04" + GOLDEN_SM2_CT).decode() == GOLDEN_SM2_MSG
    assert sm2.decrypt(GOLDEN_SM2_CT_LEADING_04).decode() == GOLDEN_SM2_MSG
    assert sm2.verify(GOLDEN_SM2_MSG.encode(), GOLDEN_SM2_SIG) is True


def test_private_key_only_can_encrypt_and_sign() -> None:
    """只给私钥也能加密/签名（内部是同一把密钥，派生出的公钥参与运算）。"""
    sm2 = gmssl_fast.SM2(private_key=GOLDEN_SM2_PRIV)
    assert sm2.decrypt(sm2.encrypt(b"only-private")) == b"only-private"
    assert sm2.verify(b"only-private", sm2.sign(b"only-private")) is True


def test_explicit_public_key_must_match_private_key() -> None:
    """显式给错公钥必须报错（GmSSL 会校验 [1] 字段与标量匹配），而不是静默算错。"""
    other = gmssl_fast.SM2.generate()
    with pytest.raises(Exception):
        gmssl_fast.SM2(
            private_key=GOLDEN_SM2_PRIV, public_key=other.public_key_hex
        ).sign(b"x")
