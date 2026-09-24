"""compat 门面测试：调用形态必须与既有 ``Sm2Cipher`` / ``Sm3Cipher`` / ``Sm4Cipher`` 逐字对齐。

对齐依据：``fastapiadmin/backend/app/utils/sm_crypto_util.py`` 只用到了
``Sm2Cipher`` 的 4 个、``Sm3Cipher`` 的 4 个、``Sm4Cipher`` 的 4 个方法（已逐条核对源码）。
"""

import pytest

from gmssl_fast import compat
from golden import (
    GOLDEN_SM2_CT,
    GOLDEN_SM2_MSG,
    GOLDEN_SM2_PRIV,
    GOLDEN_SM2_PUB,
    GOLDEN_SM2_SIG,
    GOLDEN_SM4_KEY_HEX,
)


def test_sm2_call_shape_matches_legacy() -> None:
    msg = GOLDEN_SM2_MSG.encode("utf-8")

    ciphertext = compat.Sm2Cipher.encrypt(GOLDEN_SM2_PUB, msg)
    assert ciphertext[0] != 0x30  # 裸 C1C3C2

    compat.configure(sm2_public_key=GOLDEN_SM2_PUB)
    assert compat.Sm2Cipher.decrypt(GOLDEN_SM2_PRIV, ciphertext) == msg
    # 存量密文
    assert compat.Sm2Cipher.decrypt(GOLDEN_SM2_PRIV, GOLDEN_SM2_CT) == msg

    signature = compat.Sm2Cipher.sign(GOLDEN_SM2_PRIV, GOLDEN_SM2_PUB, msg)
    assert isinstance(signature, str)  # 旧实现返回十六进制字符串
    # 128 个十六进制字符 = 64 字节裸 r‖s；DER 包装会是 142~144 字符
    assert len(signature) == 128
    assert compat.Sm2Cipher.verify(GOLDEN_SM2_PUB, msg, signature) is True
    assert compat.Sm2Cipher.verify(GOLDEN_SM2_PUB, msg, GOLDEN_SM2_SIG.hex()) is True
    assert compat.Sm2Cipher.verify(GOLDEN_SM2_PUB, b"other", signature) is False


def test_sm2_decrypt_requires_configured_public_key() -> None:
    # 旧的 decrypt 签名只有私钥，而底层构造私钥时必须同时给公钥
    compat.configure(sm2_public_key=None)
    with pytest.raises(ValueError, match="sm2_public_key"):
        compat.Sm2Cipher.decrypt(GOLDEN_SM2_PRIV, GOLDEN_SM2_CT)


def test_sm3_call_shape_matches_legacy() -> None:
    assert compat.Sm3Cipher.hash(b"abc") == (
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    )
    salt = compat.Sm3Cipher.generate_salt()
    assert len(salt) == 32

    salt2, hash_value = compat.Sm3Cipher.hash_password("admin123")
    assert len(salt2) == 32
    assert len(hash_value) == 64
    assert compat.Sm3Cipher.verify_password("admin123", f"{salt2}${hash_value}") is True
    assert compat.Sm3Cipher.verify_password("wrong", f"{salt2}${hash_value}") is False
    assert compat.Sm3Cipher.verify_password("admin123", "no-dollar") is False


def test_sm4_call_shape_matches_legacy() -> None:
    key = bytes.fromhex(GOLDEN_SM4_KEY_HEX)
    blob = compat.Sm4Cipher.encrypt(key, b"hello")
    assert len(blob) == 16 + 16  # iv(16) + 一个填充块
    assert compat.Sm4Cipher.decrypt(key, blob) == b"hello"
    assert len(compat.Sm4Cipher.generate_key()) == 16
    with pytest.raises(ValueError):
        compat.Sm4Cipher.decrypt(key, b"\x00" * 16)


def test_sm4_config_key_env_then_configure(monkeypatch: pytest.MonkeyPatch) -> None:
    compat.configure(sm4_key=None)
    monkeypatch.delenv("SM4_KEY", raising=False)
    with pytest.raises(ValueError, match="SM4_KEY"):
        compat.Sm4Cipher.get_config_key()

    monkeypatch.setenv("SM4_KEY", GOLDEN_SM4_KEY_HEX)
    assert compat.Sm4Cipher.get_config_key() == bytes.fromhex(GOLDEN_SM4_KEY_HEX)

    compat.configure(sm4_key="11" * 16)
    assert compat.Sm4Cipher.get_config_key() == bytes.fromhex("11" * 16)
