"""与存量实现（fastapiadmin 的 ``snowland-smx`` 版 ``sm_crypto.py``）**双向**对拍。

这里把 ``pysmx`` 当作「旧库」：

1. **本库产出 → 旧库能处理**（旧服务读到新库写的数据不会崩）
2. **旧库产出 → 本库能处理**（新库必须能读线上存量数据）
3. **golden 常量自洽**（参照实现本身能处理这些存量向量，否则「对拍」没有基准）

只有三个方向都通，才谈得上「把 ``sm_crypto.py`` 换成几行 re-export」（设计 §11）。

未安装 ``snowland-smx`` 时整文件跳过——``pip install -e '.[test]'`` 可装上。
本文件中的 ZA 拼装、参数长度、重试策略均逐字复刻旧实现（含它自己的重试怪癖）。
"""

import secrets

import pytest

import gmssl_fast
from gmssl_fast import compat
from golden import (
    GOLDEN_SM2_CT,
    GOLDEN_SM2_MSG,
    GOLDEN_SM2_PRIV,
    GOLDEN_SM2_PUB,
    GOLDEN_SM2_SIG,
    GOLDEN_SM4_IV_HEX,
    GOLDEN_SM4_KEY_HEX,
)

pysmx_sm2 = pytest.importorskip("pysmx.SM2", reason="双向对拍需要旧库 snowland-smx")
pysmx_sm3 = pytest.importorskip("pysmx.SM3", reason="双向对拍需要旧库 snowland-smx")
pysmx_sm4 = pytest.importorskip("pysmx.SM4", reason="双向对拍需要旧库 snowland-smx")

_PUB128 = GOLDEN_SM2_PUB[2:]
_MSG = GOLDEN_SM2_MSG.encode("utf-8")
_SM2_PARAM_LENGTH = 64
_MAX_ATTEMPTS = 10

# ZA 前缀 = ENTL(128 位) ‖ ID ‖ a ‖ b ‖ xG ‖ yG（ID 取 GM/T 0003 默认值）
_SM2_ZA_PREFIX = (
    "0080"
    + "1234567812345678".encode("utf-8").hex()
    + "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"
    + "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"
    + "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7"
    + "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"
)


@pytest.fixture(autouse=True)
def _configure() -> None:
    """Phase 2 迁移后的调用姿势：配置一次，之后按旧签名无参调用。"""
    compat.configure(sm2_public_key=GOLDEN_SM2_PUB, sm4_key=GOLDEN_SM4_KEY_HEX)


# ------------------------------------------------------------------ 旧实现镜像
def _legacy_sm3_hex(data: bytes) -> str:
    hasher = pysmx_sm3.SM3()
    hasher.update(data)
    return hasher.hexdigest()


def _legacy_digest(public_key_128: str, data: bytes) -> str:
    """E = SM3(ZA ‖ M)；旧实现手算摘要（pysmx 的 Sign/Verify 只收现成摘要）。"""
    za = _legacy_sm3_hex(bytes.fromhex(_SM2_ZA_PREFIX + public_key_128))
    return _legacy_sm3_hex(bytes.fromhex(za + data.hex()))


def _legacy_ciphertext(data: bytes) -> bytes:
    """旧库加密；KDF 输出全零时它返回 None，旧实现靠重试兜住。"""
    for _ in range(_MAX_ATTEMPTS):
        ciphertext = pysmx_sm2.Encrypt(data, _PUB128, _SM2_PARAM_LENGTH, mode="C1C3C2")
        if ciphertext:
            return bytes(ciphertext)
    raise AssertionError("旧库加密连续退化（不应发生）")


def _legacy_signature_hex(data: bytes) -> str:
    """旧库签名；随机数退化时它返回 None，同样靠重试兜住。"""
    digest = _legacy_digest(_PUB128, data)
    for _ in range(_MAX_ATTEMPTS):
        signature = pysmx_sm2.Sign(
            digest, GOLDEN_SM2_PRIV, secrets.token_hex(32), _SM2_PARAM_LENGTH, Hexstr=1
        )
        if signature:
            return bytes(signature).hex()
    raise AssertionError("旧库签名连续退化（不应发生）")


def _legacy_sm4_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """旧库 SM4-CBC，返回 ``iv(16) ‖ ciphertext``（与旧实现布局一致）。"""
    cipher = pysmx_sm4.SM4()
    cipher.set_key(key, pysmx_sm4.ENCRYPT)
    return iv + bytes(cipher.crypt_cbc(iv, plaintext))


# ------------------------------------------------------------------ SM2 双向
@pytest.mark.parametrize("size", [1, 16, 32, 255])
def test_ciphertext_from_ours_decrypts_with_legacy(size: int) -> None:
    """本库密文 → 旧库解密（1 字节明文会踩到 KDF 全零重试路径）。"""
    plaintext = (b"gmssl-fast" * 32)[:size]
    ciphertext = compat.Sm2Cipher.encrypt(GOLDEN_SM2_PUB, plaintext)
    assert len(ciphertext) == 96 + size
    assert (
        bytes(
            pysmx_sm2.Decrypt(
                ciphertext, GOLDEN_SM2_PRIV, _SM2_PARAM_LENGTH, mode="C1C3C2"
            )
        )
        == plaintext
    )


def test_ciphertext_from_legacy_decrypts_with_ours() -> None:
    """旧库密文 → 本库解密。"""
    assert compat.Sm2Cipher.decrypt(GOLDEN_SM2_PRIV, _legacy_ciphertext(_MSG)) == _MSG


def test_signature_from_ours_verifies_with_legacy() -> None:
    """本库签名 → 旧库验签（证明 ZA/摘要推导逐位一致）。"""
    signature_hex = compat.Sm2Cipher.sign(GOLDEN_SM2_PRIV, GOLDEN_SM2_PUB, _MSG)
    assert (
        bool(
            pysmx_sm2.Verify(
                bytes.fromhex(signature_hex),
                _legacy_digest(_PUB128, _MSG),
                _PUB128,
                _SM2_PARAM_LENGTH,
                Hexstr=1,
            )
        )
        is True
    )


def test_signature_from_legacy_verifies_with_ours() -> None:
    """旧库签名 → 本库验签（存量日志签名必须继续可验）。"""
    assert compat.Sm2Cipher.verify(GOLDEN_SM2_PUB, _MSG, _legacy_signature_hex(_MSG)) is True


def test_golden_vectors_are_consistent_with_legacy() -> None:
    """参照实现本身能处理 golden 向量——否则对拍基准不成立。"""
    assert (
        bytes(pysmx_sm2.Decrypt(GOLDEN_SM2_CT, GOLDEN_SM2_PRIV, _SM2_PARAM_LENGTH, mode="C1C3C2"))
        == _MSG
    )
    assert (
        bool(
            pysmx_sm2.Verify(
                GOLDEN_SM2_SIG,
                _legacy_digest(_PUB128, _MSG),
                _PUB128,
                _SM2_PARAM_LENGTH,
                Hexstr=1,
            )
        )
        is True
    )


# ------------------------------------------------------------------ SM3 / 密码
@pytest.mark.parametrize("size", [0, 1, 55, 56, 64, 65, 119, 120, 1000])
def test_sm3_matches_legacy_on_block_boundaries(size: int) -> None:
    """分组填充边界（55/56/64/65/119/120 是 512 位分组的临界长度）。"""
    data = (b"gmssl-fast" * 200)[:size]
    assert gmssl_fast.sm3_hex(data) == _legacy_sm3_hex(data)


def test_password_hash_is_derived_like_legacy() -> None:
    """``salt$hash`` 布局与推导公式逐位一致（存量密码必须能继续校验）。"""
    salt, hash_value = compat.Sm3Cipher.hash_password("admin123")
    assert len(salt) == 32
    assert _legacy_sm3_hex(("admin123" + salt).encode("utf-8")) == hash_value
    assert compat.Sm3Cipher.verify_password("admin123", f"{salt}${hash_value}") is True


# ------------------------------------------------------------------ SM4
@pytest.mark.parametrize("size", [1, 16, 17, 28, 64])
def test_sm4_cbc_is_byte_identical_to_legacy(size: int) -> None:
    """CBC + PKCS7 密文逐字节相同，且双方可互相解密。"""
    key = bytes.fromhex(GOLDEN_SM4_KEY_HEX)
    iv = bytes.fromhex(GOLDEN_SM4_IV_HEX)
    plaintext = (b"fastapiadmin-sm4" * 8)[:size]
    ours = compat.Sm4Cipher.encrypt(key, plaintext, iv)
    legacy = _legacy_sm4_cbc_encrypt(key, iv, plaintext)
    assert ours == legacy
    assert compat.Sm4Cipher.decrypt(key, legacy) == plaintext
