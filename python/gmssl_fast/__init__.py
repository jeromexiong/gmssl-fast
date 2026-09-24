"""gmssl-fast：基于 GmSSL 的国密算法扩展（SM2/SM3/SM4）。

对外**只使用裸格式**（SM2 密文裸 C1C3C2、签名裸 r‖s），与 sm-crypto / gm_crypto
等前端库以及既有存量数据保持一致。DER 编码只是调用 GmSSL 时的内部细节，不出现在 API 上。

安装即可用，不需要系统预装 GmSSL：

    pip install gmssl-fast
"""

from __future__ import annotations

import secrets

from . import _core
from ._core import (
    GmsslAuthError,
    GmsslError,
    GmsslValueError,
    GmsslVerificationError,
    sm3,
    sm3_hmac,
    sm3_pbkdf2,
)

__all__ = [
    "GmsslAuthError",
    "GmsslError",
    "GmsslValueError",
    "GmsslVerificationError",
    "SM4",
    "SM4GCM",
    "sm3",
    "sm3_hex",
    "sm3_hmac",
    "sm3_pbkdf2",
    "sm3_password_hash",
    "sm3_password_verify",
]


def sm3_hex(data: bytes) -> str:
    """SM3 摘要，返回 64 字符小写十六进制字符串。"""
    return sm3(data).hex()


def sm3_password_hash(password: str) -> str:
    """密码加盐哈希，返回 ``"salt$hash"``。

    ``salt`` 是 16 字节随机值的十六进制（32 字符），
    ``hash`` = ``SM3((password + salt).encode())``。

    该格式与 fastapiadmin 既有实现（``Sm3Cipher.hash_password``）逐位一致，
    因此存量数据无需转换。
    """
    salt = secrets.token_hex(16)
    return f"{salt}${sm3_hex((password + salt).encode('utf-8'))}"


def sm3_password_verify(password: str, stored: str) -> bool:
    """校验密码是否匹配 ``"salt$hash"``。

    存储值格式不合法时**返回 False 而不抛异常**（与既有实现一致）。
    """
    if "$" not in stored:
        return False
    salt, expected = stored.split("$", 1)
    return sm3_hex((password + salt).encode("utf-8")) == expected


class SM4:
    """SM4 对称加密（CBC / CTR / ECB）。

    - ``encrypt()`` 返回 ``iv(16)‖ciphertext``；**ECB 模式无 IV 前缀**
    - CBC / ECB 自动 PKCS7 填充；CTR 是流模式，不做填充
    - 不传 IV 时随机生成（16 字节）

    ⚠️ CBC **不提供完整性保护**：错误 IV 会解出垃圾明文而不报错。
    需要完整性请用 :class:`SM4GCM`。
    """

    def __init__(self, key: bytes, mode: str = "cbc", iv: bytes | None = None) -> None:
        if len(key) != 16:
            raise ValueError("SM4 密钥必须是 16 字节")
        if mode not in ("cbc", "ctr", "ecb"):
            raise ValueError(f"不支持的 SM4 模式：{mode!r}")
        if iv is not None and len(iv) != 16:
            raise ValueError("SM4 的 IV 必须是 16 字节")
        self._key = key
        self._mode = mode
        self._iv = iv

    def encrypt(self, plaintext: bytes, iv: bytes | None = None) -> bytes:
        """加密。返回 ``iv(16)‖ciphertext``（ECB 模式只返回密文）。"""
        if self._mode == "ecb":
            return _core.sm4_ecb_encrypt(self._key, plaintext)
        iv = iv or self._iv or secrets.token_bytes(16)
        if len(iv) != 16:
            raise ValueError("SM4 的 IV 必须是 16 字节")
        if self._mode == "cbc":
            return iv + _core.sm4_cbc_encrypt(self._key, iv, plaintext)
        return iv + _core.sm4_ctr_xor(self._key, iv, plaintext)

    def decrypt(self, blob: bytes) -> bytes:
        """解密。输入应为 ``encrypt()`` 的返回值（含 IV 前缀）。"""
        if self._mode == "ecb":
            return _core.sm4_ecb_decrypt(self._key, blob)
        if len(blob) <= 16:
            raise ValueError("解密输入必须至少包含 16 字节 IV 与 1 字节密文")
        iv, ciphertext = blob[:16], blob[16:]
        if self._mode == "cbc":
            return _core.sm4_cbc_decrypt(self._key, iv, ciphertext)
        return _core.sm4_ctr_xor(self._key, iv, ciphertext)


class SM4GCM:
    """SM4-GCM 认证加密（**只有一次性 API**）。

    - ``nonce`` 强制 12 字节、``tag`` 强制 16 字节——GmSSL 本身不校验这两个长度，
      必须由库层拦住（详见设计文档 §2）
    - 加密 N 字节需要约 N 字节额外内存（上游未暴露流式接口）
    """

    def __init__(self, key: bytes, nonce: bytes) -> None:
        if len(key) != 16:
            raise ValueError("SM4 密钥必须是 16 字节")
        if len(nonce) != 12:
            raise ValueError("SM4-GCM 的 nonce 必须是 12 字节")
        self._key = key
        self._nonce = nonce

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
        """返回 ``(ciphertext, tag)``；``tag`` 固定 16 字节。"""
        return _core.sm4_gcm_encrypt(self._key, self._nonce, aad, plaintext)

    def decrypt(self, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
        """解密并校验完整性；失败抛 :class:`GmsslAuthError`。"""
        if len(tag) != 16:
            raise ValueError("SM4-GCM 的 tag 必须是 16 字节")
        return _core.sm4_gcm_decrypt(self._key, self._nonce, aad, ciphertext, tag)
