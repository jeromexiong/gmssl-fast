"""drop-in 兼容门面：类名与静态方法签名与既有实现**逐字对齐**。

用于从 ``gmssl`` / ``snowland-smx`` / 自研 util 迁移的项目——原来的算法模块可以缩成几行：

.. code-block:: python

    from gmssl_fast import compat
    compat.configure(
        sm2_public_key=settings.SM2_PUBLIC_KEY,
        sm4_key=settings.SM4_KEY,
    )
    Sm2Cipher, Sm3Cipher, Sm4Cipher = (
        compat.Sm2Cipher,
        compat.Sm3Cipher,
        compat.Sm4Cipher,
    )

之后调用方（``CommonCryptogramUtil``、``PwdUtil``、SQLAlchemy ``TypeDecorator`` 等）**零改动**。

``configure(sm2_public_key=...)`` 是**可选**的：旧签名 ``Sm2Cipher.decrypt(private_key,
ciphertext)`` 不带公钥，库会在缺公钥时自行派生 ``d·G``。显式注入的好处是省掉那次 EC 乘法，
并让 GmSSL 校验注入的公钥与私钥是否匹配（传错会直接报错）。
"""

from __future__ import annotations

import os
import secrets
from functools import lru_cache

from . import SM4, _core, sm3_password_hash, sm3_password_verify

_sm2_public_key: str | None = None
_sm4_key: str | None = None


@lru_cache(maxsize=8)
def _key_handle(
    private_key: str | None, public_key: str | None
) -> _core.Sm2KeyHandle:
    """按 ``(私钥, 公钥)`` 缓存密钥句柄。

    旧式静态方法没有实例可挂缓存，而 GmSSL 每次都要重新解析 PKCS#8（含一次校验公钥
    是否匹配标量的 EC 乘法）——对「每条日志签一次」这种调用是纯浪费。
    """
    return _core.Sm2KeyHandle(private_key, public_key)


def configure(*, sm2_public_key: str | None = None, sm4_key: str | None = None) -> None:
    """注入项目配置，供旧签名的无参调用使用。

    Args:
        sm2_public_key: 130 字符公钥（含 ``04`` 前缀）或 128 字符，供
            :meth:`Sm2Cipher.decrypt` 使用。
        sm4_key: 32 个十六进制字符的 SM4 密钥，供 :meth:`Sm4Cipher.get_config_key` 使用；
            未提供时回退读环境变量 ``SM4_KEY``。
    """
    global _sm2_public_key, _sm4_key
    _sm2_public_key = sm2_public_key
    _sm4_key = sm4_key


class Sm2Cipher:
    """SM2 兼容门面（裸 C1C3C2 密文、裸 r‖s 签名）。"""

    @staticmethod
    def encrypt(public_key: str, data: bytes) -> bytes:
        """加密，返回裸 C1C3C2（长度 ``96 + len(data)``）；明文上限 255 字节。"""
        return _key_handle(None, public_key).encrypt(data)

    @staticmethod
    def decrypt(private_key: str, ciphertext: bytes) -> bytes:
        """解密；只给私钥即可（未 ``configure`` 时由库派生 ``d·G``，见模块文档）。"""
        return _key_handle(private_key, _sm2_public_key).decrypt(ciphertext)

    @staticmethod
    def sign(private_key: str, public_key: str, data: bytes) -> str:
        """签名，返回 128 个十六进制字符的裸 r‖s。"""
        return _key_handle(private_key, public_key).sign(data).hex()

    @staticmethod
    def verify(public_key: str, data: bytes, signature: str) -> bool:
        """校验十六进制字符串形式的裸 r‖s 签名。"""
        return _key_handle(None, public_key).verify(data, bytes.fromhex(signature))


class Sm3Cipher:
    """SM3 兼容门面（含密码加盐）。"""

    SALT_LENGTH = 16

    @staticmethod
    def hash(data: bytes) -> str:
        """SM3 摘要，返回 64 个十六进制字符。"""
        return _core.sm3(data).hex()

    @staticmethod
    def generate_salt() -> str:
        """生成 16 字节随机盐的十六进制字符串（32 字符）。"""
        return secrets.token_bytes(Sm3Cipher.SALT_LENGTH).hex()

    @classmethod
    def hash_password(cls, password: str, salt: str | None = None) -> tuple[str, str]:
        """返回 ``(salt, hash)``；``hash = SM3((password + salt).encode())``。"""
        if salt is None:
            return tuple(sm3_password_hash(password).split("$", 1))  # type: ignore[return-value]
        return salt, cls.hash((password + salt).encode("utf-8"))

    @classmethod
    def verify_password(cls, password: str, stored_value: str) -> bool:
        """校验 ``salt$hash``；格式不合法返回 False（不抛异常）。"""
        return sm3_password_verify(password, stored_value)


class Sm4Cipher:
    """SM4-CBC 兼容门面（PKCS7，输出 ``iv(16)‖ciphertext``）。"""

    @staticmethod
    def get_config_key() -> bytes:
        """取 SM4 密钥：优先 ``configure(sm4_key=...)``，其次环境变量 ``SM4_KEY``。"""
        key_hex = _sm4_key or os.environ.get("SM4_KEY", "")
        if not key_hex:
            raise ValueError(
                "SM4_KEY 未配置：请设置环境变量 SM4_KEY 或调用 compat.configure(sm4_key=...)"
            )
        return bytes.fromhex(key_hex)

    @staticmethod
    def generate_key() -> bytes:
        """生成 16 字节随机密钥。"""
        return secrets.token_bytes(16)

    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, iv: bytes | None = None) -> bytes:
        """加密，返回 ``iv(16)‖ciphertext``；``iv`` 省略时随机生成。"""
        return SM4(key, mode="cbc", iv=iv).encrypt(plaintext)

    @staticmethod
    def decrypt(key: bytes, data: bytes) -> bytes:
        """解密，输入应为 ``encrypt`` 的返回值（前 16 字节为 IV）。"""
        return SM4(key, mode="cbc").decrypt(data)
