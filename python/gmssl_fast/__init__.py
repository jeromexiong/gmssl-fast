"""gmssl-fast：基于 GmSSL 的国密算法扩展（SM2/SM3/SM4）。

对外**只使用裸格式**（SM2 密文裸 C1C3C2、签名裸 r‖s），与 sm-crypto / gm_crypto
等前端库以及既有存量数据保持一致。DER 编码只是调用 GmSSL 时的内部细节，不出现在 API 上。

安装即可用，不需要系统预装 GmSSL：

    pip install gmssl-fast
"""

import secrets

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
