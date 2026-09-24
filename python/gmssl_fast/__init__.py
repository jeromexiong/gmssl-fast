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
    "SM2",
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


def _validate_hex(value: str, length: int, what: str) -> None:
    if len(value) != length:
        raise ValueError(f"{what}必须是 {length} 个十六进制字符，实际 {len(value)}")
    try:
        bytes.fromhex(value)
    except ValueError as exc:  # 非十六进制
        raise ValueError(f"{what}不是合法十六进制") from exc


class SM2:
    """SM2 非对称加密 / 签名。

    **只使用裸格式**：

    - 密文 = 裸 C1C3C2 = ``x(32)‖y(32)‖C3(32)‖C2(n)``，长度 ``96 + n``
    - 签名 = 裸 r‖s，64 字节

    与 ``sm-crypto`` / ``gm_crypto`` 以及既有存量数据一致（DER 只是库内部调 GmSSL 的实现细节）。

    公钥接受 128（``X‖Y``）与 130（``04‖X‖Y``）字符两种输入。

    ⚠️ **私钥操作（``decrypt`` / ``sign``）必须同时提供公钥**：GmSSL 的 PKCS#8 解析
    要求公钥字段存在，且未暴露「由标量派生公钥」的接口（已实测）。这也与既有调用
    形态一致（``sign(private_key, public_key, data)``）。

    ⚠️ 加密明文上限 **255 字节**（GmSSL 限制），不要用它加密长数据。
    """

    def __init__(
        self, private_key: str | None = None, public_key: str | None = None
    ) -> None:
        if private_key is not None:
            _validate_hex(private_key, 64, "SM2 私钥")
        if public_key is not None:
            if len(public_key) == 130:
                if not public_key.startswith("04"):
                    raise ValueError("130 字符的 SM2 公钥必须以 04 开头")
                body = public_key[2:]
            elif len(public_key) == 128:
                # 注意：不能按「是否以 04 开头」判断前缀——x 坐标首字节本身可能就是 04
                body = public_key
            else:
                raise ValueError("SM2 公钥必须是 128 或 130 个十六进制字符")
            _validate_hex(body, 128, "SM2 公钥")
        if private_key is not None and public_key is None:
            raise ValueError(
                "SM2 私钥操作需要同时提供公钥（GmSSL 的 PKCS#8 解析要求公钥字段，已实测）"
            )
        self._private_key = private_key
        self._public_key = public_key

    @classmethod
    def generate(cls) -> "SM2":
        """生成密钥对。"""
        private_key, public_key = _core.sm2_generate()
        return cls(private_key=private_key, public_key=public_key)

    @property
    def private_key_hex(self) -> str | None:
        return self._private_key

    @property
    def public_key_hex(self) -> str | None:
        """130 字符（含 04 前缀）。"""
        return self._public_key

    def encrypt(self, data: bytes) -> bytes:
        """加密，返回裸 C1C3C2；明文上限 255 字节。"""
        if self._public_key is None:
            raise ValueError("SM2 加密需要公钥")
        return _core.sm2_encrypt_raw(self._public_key, data)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """解密裸 C1C3C2（内部按「原样 / 剥掉 04」两候选试解）。"""
        if self._private_key is None:
            raise ValueError("SM2 解密需要私钥")
        return _core.sm2_decrypt_raw(self._private_key, self._public_key, ciphertext)

    def sign(self, data: bytes) -> bytes:
        """签名，返回裸 r‖s（64 字节）；签名者标识用 GmSSL 默认值。"""
        if self._private_key is None:
            raise ValueError("SM2 签名需要私钥")
        return _core.sm2_sign_raw(self._private_key, self._public_key, data)

    def verify(self, data: bytes, signature: bytes) -> bool:
        """校验裸 r‖s 签名。"""
        if self._public_key is None:
            raise ValueError("SM2 验签需要公钥")
        return _core.sm2_verify_raw(self._public_key, data, signature)
