"""gmssl-fast：基于 GmSSL 的国密算法扩展（SM2/SM3/SM4）。

对外**只使用裸格式**（SM2 密文裸 C1C3C2、签名裸 r‖s），与 sm-crypto / gm_crypto
等前端库以及既有存量数据保持一致。DER 编码只是调用 GmSSL 时的内部细节，不出现在 API 上。

安装即可用，不需要系统预装 GmSSL：

    pip install gmssl-fast
"""

from ._core import sm3

__all__ = ["sm3", "sm3_hex"]


def sm3_hex(data: bytes) -> str:
    """SM3 摘要，返回 64 字符小写十六进制字符串。"""
    return sm3(data).hex()
