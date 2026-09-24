"""SM3 公开 API 测试。

标准向量来源：GM/T 0004-2012 附录 A（SM3("abc")）。
"""

import gmssl_fast

SM3_ABC = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"


def test_sm3_standard_vector() -> None:
    assert gmssl_fast.sm3(b"abc").hex() == SM3_ABC
    assert gmssl_fast.sm3_hex(b"abc") == SM3_ABC
