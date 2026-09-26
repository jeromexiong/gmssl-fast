"""SM3 公开 API 测试。

标准向量来源：GM/T 0004-2012 附录 A（SM3("abc")）。

⚠️ 本目录的断言规则：**不得依赖概率**。随机性（盐 / IV / 临时密钥）用
`monkeypatch` 注入固定值来断言，而不是「跑两次看它不一样」（那是概率断言）。
"""

import pytest

import gmssl_fast

SM3_ABC = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"


def test_sm3_standard_vector() -> None:
    assert gmssl_fast.sm3(b"abc").hex() == SM3_ABC
    assert gmssl_fast.sm3_hex(b"abc") == SM3_ABC


# ---------------------------------------------------------------------------
#  fastapiadmin 契约（golden 向量，设计 §4.2 / §7）
# ---------------------------------------------------------------------------

# salt 固定为 32 个 'a'，便于验证 hash 的确定性（真实场景由 secrets 生成）
GOLDEN_PWD = (
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa$"
    "d213b154ddba7eda7f38786f4675d1e3b926d32192a7306e7bcb8d2ea62c68fc"
)


def test_password_hash_matches_fastapiadmin_format() -> None:
    # 旧实现：hash = SM3((password + salt).encode())，其中 salt 是十六进制字符串本身
    assert gmssl_fast.sm3_hex(("admin123" + "a" * 32).encode()) == GOLDEN_PWD.split("$")[1]


def test_password_verify_accepts_golden_stored_value() -> None:
    assert gmssl_fast.sm3_password_verify("admin123", GOLDEN_PWD) is True
    assert gmssl_fast.sm3_password_verify("wrong", GOLDEN_PWD) is False
    # 格式不合法必须返回 False，不抛异常（旧实现如此，39 条测试依赖）
    assert gmssl_fast.sm3_password_verify("admin123", "no-dollar-sign") is False


def test_password_hash_roundtrip() -> None:
    stored = gmssl_fast.sm3_password_hash("admin123")
    assert gmssl_fast.sm3_password_verify("admin123", stored) is True
    assert gmssl_fast.sm3_password_verify("admin1", stored) is False


def test_password_hash_salt_comes_from_secrets_token_hex(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """盐必须来自 `secrets.token_hex(16)`。

    注意断言方式：**注入**随机源再断言它被按约定调用，而不是「两次取到不同盐」
    （后者是概率断言：碰撞概率 2⁻¹²⁸，虽极小但不可证明）。
    """
    injected = "ab" * 16
    calls: list[int] = []

    def fake_token_hex(n: int) -> str:
        calls.append(n)
        return injected

    monkeypatch.setattr(gmssl_fast.secrets, "token_hex", fake_token_hex)
    stored = gmssl_fast.sm3_password_hash("admin123")

    assert calls == [16]  # 恰好调用一次、16 字节
    assert stored == f"{injected}${gmssl_fast.sm3_hex(('admin123' + injected).encode())}"
    assert gmssl_fast.sm3_password_verify("admin123", stored) is True


def test_sm3_hmac() -> None:
    assert gmssl_fast.sm3_hmac(b"key", b"data").hex() == (
        "88a5a14b0fcf4a8a7b0c5084b8ee36e70efca4e8467fa264c3231bf16463b425"
    )


def test_sm3_pbkdf2_derives_requested_length() -> None:
    dk = gmssl_fast.sm3_pbkdf2(b"password", b"salt", 10000, 32)
    assert len(dk) == 32
    assert dk.hex() == "738c8c432372d98a73350bc252209e4cf2acdde7cc816730b9812bdfd55c1265"
