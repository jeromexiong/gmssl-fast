"""fastapiadmin 国密契约的 golden 向量（冻结的存量数据）。

逐字复制自 ``/Users/jerome/Developer/AI/fastapiadmin/backend/tests/core/test_sm_crypto.py``
（2026-09-24 快照）。这些值代表**已落库/已在线上流通**的数据，任何实现改动都必须让它们
继续通过；它们同时也是「新库能不能替换旧库」的验收标准。

📌 本文件是**唯一**允许做字节级断言的对象（固定向量）。规则：
随机产生的值只断言不变量（长度 / 往返 / 互相验证），
「随机盐不同」「随机 IV 非全零」这类行为要用 monkeypatch 注入随机源后断言。
机械检查：``python scripts/lint_test_asserts.py``。
"""

# ---------------------------------------------------------------- SM2
GOLDEN_SM2_PRIV = "fef1cd14d44d8a57afa854312a2fb11155638a9d6444d8a35db0e75cf4949246"
GOLDEN_SM2_PUB = (
    "046574bf3f968a9fc217ce48f65543c64be1a6a8dc8325ffed3125e425fb09626"
    "b3996ca6e16bc109c3e43a1133a2c16485f4f67dd0d8dded6b837f4e9dca2ea21"
)
GOLDEN_SM2_MSG = "fastapiadmin-国密契约"
GOLDEN_SM2_CT = bytes.fromhex(
    "5e2ad5aa14c202bcb8653d1edcb4c13a89a7c959a50d6056679ccc8229b69ce0"
    "4cd1df4597e9bdfb05007785a514af83a70f09a66767784522b18da00fe9a75a"
    "f2262f8d9d6b18a303953eb121947f8540dbeef01003e6dc09f9aa6850929245"
    "a6b8b306e770b524180f61aebfb1e2c151918747d7a401c8a6"
)
# 首字节恰为 0x04 的**合法裸**密文：x 坐标首字节本身就是 0x04。
# 用于锁定「按首字节剥离 04 前缀」这个启发式的回归。
GOLDEN_SM2_CT_LEADING_04 = bytes.fromhex(
    "044a6aab51879c22a823c7e9c305978679fbe222f37f8492c25b61fd295e7621"
    "0274dadbe2d1585ab5266e54661c02fd5f839e90b1f74e16ff7c369059417052"
    "d7d3498ea4527a2ccb9772694461a9c1778df1948e9f95b27af0942997c58446"
    "d5ca11a5bcfcbc29b4a7ffe4483cc3373f5928198b3bd9b0e0"
)
GOLDEN_SM2_SIG = bytes.fromhex(
    "6512c757cb3e105aac6e6d9ca66f9d9b9badaba2eb45ec04768df6be2ed37e0e"
    "45619e22909951cc909fbe8e5ca2acc47b22a44b35e99856e8e4f3daf947e6ce"
)

# ---------------------------------------------------------------- SM3 / 密码
# salt 固定为 32 个 'a'，便于验证 hash 的确定性（真实场景由 secrets 生成）
GOLDEN_PWD = (
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa$"
    "d213b154ddba7eda7f38786f4675d1e3b926d32192a7306e7bcb8d2ea62c68fc"
)
GOLDEN_PWD_PLAIN = "admin123"
SM3_ABC_VECTOR = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"

# ---------------------------------------------------------------- SM4
GOLDEN_SM4_KEY_HEX = "0123456789abcdeffedcba9876543210"
GOLDEN_SM4_IV_HEX = "00000000000000000000000000000000"
# 全零 IV 下 CBC 首块 == ECB(明文块)，与实现无关的已知答案
GOLDEN_SM4_BLOCK_CIPHER = "99ce75c0ca2949d3eb87bd2d831f3510"
