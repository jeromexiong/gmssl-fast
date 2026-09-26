"""性能基准：本库（GmSSL）与纯 Python 参考实现对照。

用法::

    python benches/bench.py                      # 64 MiB 缓冲 / 2000 次 SM2
    python benches/bench.py --mib 16 --ops 500

口径：

- 必须用 **release 构建**（`maturin build --release` 或 `develop --release`）；
- SM3 / SM4 用一次性大缓冲测**吞吐**，SM2 用短消息测**ops/s**；
- 每项取 `--repeat` 次里最快的一次；
- 纯 Python 对照（`snowland-smx`、`gmssl`）**装了才跑**，且用 `--ref-mib`（默认 1 MiB）、
  `--ref-ops`（默认 100 次 SM2）的小规模——它们慢 1～2 个数量级，用 64 MiB 要跑几分钟。
  `pysmx` 的 SM2 `Sign/Verify` 只收「已算好的摘要」，所以按存量实现的姿势
  手拼 ZA 再派生 E = SM3(ZA‖M)，**摘要开销计在签名里**（旧代码就是这样）。

⚠️ 数字与机器强相关：README / 设计文档里引用时必须标注测试机与架构。
⚠️ 两边量级差很多：SM3/SM4 大缓冲吞吐差 500～800×（纯 Python 逐块循环），
但 **SM2 只差 4～9×**（椭圆曲线运算在 Python 里靠大整数，本就不算慢）——
对外说性能时别拿 SM3 的倍数去形容 SM2。
"""

from __future__ import annotations

import argparse
import platform
import secrets
import sys
import time
from collections.abc import Callable
from importlib.metadata import PackageNotFoundError, version

import gmssl_fast

MIB = 1024 * 1024
KEY = bytes.fromhex("0123456789abcdeffedcba9876543210")
IV = bytes(range(16))
NONCE = bytes(range(12))
SM2_MESSAGE = b"gmssl-fast benchmark"
_SM2_PARAM_LENGTH = 64
# ZA 前缀 = ENTL(128 位) ‖ ID ‖ a ‖ b ‖ xG ‖ yG（ID 取 GM/T 0003 默认值）
_SM2_ZA_PREFIX = (
    "0080"
    + "1234567812345678".encode("utf-8").hex()
    + "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"
    + "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"
    + "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7"
    + "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"
)


def _best_of(fn: Callable[[], None], repeat: int) -> float:
    """跑 repeat 次，返回最快一次的单次耗时（秒）。"""
    best = float("inf")
    for _ in range(repeat):
        start = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - start)
    return best


def _batched(fn: Callable[[], None], times: int) -> Callable[[], None]:
    """把 times 次调用合成一批，便于按批计时。"""

    def run() -> None:
        for _ in range(times):
            fn()

    return run


def _ours(
    payload: bytes, sm2: gmssl_fast.SM2, ops: int
) -> dict[str, tuple[str, Callable[[], None]]]:
    """本库的被测操作；unit 为 ``"MiB"``（测吞吐）或 ``"op"``（测单次调用）。"""
    signature = sm2.sign(SM2_MESSAGE)
    sm4_cbc = gmssl_fast.SM4(KEY, mode="cbc", iv=IV)
    sm4_gcm = gmssl_fast.SM4GCM(KEY, NONCE)
    return {
        "SM3": ("MiB", lambda: gmssl_fast.sm3(payload)),
        "SM4-CBC": ("MiB", lambda: sm4_cbc.encrypt(payload)),
        "SM4-GCM": ("MiB", lambda: sm4_gcm.encrypt(payload)),
        "SM2 签名": ("op", _batched(lambda: sm2.sign(SM2_MESSAGE), ops)),
        "SM2 验签": ("op", _batched(lambda: sm2.verify(SM2_MESSAGE, signature), ops)),
    }


def _reference(
    payload: bytes, sm2: gmssl_fast.SM2, sm2_ops: int
) -> dict[str, dict[str, tuple[str, Callable[[], None]]]]:
    """可用的纯 Python 对照实现（装了才有）。键与 ``_ours`` 一致。"""
    refs: dict[str, dict[str, tuple[str, Callable[[], None]]]] = {}

    try:
        from pysmx.SM2 import Sign as PysmxSign
        from pysmx.SM2 import Verify as PysmxVerify
        from pysmx.SM3 import SM3 as PysmxSM3
        from pysmx.SM4 import ENCRYPT as PYS_ENCRYPT
        from pysmx.SM4 import SM4 as PysmxSM4
    except ImportError:
        pass
    else:

        def pysmx_sm3(data: bytes) -> str:
            hasher = PysmxSM3()
            hasher.update(data)
            return hasher.hexdigest()

        def pysmx_digest(public_key_128: str, data: bytes) -> str:
            """E = SM3(ZA ‖ M)——复刻老实现 ``_compute_sm2_digest``。"""
            za = pysmx_sm3(bytes.fromhex(_SM2_ZA_PREFIX + public_key_128))
            return pysmx_sm3(bytes.fromhex(za + data.hex()))

        def pysmx_sm3_op() -> None:
            pysmx_sm3(payload)

        def pysmx_sm4_cbc() -> None:
            cipher = PysmxSM4()
            cipher.set_key(KEY, PYS_ENCRYPT)
            cipher.crypt_cbc(IV, payload)

        public_key_128 = (sm2.public_key_hex or "")[2:]
        private_key = sm2.private_key_hex or ""
        digest = pysmx_digest(public_key_128, SM2_MESSAGE)
        signature = bytes(
            PysmxSign(digest, private_key, secrets.token_hex(32), _SM2_PARAM_LENGTH, Hexstr=1)
        ).hex()

        def pysmx_sm2_sign() -> None:
            for _ in range(sm2_ops):
                PysmxSign(digest, private_key, secrets.token_hex(32), _SM2_PARAM_LENGTH, Hexstr=1)

        def pysmx_sm2_verify() -> None:
            for _ in range(sm2_ops):
                PysmxVerify(
                    bytes.fromhex(signature), digest, public_key_128, _SM2_PARAM_LENGTH, Hexstr=1
                )

        refs["snowland-smx"] = {
            "SM3": ("MiB", pysmx_sm3_op),
            "SM4-CBC": ("MiB", pysmx_sm4_cbc),
            "SM2 签名": ("op", pysmx_sm2_sign),
            "SM2 验签": ("op", pysmx_sm2_verify),
        }

    try:
        from gmssl import func, sm3
        from gmssl.sm4 import SM4_ENCRYPT as GS_ENCRYPT
        from gmssl.sm4 import CryptSM4
    except ImportError:
        pass
    else:

        def gmssl_sm3() -> None:
            sm3.sm3_hash(func.bytes_to_list(payload))

        def gmssl_sm4_cbc() -> None:
            cipher = CryptSM4()
            cipher.set_key(KEY, GS_ENCRYPT)
            cipher.crypt_cbc(IV, payload)

        refs["gmssl"] = {"SM3": ("MiB", gmssl_sm3), "SM4-CBC": ("MiB", gmssl_sm4_cbc)}

    return refs


def main() -> int:
    parser = argparse.ArgumentParser(description="gmssl-fast 性能基准")
    parser.add_argument("--mib", type=int, default=64, help="吞吐测试的缓冲大小（MiB）")
    parser.add_argument("--ops", type=int, default=2000, help="本库 SM2 签名/验签次数")
    parser.add_argument(
        "--ref-ops", type=int, default=100, help="对照实现的 SM2 次数（慢，默认 100）"
    )
    parser.add_argument("--repeat", type=int, default=3, help="每项重复次数（取最快）")
    parser.add_argument(
        "--ref-mib", type=int, default=1, help="吞吐对照的缓冲大小（MiB，默认 1）"
    )
    args = parser.parse_args()

    try:
        our_version = version("gmssl-fast")
    except PackageNotFoundError:  # 未安装（直接用源码跑）
        our_version = "unknown"
    print(
        f"gmssl-fast {our_version} / CPython {sys.version.split()[0]} / "
        f"{platform.machine()} / {platform.platform()}"
    )
    print()

    payload = b"\xa5" * (args.mib * MIB)
    sm2 = gmssl_fast.SM2.generate()
    ours = _ours(payload, sm2, args.ops)
    our_times = {name: (unit, _best_of(fn, args.repeat)) for name, (unit, fn) in ours.items()}

    print(f"== 本库（{args.mib} MiB 一次性缓冲 / SM2 各 {args.ops} 次）==")
    for name, (unit, elapsed) in our_times.items():
        if unit == "op":
            print(f"{name:<12}{args.ops / elapsed:>12.0f} ops/s")
        else:
            print(f"{name:<12}{args.mib / elapsed:>12.1f} MiB/s")

    small = b"\xa5" * (args.ref_mib * MIB)
    refs = _reference(small, sm2, args.ref_ops)
    if not refs:
        print("\n（未安装 snowland-smx / gmssl，跳过纯 Python 对照）")
        return 0

    our_signature = sm2.sign(SM2_MESSAGE)
    our_small: dict[str, Callable[[], None]] = {
        "SM3": lambda: gmssl_fast.sm3(small),
        "SM4-CBC": lambda: gmssl_fast.SM4(KEY, mode="cbc", iv=IV).encrypt(small),
        "SM2 签名": _batched(lambda: sm2.sign(SM2_MESSAGE), args.ref_ops),
        "SM2 验签": _batched(lambda: sm2.verify(SM2_MESSAGE, our_signature), args.ref_ops),
    }

    print(
        f"\n== 纯 Python 对照（吞吐两侧同用 {args.ref_mib} MiB；"
        f"SM2 两侧同用 {args.ref_ops} 次）=="
    )
    print(f"{'实现':<16}{'操作':<10}{'本库':>16}{'对照':>16}{'倍数':>8}")
    for impl_name, ops_map in refs.items():
        for op_name, (unit, ref_fn) in ops_map.items():
            our_seconds = _best_of(our_small[op_name], args.repeat)
            ref_seconds = _best_of(ref_fn, max(1, args.repeat - 1))
            if unit == "op":
                our_text = f"{args.ref_ops / our_seconds:.0f} ops/s"
                ref_text = f"{args.ref_ops / ref_seconds:.0f} ops/s"
            else:
                our_text = f"{args.ref_mib / our_seconds:.2f} MiB/s"
                ref_text = f"{args.ref_mib / ref_seconds:.2f} MiB/s"
            ratio = ref_seconds / our_seconds
            print(f"{impl_name:<16}{op_name:<10}{our_text:>16}{ref_text:>16}{ratio:>7.1f}x")

    print(
        "\n注：SM2 侧的对照按存量实现的姿势手拼 ZA 后再算摘要，"
        "摘要开销计在签名里；两侧都是单线程、同一条消息。"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
