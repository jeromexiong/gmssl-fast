"""性能基准：本库（GmSSL）与纯 Python 参考实现对照。

用法::

    python benches/bench.py                      # 64 MiB 缓冲 / 2000 次 SM2
    python benches/bench.py --mib 16 --ops 500

口径：

- 必须用 **release 构建**（`maturin build --release` 或 `develop --release`）；
- SM3 / SM4 用一次性大缓冲测**吞吐**，SM2 用短消息测**ops/s**；
- 每项取 `--repeat` 次里最快的一次；
- 纯 Python 对照（`snowland-smx`、`gmssl`）**装了才跑**，且用 `--ref-mib` 的小缓冲——
  它们慢 1～2 个数量级，用 64 MiB 要跑几分钟。

⚠️ 数字与机器强相关：README / 设计文档里引用时必须标注测试机与架构。
"""

from __future__ import annotations

import argparse
import platform
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


def _best_of(fn: Callable[[], None], repeat: int) -> float:
    """跑 repeat 次，返回最快一次的单次耗时（秒）。"""
    best = float("inf")
    for _ in range(repeat):
        start = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - start)
    return best


def _ours(payload: bytes, ops: int) -> dict[str, Callable[[], None]]:
    """本库的 5 个被测操作。"""
    sm2 = gmssl_fast.SM2.generate()
    signature = sm2.sign(SM2_MESSAGE)
    sm4_cbc = gmssl_fast.SM4(KEY, mode="cbc", iv=IV)
    sm4_gcm = gmssl_fast.SM4GCM(KEY, NONCE)
    sign_batch = _batched(lambda: sm2.sign(SM2_MESSAGE), ops)
    verify_batch = _batched(lambda: sm2.verify(SM2_MESSAGE, signature), ops)
    return {
        "SM3": lambda: gmssl_fast.sm3(payload),
        "SM4-CBC": lambda: sm4_cbc.encrypt(payload),
        "SM4-GCM": lambda: sm4_gcm.encrypt(payload),
        "SM2 签名": sign_batch,
        "SM2 验签": verify_batch,
    }


def _batched(fn: Callable[[], None], times: int) -> Callable[[], None]:
    """把 ops 次调用合成一批，便于按批计时。"""

    def run() -> None:
        for _ in range(times):
            fn()

    return run


def _reference(payload: bytes) -> dict[str, dict[str, Callable[[], None]]]:
    """可用的纯 Python 对照实现（只做 SM3 与 SM4-CBC，SM2 需手工拼 ZA/摘要）。"""
    refs: dict[str, dict[str, Callable[[], None]]] = {}

    try:
        from pysmx.SM3 import SM3 as PysmxSM3
        from pysmx.SM4 import ENCRYPT as PYS_ENCRYPT
        from pysmx.SM4 import SM4 as PysmxSM4
    except ImportError:
        pass
    else:

        def pysmx_sm3() -> None:
            hasher = PysmxSM3()
            hasher.update(payload)
            hasher.hexdigest()

        def pysmx_sm4_cbc() -> None:
            cipher = PysmxSM4()
            cipher.set_key(KEY, PYS_ENCRYPT)
            cipher.crypt_cbc(IV, payload)

        refs["snowland-smx"] = {"SM3": pysmx_sm3, "SM4-CBC": pysmx_sm4_cbc}

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

        refs["gmssl"] = {"SM3": gmssl_sm3, "SM4-CBC": gmssl_sm4_cbc}

    return refs


def main() -> int:
    parser = argparse.ArgumentParser(description="gmssl-fast 性能基准")
    parser.add_argument("--mib", type=int, default=64, help="本库吞吐测试的缓冲大小（MiB）")
    parser.add_argument("--ops", type=int, default=2000, help="SM2 签名/验签次数")
    parser.add_argument("--repeat", type=int, default=3, help="每项重复次数（取最快）")
    parser.add_argument(
        "--ref-mib", type=int, default=1, help="纯 Python 对照的缓冲大小（MiB，默认 1）"
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
    ours = _ours(payload, args.ops)
    our_times = {name: _best_of(fn, args.repeat) for name, fn in ours.items()}

    print(f"== 本库（{args.mib} MiB 一次性缓冲 / SM2 各 {args.ops} 次）==")
    for name, elapsed in our_times.items():
        if name.startswith("SM2"):
            print(f"{name:<12}{args.ops / elapsed:>12.0f} ops/s")
        else:
            print(f"{name:<12}{args.mib / elapsed:>12.1f} MiB/s")

    small = b"\xa5" * (args.ref_mib * MIB)
    refs = _reference(small)
    if not refs:
        print("\n（未安装 snowland-smx / gmssl，跳过纯 Python 对照）")
        return 0

    print(f"\n== 纯 Python 对照（两侧均用 {args.ref_mib} MiB 缓冲）==")
    print(f"{'实现':<16}{'操作':<10}{'本库':>14}{'对照':>14}{'倍数':>8}")
    for impl_name, ops_map in refs.items():
        for op_name, fn in ops_map.items():
            our_small = {
                "SM3": lambda: gmssl_fast.sm3(small),
                "SM4-CBC": lambda: gmssl_fast.SM4(KEY, mode="cbc", iv=IV).encrypt(small),
            }[op_name]
            our_rate = args.ref_mib / _best_of(our_small, args.repeat)
            ref_rate = args.ref_mib / _best_of(fn, max(1, args.repeat - 1))
            print(
                f"{impl_name:<16}{op_name:<10}{our_rate:>11.1f} MiB/s"
                f"{ref_rate:>11.1f} MiB/s{our_rate / ref_rate:>7.0f}x"
            )

    print("\n注：SM2 对照需手工拼装 ZA 与摘要（见 tests/test_cross_fastapiadmin.py），故不列入。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
