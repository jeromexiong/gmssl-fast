#!/usr/bin/env python3
"""静态检查：测试里的断言不得依赖概率。

背景（真实踩过）：CI 上 `assert_ne!(raw[0], 0x30)` 假失败——裸格式 x 坐标首字节**本身**
就有约 1/256 的概率等于 0x30（8000 次采样实测 0.537%）。同类还有「两次随机盐不同」
「IV 不是全零」这种 2⁻¹²⁸ 级断言。**只要断言里有一处非零概率，CI 的红就是随机的。**

规则：

- **R1**：`assert` 行里出现字节字面量（`0x30`、`b"\\x5a"`、`\\x..`）时，同行必须出现
  `GOLDEN_`——即「字节级契约只对**固定向量**断言」。随机产生的值只能断言不变量
  （长度 / 往返 / 互相验证）。
- **R2**：禁止把两个「会随机的产生式」互相比较（如
  `assert hash_pw("x") != hash_pw("x")`）。这类行为要用 `monkeypatch` **注入**随机源后断言。
- **Rust 侧**只检查「调用 GmSSL 随机运算」的文件（`sm2_encrypt` / `sm2_sign` /
  `Sm2Key::generate`）；纯 DER 编解码（`sm2_fmt.rs`）输入固定，允许直接断言字节。

用法::

    python scripts/lint_test_asserts.py          # 默认检查 tests/ 与 src/
    python scripts/lint_test_asserts.py tests src

退出码：0 = 干净，1 = 有违规（逐条打印 file:line）。
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# 字节字面量：0x30 / 0x04 / \x5a
BYTE_LITERAL = re.compile(r"0x[0-9a-fA-F]{2}|\\x[0-9a-fA-F]{2}")
FIXED_VECTOR = re.compile(r"golden_", re.IGNORECASE)
# 「会产生随机输出」的调用（Python 侧）
RANDOM_PRODUCER = re.compile(
    r"sm3_password_hash\(|generate_salt\(|generate_key\(|\.encrypt\(|\.sign\(|"
    r"SM2\.generate\(|token_hex\(|token_bytes\("
)
# Rust 侧：只有测试模块里调了这些才涉及随机性
RUST_RANDOM = re.compile(r"sm2_encrypt|sm2_sign\(|Sm2Key::generate|Sm2Signer::sign\(")
COMPARISON = re.compile(r"!==|==|!=")


def _comparison_sides(line: str) -> tuple[str, str] | None:
    """把 assert 行按比较运算符切开，返回左右两侧（取最后一个运算符）。"""
    matches = list(COMPARISON.finditer(line))
    if not matches:
        return None
    last = matches[-1]
    return line[: last.start()], line[last.end() :]


def _check_python(path: Path) -> list[str]:
    problems: list[str] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if "assert" not in line:
            continue
        if BYTE_LITERAL.search(line) and not FIXED_VECTOR.search(line):
            problems.append(
                f"{path}:{lineno}: R1 断言了字节取值但没引用固定向量（GOLDEN_*）——"
                f"随机产生的值只允许断言不变量：{line.strip()}"
            )
        sides = _comparison_sides(line)
        if sides and all(RANDOM_PRODUCER.search(side) for side in sides):
            problems.append(
                f"{path}:{lineno}: R2 拿两个会随机的产生式互相比较（概率断言）——"
                f"请用 monkeypatch 注入随机源：{line.strip()}"
            )
    return problems


def _check_rust(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    # 只看测试模块内部：模块文档里提到 sm2_sign_xxx / sm2_ciphertext_to_der 这类**名字**
    # 不算「测试调了随机运算」（否则 sm2_fmt.rs 手工构造 DER 的固定输入断言会被误判）。
    marker = text.find("#[cfg(test)]")
    if marker < 0:
        return []
    region = text[marker:]
    if not RUST_RANDOM.search(region):
        return []  # 该文件的测试不消费 GmSSL 的随机输出 → 允许直接断言字节
    problems: list[str] = []
    for offset, line in enumerate(region.splitlines(), 1):
        lineno = text[:marker].count("\n") + offset
        if "assert" not in line:
            continue
        if BYTE_LITERAL.search(line) and not FIXED_VECTOR.search(line):
            problems.append(
                f"{path}:{lineno}: R1 断言了字节取值但没引用固定向量（GOLDEN_*）：{line.strip()}"
            )
    return problems


def main(argv: list[str]) -> int:
    roots = [Path(arg) for arg in argv[1:]] or [Path("tests"), Path("src")]
    problems: list[str] = []
    for root in roots:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.py")):
            if path.name.startswith("_"):
                continue
            problems.extend(_check_python(path))
        for path in sorted(root.rglob("*.rs")):
            problems.extend(_check_rust(path))

    for problem in problems:
        print(problem)
    if problems:
        print(f"\n共 {len(problems)} 处概率断言。规则见本脚本头部注释。")
        return 1
    print("断言概率检查通过：没有依赖随机性的断言。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
