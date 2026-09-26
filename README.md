# gmssl-fast

基于 [GmSSL](https://github.com/guanzhi/GmSSL) 的国密算法（SM2 / SM3 / SM4）Python 扩展：
**静态链接、零系统依赖、`pip install` 即用** —— 安装不需要 Rust / GCC / CMake，也不需要预装 GmSSL。

- **只暴露裸格式**：SM2 密文 = 裸 C1C3C2，签名 = 裸 `r‖s`（64 字节）。曲线参数、ZA 拼装、
  摘要推导、格式转换、PKCS7 填充、IV 拼接全部在库里，业务代码只需 `import gmssl_fast`。
- **兼容层** `gmssl_fast.compat`：类名与静态方法签名对齐存量 `snowland-smx` 版实现，
  迁移时把原算法模块缩成几行 re-export 即可，调用方零改动。

## 安装

```bash
pip install gmssl-fast          # abi3 wheel（cp38+），Python ≥ 3.8
```

CI 产出 **8 个 wheel**，全部原生构建，且每个轮子都经过「装真轮子 + 跑完整测试」验证：

| 平台 | 架构 / libc |
|---|---|
| Linux | x86_64、aarch64（各含 glibc 与 musl 两套） |
| macOS | arm64、x86_64 |
| Windows | x64、arm64 |

其他平台走源码安装：`pip install gmssl-fast` 会从 sdist 用 Rust + CMake 现场构建
（要求 CMake ≥ 3.6）。注意 glibc 基线是 **2.28**（CentOS 8 / Ubuntu 18.10 起），
更老的发行版（如 CentOS 7）请用源码安装。

## 快速开始

```python
import gmssl_fast

# --- SM3 ---
gmssl_fast.sm3_hex(b"abc")                       # 64 字符十六进制

# --- 密码（格式 salt$hash）---
stored = gmssl_fast.sm3_password_hash("admin123")
gmssl_fast.sm3_password_verify("admin123", stored)   # True

# --- SM4-CBC（返回 iv(16)‖ciphertext）---
key = bytes.fromhex("0123456789abcdeffedcba9876543210")
sm4 = gmssl_fast.SM4(key, mode="cbc")            # 也可 mode="ctr" / "ecb"
blob = sm4.encrypt(b"hello")
sm4.decrypt(blob)                                # b"hello"

# --- SM4-GCM（带完整性校验）---
gcm = gmssl_fast.SM4GCM(key, b"\x00" * 12)       # nonce 强制 12 字节
ciphertext, tag = gcm.encrypt(b"hello")          # tag 固定 16 字节
gcm.decrypt(ciphertext, tag)                     # 失败抛 GmsslAuthError

# --- SM2 ---
pair = gmssl_fast.SM2.generate()
sm2 = gmssl_fast.SM2(private_key=pair.private_key_hex, public_key=pair.public_key_hex)
ciphertext = sm2.encrypt(b"short")               # 明文上限 255 字节
sm2.decrypt(ciphertext)                          # b"short"
signature = sm2.sign(b"message")                 # 64 字节裸 r‖s
sm2.verify(b"message", signature)                # True
```

公钥接受 **128**（`X‖Y`）与 **130**（`04‖X‖Y`）两种输入；只给私钥时库会自行派生公钥。

## 已知行为（务必读）

1. **SM2 加密明文上限 255 字节**：这是 **GmSSL API 的限制**（`SM2_CIPHERTEXT` 用固定缓冲
   `uint8_t ciphertext[255]`），**不是裸 C1C3C2 格式的限制**。长数据请用 SM4，或先用 SM2
   加密一个对称密钥（信封模式）。
2. **CBC 不提供完整性保护**：错 IV / 错密钥不会报错，只会解出垃圾明文。需要完整性请用
   `SM4GCM`（失败时抛 `GmsslAuthError`）。
3. **校验失败会往 stderr 打印调试信息**：GmSSL 的 `DEBUG` 宏硬编码为 1，库里无法关闭
   （上游行为）。stdout 不受影响，但捕获 stderr 时需注意。
4. **Windows 轮子用 `/FORCE:UNRESOLVED` 链接**：上游 `gmssl-rs` 0.1.1 声明了两个 GmSSL
   3.2.0 才有的符号，而它依赖的 `gmssl-rs-sys` 构建的是 3.1.1（详见 `build.rs`）。代价是
   「真缺符号」改为运行期才崩，因此每个轮子都在 CI 上做安装 + 全量测试兜底。
5. **源码构建需要 CMake ≥ 3.6**（wheel 不需要）。GmSSL 3.1.1 的
   `cmake_minimum_required(VERSION 3.6)` 在 CMake 4.x 下同样合法（已在 CMake 4.4.3 实测）。

## 从其他实现迁移

```python
from gmssl_fast import compat

compat.configure(sm2_public_key=settings.SM2_PUBLIC_KEY, sm4_key=settings.SM4_KEY)

Sm2Cipher = compat.Sm2Cipher
Sm3Cipher = compat.Sm3Cipher
Sm4Cipher = compat.Sm4Cipher
```

之后 `Sm2Cipher.encrypt/decrypt/sign/verify`、`Sm3Cipher.hash/hash_password/verify_password`、
`Sm4Cipher.get_config_key/generate_key/encrypt/decrypt` 的调用方式与原实现一致。

> `Sm2Cipher.decrypt(private_key, ciphertext)` 的旧签名不带公钥，而 GmSSL 解析 PKCS#8
> **必须**同时提供公钥，因此需要先用 `compat.configure(sm2_public_key=...)` 注入。
> 该调用是**可选**的：不注入时库会用私钥自行派生公钥，注入只是省掉一次 EC 乘法。

## 性能

口径：release 构建、GmSSL 3.1.1（**未启用任何硬件加速**，上游默认全关）、一次性大缓冲、
每项取多次最快值。测试机为 **x86_64**（Apple Silicon 上的 Rosetta，CPython 3.9.6）。

| 操作 | 吞吐 |
|---|---|
| SM3 | 158.8 MiB/s |
| SM4-CBC | 93.6 MiB/s |
| SM4-GCM | 39.6 MiB/s |
| SM2 签名 / 验签 | 2528 / 1588 ops/s |

SM2 的密钥只解析一次并缓存（`Sm2KeyHandle`），因此已追平 C 层基线。
arm64 数字尚未实测。复现：`python benches/bench.py`；**任何对外引用的性能数字都必须来自它**。

## 维护者信息

**上游补丁**：`Cargo.toml` 用 `[patch.crates-io]` 钉住一份回移了 Windows 修复的 `gmssl-rs`
副本（<https://github.com/jeromexiong/gmssl-rs-patched>）——上游 `main` 已修好但**未发版**，
crates.io 上仍是修复前的版本，Windows 下编不过。该副本保持 **GmSSL 3.1.1**、源码随 crate
分发（构建不下载 GmSSL、不需要 submodule），只有 `build.rs` / `pem_helpers.rs` 两个文件与
crates.io 字节不同。上游一发新版就能撤掉：删掉 `[patch.crates-io]` 段，再
`cargo update -p gmssl-rs -p gmssl-rs-sys`。

**开发**：

```bash
maturin develop --release
pytest -q                            # 含存量 golden 与与旧库的双向对拍
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
python scripts/lint_test_asserts.py  # 断言不得依赖概率（CI 也在跑）
```

- **测试断言规则（硬规则）**：随机性（盐 / IV / 临时密钥）只能**注入**后断言，字节级契约
  只对**固定向量**（`GOLDEN_*`）断言。禁止「两次随机值不相等」这类**概率断言**——它们会让
  CI 的红变得随机。`scripts/lint_test_asserts.py` 会机械检查。
- 测试分两层：Rust 单测（格式编解码，不需要 Python）与 Python 测试（API、安全门、对拍）。
- `tests/golden.py` 是冻结的存量数据（密文 / 签名 / 密码哈希 / SM4 块），**任何实现改动都
  必须让它继续通过**。
- `tests/test_cross_legacy.py` 与旧库 `snowland-smx` 做双向对拍；未安装该库时整文件跳过
  （`pip install -e '.[test]'`）。

## 许可

Apache-2.0。上游 GmSSL 与 `gmssl-rs` 同为 Apache-2.0。
