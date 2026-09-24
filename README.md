# gmssl-fast

基于 [GmSSL](https://github.com/guanzhi/GmSSL) 的国密算法（SM2 / SM3 / SM4）Python 扩展：
**静态链接、零系统依赖、`pip install` 即用**。

- **只暴露裸格式**：SM2 密文 = 裸 C1C3C2，签名 = 裸 r‖s（64 字节）。与 `sm-crypto`、
  `gm_crypto` 以及既有存量数据一致；DER 只是库内部调用 GmSSL 的实现细节。
- **傻瓜式引用**：曲线参数、ZA 拼装、摘要推导、格式转换、PKCS7 填充、IV 拼接全部在库里，
  业务代码只需要 `import gmssl_fast`。
- **兼容层** `gmssl_fast.compat`：类名与静态方法签名对齐既有 `snowland-smx` 版实现，
  迁移时原来的算法模块可缩成几行 re-export，调用方零改动。
- 安装**不需要** Rust / GCC / CMake / 系统预装 GmSSL（wheel 已静态链接 GmSSL 3.1.1）。

## 安装

```bash
pip install gmssl-fast          # 4 平台 abi3 wheel，Python ≥ 3.8
```

## 快速开始

```python
import gmssl_fast

# --- SM3 ---
gmssl_fast.sm3_hex(b"abc")                       # 64 字符十六进制

# --- 密码（格式 salt$hash，与既有实现逐位一致）---
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

公钥接受 **128**（`X‖Y`）与 **130**（`04‖X‖Y`）两种输入。

### 从 `snowland-smx` / 自研 util 迁移

```python
from gmssl_fast import compat

compat.configure(sm2_public_key=settings.SM2_PUBLIC_KEY, sm4_key=settings.SM4_KEY)

Sm2Cipher = compat.Sm2Cipher
Sm3Cipher = compat.Sm3Cipher
Sm4Cipher = compat.Sm4Cipher
```

之后 `Sm2Cipher.encrypt/decrypt/sign/verify`、`Sm3Cipher.hash/hash_password/verify_password`、
`Sm4Cipher.get_config_key/generate_key/encrypt/decrypt` 的调用方式与原实现**完全一致**。

> `Sm2Cipher.decrypt(private_key, ciphertext)` 的旧签名不带公钥，而 GmSSL 的 PKCS#8 解析
> **必须**同时提供公钥（未暴露「由标量派生公钥」的接口，已实测），因此需要先用
> `compat.configure(sm2_public_key=...)` 注入。`encrypt` / `verify` / `sign` 不受影响。

## 已知行为（务必读）

1. **SM2 加密明文上限 255 字节**（GmSSL 限制）。长数据请用 SM4 对称加密，或用 SM2 加密一个
   对称密钥（信封模式）。
2. **CBC 不提供完整性保护**：用错 IV / 错密钥时不会报错，只会解出垃圾明文。需要完整性请用
   `SM4GCM`（错误时抛 `GmsslAuthError`）。
3. **校验失败会往 stderr 打 `文件:行号:函数():` 前缀的调试输出**：GmSSL 的 `DEBUG` 宏被
   硬编码为 1，库里无法关闭（上游行为）。程序输出不受影响，但如果要捕获 stderr 需注意。
4. **SM4-GCM 只有一次性 API**：加密 N 字节需要约 N 字节额外内存，大文件请分块并自行拼接。
5. **从源码构建需要 CMake**（wheel 不需要）：GmSSL 由 CMake 构建。若本机 CMake ≥ 4.x，
   还需给出策略下限（GmSSL 的 `CMakeLists.txt` 是老写法）：
   ```bash
   GMSSL_CMAKE_DEFINES="-DCMAKE_POLICY_VERSION_MINIMUM=3.5" maturin build --release
   ```

## 性能（本仓库实测）

口径：release 构建、GmSSL 3.1.1（**未启用任何硬件加速**，上游默认全关）、一次性大缓冲；
每项取多次最快值。测试机：macOS 26.5.2 / **x86_64**（Apple Silicon 上的 Rosetta，
CPython 3.9.6）/ 64 MiB 缓冲 / SM2 各 2000 次。

| 操作 | 本库 | 备注 |
|---|---|---|
| SM3 | **158.0 MiB/s** | |
| SM4-CBC | **94.2 MiB/s** | 含 PKCS7 |
| SM4-GCM | **39.5 MiB/s** | |
| SM2 签名 | **1395 ops/s** | 每次调用重新解析 PKCS#8 私钥（含一次 EC 乘法的公钥校验） |
| SM2 验签 | **1583 ops/s** | |

与纯 Python 实现对照（同机、1 MiB 缓冲、两侧同缓冲）：

| 实现 | 操作 | 本库 | 对照 | 倍数 |
|---|---|---|---|---|
| snowland-smx | SM3 | 159.4 MiB/s | 0.3 MiB/s | 562× |
| snowland-smx | SM4-CBC | 95.3 MiB/s | 0.1 MiB/s | 823× |

⚠️ **arm64 数字尚未实测**（本机 Rust 工具链是 Rosetta x86_64），待 CI 在 arm64 runner 上补测。
⚠️ 复现：`python benches/bench.py`；任何对外引用的性能数字都必须来自它。

## 开发

```bash
maturin develop --release            # CMake ≥ 4 需带 GMSSL_CMAKE_DEFINES
pytest -q                            # 含 4 条存量 golden 与双向对拍
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

- 测试分两层：Rust 单测（格式编解码，不需要 Python）与 Python 测试（API、安全门、对拍）。
- `tests/golden.py` 是冻结的存量数据（密文/签名/密码哈希/SM4 块），**任何实现改动都必须让它继续通过**。
- `tests/test_cross_fastapiadmin.py` 与旧库 `snowland-smx` 做双向对拍；未安装该库时整文件跳过
  （`pip install -e '.[test]'`）。

## 许可

Apache-2.0。上游 GmSSL 与 `gmssl-rs` 同为 Apache-2.0。
