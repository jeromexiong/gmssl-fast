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
pip install gmssl-fast          # abi3 wheel，Python ≥ 3.8
```

已实测产出 wheel 的平台（CI，共 5 个）：**Linux x86_64（manylinux）、Linux x86_64（musl）、
macOS arm64、macOS x86_64、Windows x86_64（MSVC）**。

⚠️ **Linux aarch64（ARM 服务器）暂未提供**：试过一腿，但失败原因是 CI 侧没有 binfmt/qemu
（在 x86_64 runner 上构建 aarch64 需要它），**不是 GmSSL 编译问题**；两种修法已写在
`.github/workflows/build.yml` 的注释里，落地后即可补上。在此之前 ARM 服务器需源码安装
（需 Rust + CMake）。

### Windows 是怎么拿下的

上游 `gmssl-rs-sys` **0.1.0** 在 MSVC 下构建不过，硬伤有两处：

1. GmSSL 的 `api.h` / `socket.h` / `dylib.h` 用 `#ifdef WIN32`，而 MSVC 只预定义 `_WIN32`。
   CMake 的 `Windows-MSVC` 平台模块本会补 `/DWIN32`，但 `cmake-rs` 覆盖
   `CMAKE_C_FLAGS(_RELEASE)` 时把它顶掉了 → 代码走 POSIX 分支 → `C1083: 缺 dlfcn.h / netdb.h`。
2. GmSSL 的 `CMakeLists.txt` 硬编码 `CMAKE_INSTALL_PREFIX="C:/Program Files/GmSSL"`，
   而 VS 是多配置生成器（库落在 `lib/Release/`），0.1.0 的 `build.rs` 只认 `dst/lib`。

上游 `GmSSL/gmssl-rs@main` 已经把这两处都修好了（`cflag("-DWIN32")`、构建时打补丁改
CMakeLists、`find_lib_dir`、`pem_helpers.rs` 的 `#[cfg(windows)]` + `tmpfile`），**但没有发版**：
crates.io 上 `gmssl-rs-sys` 至今只有 0.1.0、`gmssl-rs` 只有 0.1.1（都发布于 2026-05-31，早于修复）。
因此本项目用 `[patch.crates-io]` 钉住一份把这两处回移好的副本：

<https://github.com/jeromexiong/gmssl-rs-patched>（按上游仓库布局：`gmssl/` + `gmssl-sys/`，
后者是前者的 path 依赖 ⇒ **一条 patch 就够**；rev 写死在 `Cargo.toml`，并由 `Cargo.lock` +
`--locked` 锁住）。该副本只有那两个文件与 crates.io 字节不同，且保持 **GmSSL 3.1.1**、源码随
crate 一起分发 ⇒ **API/ABI 与本机已验证的版本逐字节一致**，构建也**不会下载 GmSSL、不需要
submodule**（联网只为了取这份 crate 本身）。

> 上游一发新版就能撤掉：删 `Cargo.toml` 里的 `[patch.crates-io]` 段，再
> `cargo update -p gmssl-rs -p gmssl-rs-sys`。

除 `build.rs` 那两处外，Windows 还多踩了一个**上游 crates.io 组合不自洽**的坑：`gmssl-rs`
0.1.1 声明了两个 **GmSSL 3.2.0 才有**的符号（`x509_key_cleanup`、
`zuc256_generate_keystream`，后者在 3.1.1 里只是 `zuc.h` 的一个宏），而它依赖的
`gmssl-rs-sys` 0.1.0 构建的是 **3.1.1**。macOS/Linux 上静态库按需取成员、恰好没拉到那两个
CGU，MSVC 下则直接 `LNK2019 → LNK1120`。本库不暴露 X509/ZUC，这两个符号不会被调用，
所以在 `build.rs` 里加了 `/FORCE:UNRESOLVED` 放行 —— ⚠️ 代价是真缺符号时改为**调用期**才崩，
因此 CI 的 Windows 腿会「装真轮子 + 跑完整 pytest」在运行期兜底（不能只靠链接参数自证）。

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
> `compat.configure(sm2_public_key=...)` 注入（**可选**：不注入时库会用私钥自行派生公钥，
> 注入只是省掉那次 EC 乘法）。`encrypt` / `verify` / `sign` 不受影响。

## 已知行为（务必读）

1. **SM2 加密明文上限 255 字节**：这是 **GmSSL API 的限制**（它的 `SM2_CIPHERTEXT` 用固定
   缓冲 `uint8_t ciphertext[255]`），**不是裸 C1C3C2 格式的限制** —— 纯 Python 实现（如
   `pysmx`）不受此限。长数据请用 SM4 对称加密，或用 SM2 加密一个对称密钥（信封模式）。
2. **CBC 不提供完整性保护**：用错 IV / 错密钥时不会报错，只会解出垃圾明文。需要完整性请用
   `SM4GCM`（错误时抛 `GmsslAuthError`）。
3. **校验失败会往 stderr 打 `文件:行号:函数():` 前缀的调试输出**：GmSSL 的 `DEBUG` 宏被
   硬编码为 1，库里无法关闭（上游行为）。程序输出不受影响，但如果要捕获 stderr 需注意。
4. **SM4-GCM 只有一次性 API**：加密 N 字节需要约 N 字节额外内存，大文件请分块并自行拼接。
5. **从源码构建需要 CMake ≥ 3.6**（wheel 不需要）：GmSSL 由 CMake 构建。
   环境变量 `GMSSL_CMAKE_DEFINES` 是上游留的透传通道，**当前不需要用**——GmSSL 3.1.1 的
   `cmake_minimum_required(VERSION 3.6)` 在 CMake 4.x 下同样合法。真要用它时写法是
   `KEY=value`（库会自己加 `-D`），多写一个 `-D` 只会得到 `-DKEY` 这种假变量。

## 性能（本仓库实测）

口径：release 构建、GmSSL 3.1.1（**未启用任何硬件加速**，上游默认全关）、一次性大缓冲；
每项取多次最快值。测试机：macOS 26.5.2 / **x86_64**（Apple Silicon 上的 Rosetta，
CPython 3.9.6）/ 64 MiB 缓冲 / SM2 各 2000 次。

| 操作 | 本库 | 备注 |
|---|---|---|
| SM3 | **158.8 MiB/s** | |
| SM4-CBC | **93.6 MiB/s** | 含 PKCS7 |
| SM4-GCM | **39.6 MiB/s** | |
| SM2 签名 | **2528 ops/s** | 密钥只解析一次（句柄缓存），已追平 C 层基线 |
| SM2 验签 | **1588 ops/s** | |

与纯 Python 实现（`snowland-smx`，就是既有 `sm_crypto.py` 用的那个）同条件对照：
吞吐两侧同用 1 MiB 缓冲，SM2 两侧同用 100 次、同一条消息（ZA/摘要开销计在签名里）。

| 操作 | 本库 | snowland-smx | 倍数 |
|---|---|---|---|
| SM3（每 MiB） | 158.98 MiB/s | 0.29 MiB/s | **557×** |
| SM4-CBC（每 MiB） | 94.77 MiB/s | 0.12 MiB/s | **819×** |
| SM2 签名 | 2512 ops/s | 314 ops/s | **8.0×** |
| SM2 验签 | 1580 ops/s | 162 ops/s | **9.7×** |

⚠️ **别把吞吐的倍数套到 SM2 上**：SM3/SM4 差三个数量级是因为纯 Python 逐块跑 Python 循环；
SM2 的瓶颈是椭圆曲线运算（Python 用大整数算，本来就不算慢），所以只差 **8.0× / 9.7×**。
而且 `snowland-smx` 的 314 ops/s 对「每请求一次签名」这种负载**完全够用**。

⚠️ **SM2 签名已经优化过一轮**：早期版本每次调用都重建 PKCS#8 私钥（GmSSL 解析时会
校验公钥字段与标量是否匹配，那是一次额外的 EC 乘法），只有 1395 ops/s。
现在密钥只解析一次并缓存在句柄里（`gmssl_fast._core.Sm2KeyHandle`，`SM2` 实例与
`compat` 各自缓存），**2528 ops/s，已追平 C 层基线**。

⚠️ **所以这次迁移的收益不只是性能**：

1. 接口彻底傻瓜化（曲线常数 / ZA 拼装 / 摘要 / 格式转换 / PKCS7 / IV 全在库里）；
2. 安全门（GCM tag 长度硬编码 16、nonce 强制 12 字节——GmSSL 自己不校验这两个长度）；
3. 少维护约 470 行易错代码（老的 `_strip_04`、两候选试解、10 次重试那套坑，现在由测试锁住）。

⚠️ **arm64 的性能数字尚未实测**：arm64 wheel 已由 CI 产出（可安装可用），但 `benches/bench.py`
只在 Rosetta x86_64 上跑过，要在 README 引用 arm64 数字得先在 arm64 上跑一次。
⚠️ 复现：`python benches/bench.py`；任何对外引用的性能数字都必须来自它。

## 开发

```bash
maturin develop --release
pytest -q                            # 含 4 条存量 golden 与双向对拍
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
python scripts/lint_test_asserts.py  # 断言不得依赖概率（CI 也在跑）
```

- **测试断言规则（硬规则）**：随机性（盐 / IV / 临时密钥）只能 **注入**（`monkeypatch`）
  后断言，字节级契约只对**固定向量**（`GOLDEN_*`）断言。因此禁止
  「两次随机值不相等」「随机密文的首字节不是 0x30」这类**概率断言**——
  它们会让 CI 的红变得随机（这个坑真踩过：1/256 级，详见设计文档 §7）。
  `scripts/lint_test_asserts.py` 会机械检查，测试里不允许出现。

- 测试分两层：Rust 单测（格式编解码，不需要 Python）与 Python 测试（API、安全门、对拍）。
- `tests/golden.py` 是冻结的存量数据（密文/签名/密码哈希/SM4 块），**任何实现改动都必须让它继续通过**。
- `tests/test_cross_fastapiadmin.py` 与旧库 `snowland-smx` 做双向对拍；未安装该库时整文件跳过
  （`pip install -e '.[test]'`）。

## 许可

Apache-2.0。上游 GmSSL 与 `gmssl-rs` 同为 Apache-2.0。
