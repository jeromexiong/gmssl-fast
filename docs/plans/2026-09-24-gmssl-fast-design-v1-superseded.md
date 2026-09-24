# gmssl-fast 设计（PyO3 + maturin 国密算法库）

日期：2026-09-24
状态：已确认（用户逐节拍板）
位置：`/Users/jerome/Developer/tauri/gmssl-rust-py/`（独立仓库，与 publishKit-desktop 无关）

## 0. 定位与决策摘要

**通用国密算法库，独立发布 PyPI。** 基于 GmSSL 3.2.0 C 内核 + PyO3 绑定，
主打「高性能 + 零依赖安装」（wheel 自带静态链接的 GmSSL，用户端不装任何 C 库）。

| 决策点 | 结论 |
|---|---|
| 算法范围（首版） | SM2 / SM3 / SM4 核心三件套 |
| API 形态 | 现代风格新 API（bytes 进 bytes 出），**不对齐 gmssl-py** |
| wheel 策略 | **abi3（`abi3-py38`），支持 Python 3.8+**，每平台 1 个 whl |
| 平台矩阵 | Linux x86_64（manylinux）/ macOS universal2 / Windows x86_64 |
| 包名 | `gmssl-fast`（模块 `gmssl_fast`）；发布前需在 PyPI 占名 |
| GmSSL 版本 | v3.2.0，git submodule 锁定 tag |

## 1. 项目骨架

```
gmssl-rust-py/
├── .github/workflows/build.yml   # CI 构建 + 测试 + 发布
├── gmssl/                        # GmSSL 源码（submodule，锁定 v3.2.0 tag）
├── src/
│   ├── lib.rs                    # 仅 pymodule 装配（装配不放逻辑）
│   ├── sm2.rs / sm3.rs / sm4.rs  # 各算法 Rust 封装层（参数校验 + 类型转换）
│   └── ffi.rs                    # C 边界声明（唯一 unsafe 集中处）
├── tests/                        # Python 集成测试（GM/T 标准测试向量）
├── benches/                      # 对标 gmssl-py 的基准脚本
├── build.rs                      # 编译 GmSSL C 源 + 静态链接
├── Cargo.toml / pyproject.toml
└── README.md
```

要点：
- `lib.rs` 只做装配，每个算法独立文件——将来加 SM9/ZUC 不搅在一起。
- `tests/` 用国密标准测试向量钉正确性（库的命根子）。
- `benches/`：「高性能」是卖点，必须有数字。
- `crate-type = ["cdylib"]`，PyO3 开 `extension-module` + `abi3-py38`。

## 2. Python API

```python
import gmssl_fast as gm

# SM3 —— hashlib 风格
gm.sm3(b"hello")            # -> bytes(32)
gm.sm3_hex(b"hello")        # -> "66c7f0f4..."
gm.sm3_hmac(key, data)      # HMAC-SM3 -> bytes(32)

# SM4 —— 类风格
sm4 = gm.SM4(key, mode="cbc", iv=iv)   # mode: "cbc" | "ecb" | "gcm"
sm4.encrypt(b"...")         # 自动 PKCS7 填充（GCM 除外）-> bytes
sm4.decrypt(b"...")         # 自动去填充
sm4_gcm.encrypt(b"...")     # GCM 返回 (ciphertext, tag)

# SM2 —— 密钥对象风格，签名默认「SM2 with SM3」国标套件
sk = gm.SM2PrivateKey.from_hex(d)      # 或 gm.SM2PrivateKey.generate()
pk = sk.public_key()                   # 未压缩 04||X||Y 点
sig = sk.sign(msg)                     # 内部做 ZA 签名者标识杂凑（默认 ID，可传参覆盖）
ok  = pk.verify(msg, sig)
ct  = pk.encrypt(b"...")               # C1C3C2 密文序（国标 2016 默认）
pt  = sk.decrypt(ct)
```

约定：
- **错误即异常**：长度/格式错抛 `ValueError` 子类（`gm.GmsslError` 等），
  FFI 边界在 Rust 侧把 C 返回值翻译成 Python 异常，绝不返回错误码。
- **bytes 进 bytes 出**；hex 只出现在显式命名（`_hex` 后缀/from_hex），不隐式猜编码。
- 不做文件/PEM I/O（YAGNI，序列化让用户用 `cryptography` 自理）。

## 3. 构建链路与 FFI 边界

**核心风险：GmSSL 不是为单文件挑选编译设计的。** `sm2.c` 依赖 `sm3.c`、`bn.c`（大数）、
`asn1.c` 等一串内部文件。对策：

- **build.rs 维护显式文件清单**（不做 `glob("*.c")` 全量编译——会拖进 TLS/协议代码，
  Windows 上还可能撞汇编文件）。SM2 需要 `sm2_lib.c`/`sm2_sign.c`/`sm2_enc.c`/`sm2_zca.c`
  + `sm3.c` + `bn.c` + `asn1.c`/`rand.c`/`hex.c`/`endian.c` 等，首次打通按编译器
  报错逐个补；清单写在 build.rs 顶部并注释「为什么需要它」。
- `cc` 开 `-std=c99`；Windows 走 MSVC（maturin-action 默认），遇不兼容逐个打补丁。
- `println!("cargo:rerun-if-changed=gmssl/src")`；产出静态库 `libgmssl.a` 全链入 wheel。
- **unsafe 只许出现在 `src/ffi.rs` 与各算法模块的 3~5 行调用点**；长度校验、
  PKCS7 填充、hex 编解码全在安全 Rust 做，C 层只见裸指针和定长缓冲。
- ⚠️ **上下文结构体不用 `[u8; 1024]` 瞎猜大小**（方案一原稿写法，是缓冲区溢出隐患）：
  用 `MaybeUninit` + 头文件实测 `sizeof`，或直接把 `SM3_CTX` 等结构 FFI 化。
- **绝不 panic 穿越 FFI**：`#[pyfunction]` 内不 `unwrap()`。

**测试**：`tests/` 跑 GM/T 0004（SM3）、0002（SM4）、0003（SM2）标准向量 +
与 `gmssl-py` 交叉比对；Rust 单测只测填充/hex 等纯逻辑。

## 4. CI/CD、发布与文档

两条流水（`.github/workflows/build.yml`）：

1. **PR 流水**：`ubuntu-latest` 上 `maturin develop` + `pytest` + `cargo clippy`
   + `cargo fmt --check`——正确性门禁不依赖全平台矩阵，快且便宜。
2. **Release 流水**（`v*` tag 触发）：`ubuntu-latest`（manylinux x86_64）/
   `macos-latest`（universal2）/ `windows-latest`（x86_64），abi3 → 共 3 个 whl。
   每平台构建完先跑测试再上传；最后 `pypa/gh-action-pypi-publish` 上 PyPI。
   `actions/checkout` 必须 `submodules: recursive`。

发布流程（维护者）：`maturin develop` 调试 → 改版本号（Cargo.toml + pyproject.toml）
→ `git tag v0.1.0 && git push origin v0.1.0` → CI 约 15 分钟出包上架。
- `PYPI_API_TOKEN` 进 GitHub Secrets；**先走 TestPyPI 全流程再切正式源**。
- 首次发布前在 PyPI 占名 `gmssl-fast`。

文档：README 含安装、三算法速查示例、与 gmssl-py 差异说明、基准数字表；
类型标注随包发布（`py.typed` + `.pyi`）。

## 5. 协作者使用（零编译）

```bash
pip install gmssl-fast
```

不需要 Rust / GCC / GmSSL——wheel 自带全部二进制依赖。

## 6. 对方案一原稿的修正记录

| 方案一原稿 | 本设计 | 原因 |
|---|---|---|
| build.rs 挑 6 个 C 文件 | 显式清单 + 按报错补全（SM2 依赖链） | 挑编译到 SM2 必断 |
| `[u8; 1024]` 当 SM3_CTX | `MaybeUninit` + 实测 sizeof / 结构 FFI 化 | 缓冲区溢出隐患 |
| 逐版本出 15 个 whl | abi3，3 个 whl | 维护成本与体验 |
| 错误码/无异常规范 | 统一异常 + bytes 进出 | API 易用性 |
| CI 矩阵 3 OS × 5 Python | 3 平台 × abi3，PR 只跑 Linux | 快且够 |
