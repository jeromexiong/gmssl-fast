# gmssl-fast 设计（v2：基于官方 gmssl-rs）

日期：2026-09-24
状态：已确认（用户逐节拍板；v1 的"自建 FFI"路线已废弃，见 §9）
仓库：`/Users/jerome/Developer/tauri/gmssl-fast/`（独立仓库，与 publishKit-desktop 无关）

## 0. 决策摘要

| 决策点 | 结论 |
|---|---|
| 定位 | **通用国密算法轮子**，独立发 PyPI；FastAPI 集成属消费方职责，不进库 |
| 国密内核 | **`gmssl-rs = "0.1.1"`（crates.io）→ `gmssl-rs-sys 0.1.0` → vendored GmSSL 3.1.1** |
| 算法范围 | SM2 + SM3 + SM4（CBC / CTR / GCM / **ECB**）；不暴露 SM9 / ZUC / X.509 |
| SM4-ECB | 上游无封装，用 `Sm4Key::encrypt_block` 自拼 + 自管 PKCS7（纯安全 Rust，无 unsafe） |
| SM4-GCM | **只提供一次性 API**（上游未暴露流式），文档写明内存占用 |
| wheel | **abi3-py38**，4 个包：`manylinux_2_28_x86_64` / `macosx arm64` / `macosx x86_64` / `win_amd64` |
| 工具链 | pyo3 0.29.x（MSRV Rust 1.83）、maturin 1.15.x、CMake（构建前置） |
| 包名 | `gmssl-fast`（PyPI 未占用，HTTP 404，发布前占名）；模块 `gmssl_fast` |

## 1. 依赖链与版本锚点（已实测核实）

```
gmssl-fast（本项目，PyO3 扩展）
└── gmssl-rs 0.1.1        crates.io，owner = guanzhi（GmSSL 作者本人），Apache-2.0
    └── gmssl-rs-sys 0.1.0   links = "gmssl"；build-dep = cmake 0.1
        └── GmSSL 3.1.1      **vendored 源码（3MB）随 .crate 分发**
```

要点：
- **不是** crates.io 上那个第三方 `gmssl-sys`（`acovo/rust-gmssl` 的 GmSSL 2.x 绑定，2023 年停更）——两者名字接近，极易混淆。
- `.crate` 自带 GmSSL 源码 → **构建期不需要访问 github.com**（实测日志里 `Downloading GmSSL` 计数 = 0）。
- `gmssl-rs-sys` 只在源码缺失时才 `curl` 下载 tarball（走 git 依赖时 cargo 会先递归拉子模块，那条兜底路径不可达）。
- 上游 `gmssl-rs 0.1.1` 自身带 **59 个 `#[test]`**。
- ⚠️ docs.rs 走 `DOCS_RS` 早退分支、**不真正编译链接 C 库** → "docs.rs 有文档"不等于"能编过"，必须以 CI 实测为准。
- ⚠️ **CMake 4.x 兼容**：GmSSL 的 CMakeLists 仍是老式 `cmake_minimum_required` 写法，CMake ≥ 4 会直接报错。构建时必须传
  `GMSSL_CMAKE_DEFINES="-DCMAKE_POLICY_VERSION_MINIMUM=3.5"`（`gmssl-rs-sys` 支持该环境变量透传，实测有效）。
- ⚠️ `ENABLE_SM2_PRIVATE_KEY_EXPORT` 默认 OFF，不开就缺 `sm2_private_key_info_from_pem/to_pem`；上游 build.rs 已强制 ON，无需我们处理（但要记住这条依赖）。

## 2. 上游已知问题与我们的对策

全部来自实测或源码复核：

| 上游问题 | 影响 | 我们的对策 |
|---|---|---|
| **GCM `taglen` 只校验上界、不校验下界**（`sm4_modes.c`：`if (taglen > MAX) return -1;` 之后 `memcmp(T, tag, taglen)`），实测传 8B tag 即返回 Ok | 若把 tag 长度暴露给调用方，1 字节 tag ≈ 1/256 伪造，AEAD 完整性被击穿 | **Python API 硬编码 `taglen = 16`，绝不暴露该参数**；并在测试里钉死 |
| **GCM `ivlen` 不校验**（实测 1 / 8 / 16 字节都 Ok） | IV 复用 / 非标准 J0 推导 / 跨库不互通 | 绑定层**强制 12 字节** IV，其它长度直接 `ValueError` |
| **CBC 无完整性**：错误 IV 解密返回 Ok（垃圾明文） | 用户可能误以为"解密成功 = 数据可信" | 文档明写"要完整性请用 GCM"；测试固化该行为 |
| **`#define DEBUG 1` 硬编码**（`include/gmssl/error.h`），错误直接 `fprintf(stderr, "file:line:func():")`，无运行时开关 | 校验失败会污染宿主进程 stderr（FastAPI 日志里冒 `sm4_modes.c:191:...`） | **已知瑕疵**：crates.io 依赖是只读的，无法关；写进 README「已知行为」。若未来必须消除，只能走 §9 的 vendor 路线改这一行 |
| SM2 加密明文 **≤ 255 字节**，密文是 **DER 编码**（首字节 0x30；255B 明文 → 364B 密文） | 拿 SM2 加密长数据会失败；密文与"裸 C1C3C2"不互通 | API 文档写明 255B 上限与 DER 格式；异常消息明确 |
| `sm2_encrypt` 内部有绕 GmSSL `*outlen=0` 回绕的补丁 | 已由上游处理 | 无需动作，仅记录 |
| 上游为**单人维护**、仓库新（首个版本 2026-05-31）、下载量低 | 停更/跑路风险 | 见 §9 的 vendor 预案（R3），切换成本低 |

## 3. 项目骨架

```
gmssl-fast/
├── .github/workflows/build.yml   # PR 流水 + Release 流水
├── Cargo.toml                    # pyo3 + gmssl-rs；crate-type = ["cdylib"]
├── Cargo.lock                    # 必须提交（--locked 构建，保证可复现）
├── pyproject.toml                # maturin 后端 + 包元数据
├── README.md                     # 安装 / 速查示例 / 已知行为 / 基准数字
├── docs/plans/                   # 本设计文档
├── src/
│   ├── lib.rs                    # 只做 pymodule 装配（不放逻辑）
│   ├── errors.rs                 # GmsslError → Python 异常映射（唯一映射点）
│   ├── sm2.rs / sm3.rs / sm4.rs  # 各算法封装：参数校验 + 类型转换
│   └── gmssl_fast.pyi + py.typed # 类型标注随包发布
├── tests/                        # Python 集成测试（GM/T 标准向量 + 边界）
└── benches/                      # 对标 gmssl-rs 裸调用 / 纯 Python 的基准脚本
```

## 4. Python API

```python
import gmssl_fast as gm

# SM3 —— hashlib 风格
gm.sm3(b"hello")                    # -> bytes(32)
gm.sm3_hex(b"hello")                # -> "66c7f0f4..."
gm.sm3_hmac(key, data)              # HMAC-SM3 -> bytes(32)
gm.sm3_pbkdf2(password, salt, iterations, dklen)   # -> bytes

# SM4 —— 类风格
sm4 = gm.SM4(key, mode="cbc", iv=iv)  # "cbc" | "ctr" | "gcm" | "ecb"
sm4.encrypt(b"...")                   # CBC/ECB 自动 PKCS7；CTR 无填充
sm4.decrypt(b"...")                   # CBC/ECB 自动去填充
gcm = gm.SM4GCM(key, nonce)           # nonce 强制 12 字节
ct, tag = gcm.encrypt(plaintext, aad=b"")   # tag 固定 16 字节，不暴露长度参数
pt = gcm.decrypt(ct, tag, aad=b"")          # 失败抛 GmsslAuthError

# SM2 —— 密钥对象风格
sk = gm.SM2PrivateKey.from_pem(pem)   # 或 .generate()
pk = sk.public_key()
sig = sk.sign(msg)                    # 内部做 ZA 杂凑，默认 ID "1234567812345678"，可传 id=
ok  = pk.verify(msg, sig)             # -> bool
ct  = pk.encrypt(b"...")              # 明文 ≤ 255 字节；DER 密文
pt  = sk.decrypt(ct)
```

约定：
- **错误即异常**：`GmsslError(Exception)` 为基类，下分 `GmsslValueError(ValueError)` /
  `GmsslAuthError`（GCM tag 校验失败）/ `GmsslVerificationError`。FFI 的 C 返回值
  在 Rust 侧翻译成异常，**绝不返回错误码**。
  （注意：上游 `GmsslError` 只有 `LibraryError(&'static str)` 这类粗粒度变体，
  拿不到 reason code，所以异常消息会比较泛化——这是上游限制。）
- **bytes 进 bytes 出**；hex 只出现在显式命名（`_hex` 后缀 / `from_pem`）。
- **不暴露的参数**：GCM 的 tag 长度（固定 16）、GCM 的 IV 长度（固定 12）。
- 不做文件 / 磁盘 PEM IO（YAGNI；上游有 `*_file` 方法但我们不包）。

## 5. 构建与 wheel 策略

- `pyo3 = { version = "0.29", features = ["extension-module", "abi3-py38"] }`
  （abi3-py38 在 0.29.2 仍受支持，目标到 abi3-py315）→ **每平台 1 个 whl**。
- `crate-type = ["cdylib"]`；Python 3.8+。
- 构建前置：**Rust 1.83+ / C 编译器 / CMake**。wheel 使用者三者都不需要。
- 环境变量链（写进 CI 与本地文档）：
  ```bash
  GMSSL_CMAKE_DEFINES="-DCMAKE_POLICY_VERSION_MINIMUM=3.5" maturin build --release --locked
  ```
- macOS 出**两个独立 wheel**（arm64 / x86_64），不做 universal2：GmSSL 是 C 代码，
  universal2 要求 CMake 同时按两架构编译（`cmake` crate 不会自动传
  `CMAKE_OSX_ARCHITECTURES`），是已知坑，收益只是少一个包。
- ⚠️ **CI 风险点（首个 PR 就要验证）**：maturin-action 的 manylinux 容器里是否有
  `cmake`；若无，需要在 `before-script-linux` 里 `yum/dnf install -y cmake`。

## 6. CI/CD

1. **PR 流水**（`ubuntu-latest`）：`maturin develop --locked` → `pytest` →
   `cargo clippy -- -D warnings` → `cargo fmt --check`。正确性门禁不依赖全平台矩阵。
2. **Release 流水**（`v*` tag）：4 个 target 各出 1 个 wheel
   （`x86_64-unknown-linux-gnu` manylinux auto / `aarch64-apple-darwin` /
   `x86_64-apple-darwin` / `x86_64-pc-windows-msvc`），每平台先跑测试再上传，
   最后**单独一个 job** 用 `pypa/gh-action-pypi-publish` 发布
   （不要在矩阵里各自 publish，会重复/竞争）。
3. 首次发布先走 TestPyPI 全流程；`PYPI_API_TOKEN` 进 GitHub Secrets。
4. 维护者流程：`maturin develop` 调试 → 改版本号（Cargo.toml + pyproject.toml）→
   `git tag v0.1.0 && git push origin v0.1.0` → CI 出包。

## 7. 测试策略

- **标准向量**（正确性命根子）：GM/T 0004（SM3）、GM/T 0002（SM4）、GM/T 0003（SM2）。
  已实测可用的锚点：
  - SM3("abc") = `66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0`
  - SM4 分组：k = pt = `0123456789abcdeffedcba9876543210` → `681edf34d206965e86b3e94f536e4246`
- **参数校验测试（安全门）**：GCM tag ≠ 16 必须抛错；GCM nonce ≠ 12 必须抛错；
  CBC 输入非块倍数必须抛错；SM2 明文 > 255 必须抛错；篡改 tag / 错误 aad /
  错误消息 / 错误 ID 必须拒绝。
- **交叉比对**：与 `cryptography` 或 GmSSL CLI 对拍（可选，本地跑）。
- Rust 单测只测纯逻辑（PKCS7 填充 / ECB 拼装 / hex），不重复 C 层测试。

## 8. 实测基线（M2 / macOS / release / 64 MiB 缓冲）

⚠️ **口径声明**：本机 Rust 工具链是 `x86_64-apple-darwin`（Rosetta，FlyEnv 安装、
无 rustup），**这些是 Rosetta x86_64 数字，不代表用户拿到的 arm64 wheel**。

| 指标 | GmSSL 3.1.1（我们的 R1 路线，未加速） |
|---|---|
| SM3 | 157.5 MiB/s |
| SM4-CBC | 94.4 MiB/s |
| SM4-GCM | 39.0 MiB/s |
| SM2 签名 | 2538 ops/s |
| SM2 验签 | 1584 ops/s |

对照（同机同口径，仅作参考，不属 R1）：GmSSL 3.2.0 在未加速配置下 SM3 +53%、
SM4-CBC +29%、SM4-GCM +14%，但 **SM2 签名 −82%**。

⚠️ **README 里禁止照抄的宣称**：方案原稿称"SM4 190MB/s""SM2 签名 11 万次/秒"
——实测分别为 94 MiB/s 与 2538 ops/s（差 43 倍）。性能数字一律以本仓库
`benches/` 实测为准。

⚠️ **本仓库默认构建不带任何硬件加速**：GmSSL 3.1.1/3.2.0 的加速开关全默认 OFF，
上游 `gmssl-rs-sys` 也只开了 `ENABLE_SM2_PRIVATE_KEY_EXPORT`。3.1.1 在 arm64 上
**没有可用加速**（只有 x86 的 `ENABLE_SM4_AESNI_AVX`）。追求加速的路线见 §9 R3。

## 9. 备选路线与修正记录

### 废弃：v1「自建 FFI + cc 编译 GmSSL 源码 + 锁 3.2.0」

概念正确（PyO3 + maturin + 静态链接 wheel 与本设计一致），但落地稿不可用，实测问题：

| v1 写法 | 实际 | 后果 |
|---|---|---|
| `fn sm3_init(ctx: *mut u8) -> i32` | `void sm3_init(SM3_CTX *ctx)` | 返回/参数类型都错 |
| `fn sm4_cbc_encrypt(key, iv, in, out, len) -> i32` | `void sm4_cbc_encrypt(const SM4_KEY*, const uint8_t[16], const uint8_t*, size_t, uint8_t*)` | 参数顺序错、缺 `SM4_KEY` 构造、返回类型错 |
| `[0u8; 1024]` 当 `SM3_CTX` | 需 `sizeof` 实测 | 猜大小 |
| build.rs 编 `sm4.c` / `sm4_cbc.c` / `endian.c` | 3.1.1 里**不存在**（那是 3.2.0 的布局） | `cc::Build::files()` 直接失败 |
| 手写 PKCS7 | GmSSL 自带 `sm4_cbc_padding_encrypt/decrypt` | 白写且丢掉库内校验 |
| `pyo3 = "0.20"` + `&PyModule` | 现为 0.29.x，`&PyModule` 已在 0.23 移除 | 不编译 |
| CI：3 OS × 5 Python 且每任务 publish | — | 15 个任务、发布竞争、无测试、无 `--locked` |

另有两条推翻 v1/v2 前提的核实结论：
1. 上游 `gmssl-rs` main **自相矛盾**：`GMSSL_RELEASE_TAG` 常量写着 `v3.2.0`，但
   `.gitmodules` 子模块 gitlink 仍指 `d655c06b` = **v3.1.1**；而 cargo 会为 git
   依赖递归拉子模块 → 走 git 依赖实际编进去的是 3.1.1，且因其源码已按 3.2.0 改名
   （`sm3_pbkdf2`），**用到 PBKDF2 会链接失败**。
2. 上游对 3.2.0 的 FFI 适配**本身是完整的**（实测：手编 GmSSL 3.2.0 + `GMSSL_DIR`
   指向它，`FAILS=0`），唯一障碍是 `GMSSL_DIR` 分支漏了 macOS 的
   `framework=Security`（上游 bug，临时用
   `RUSTFLAGS="-C link-arg=-framework -C link-arg=Security"` 绕过）。

### 保留预案：R3（vendor 两个 crate + 自控构建配方）

**触发条件**（任一即可切换，成本很低）：
1. 上游停止维护、或被 yank；
2. 必须消除 `DEBUG 1` 的 stderr 噪音；
3. 需要硬件加速（arm64 的 SM4 CE / SM2_ARM64 / GMUL_ARM64）→ 只能上 3.2.0
   并在 build.rs 里显式打开 `ENABLE_SM4_ARM64` / `ENABLE_SM2_ARM64` /
   `ENABLE_SM3_ARM64` / `ENABLE_GMUL_ARM64` 等开关；
4. 需要 GmSSL 3.2.0 的新特性。

做法：把 `gmssl-rs` + `gmssl-rs-sys` 源码 vendor 进本仓库（Apache-2.0，合法），
改 build.rs 的开关与源码版本。**注意**：R3 必须先验证"打开加速后 SM2 签名是否
回升"（3.2.0 未加速时 SM2 签名比 3.1.1 慢 5.7 倍）。

## 10. 未决 / 风险

- **arm64 原生性能未测**：本机无法测（工具链是 Rosetta x86_64、无 rustup）。
  若要在 README 里写 arm64 数字，需在 CI（macos-14 runner）或原生 arm64 机器上补测。
- **上游单点维护**：见 §9 R3 预案。
- **manylinux 容器是否自带 cmake**：首个 PR 就要验证（§5）。
- **PyPI 占名**：`gmssl-fast` 当前 404（未占用），但名字随时可能被抢，尽早发布 0.1.0。
