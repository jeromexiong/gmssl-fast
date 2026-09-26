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
| wheel | **abi3-py38**，3 个包：`manylinux_2_28_x86_64` / `macosx arm64` / `macosx x86_64`（**Windows 暂不支持**，原因见 §10） |
| 工具链 | pyo3 0.29.x（MSRV Rust 1.83）、maturin 1.15.x、CMake（构建前置） |
| 包名 | `gmssl-fast`（PyPI 未占用，HTTP 404，发布前占名）；模块 `gmssl_fast` |
| SM2 线格式 | **裸格式，且是唯一行为**（密文裸 C1C3C2、签名裸 r‖s），**不暴露任何格式参数**；DER 只是内部实现细节，见 §4.1 |
| 库内分层 | Rust 只做**算法原语**（`gmssl_fast._core`）；Python 侧写 API（`__init__.py`）与 drop-in 门面（`compat.py`），改接口不必碰 Rust |
| 对接目标 | 让 fastapiadmin 的加密层**只剩设置注入 + ORM 胶水**：曲线常数 / ZA 拼装 / 摘要派生 / 格式转换 / 04 前缀 / PKCS7 / IV 打包全部下沉进库，见 §11 |
| 验收标准 | fastapiadmin `tests/core/test_sm_crypto.py`（含 golden 向量）**原样跑绿** + 反向对拍，见 §7 |

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
- ⚠️ **CMake 版本（已纠正）**：GmSSL **3.1.1** 写的是 `cmake_minimum_required(VERSION 3.6)`，
  CMake 4.x 下同样合法 → **不需要任何策略下限**。此处旧文写「必须传
  `GMSSL_CMAKE_DEFINES="-DCMAKE_POLICY_VERSION_MINIMUM=3.5"`、实测有效」是两处错：
  ① 把手工探针里 GmSSL **3.2.0** 的老式写法（低于 3.5）张冠李戴到了 3.1.1；
  ② `GMSSL_CMAKE_DEFINES` 是按 `KEY=value` 交给 cmake-rs 的，而 cmake-rs 自己会再加 `-D`，
  多写的 `-D` 只会得到 `-DCMAKE_POLICY_VERSION_MINIMUM` 这个**假变量**（本机 CMakeCache
  第 18 行实锤）→ 它一直是个空操作，从未生效过。
- ⚠️ `ENABLE_SM2_PRIVATE_KEY_EXPORT` 默认 OFF，不开就缺 `sm2_private_key_info_from_pem/to_pem`；上游 build.rs 已强制 ON，无需我们处理（但要记住这条依赖）。

## 2. 上游已知问题与我们的对策

全部来自实测或源码复核：

| 上游问题 | 影响 | 我们的对策 |
|---|---|---|
| **GCM `taglen` 只校验上界、不校验下界**（`sm4_modes.c`：`if (taglen > MAX) return -1;` 之后 `memcmp(T, tag, taglen)`），实测传 8B tag 即返回 Ok | 若把 tag 长度暴露给调用方，1 字节 tag ≈ 1/256 伪造，AEAD 完整性被击穿 | **Python API 硬编码 `taglen = 16`，绝不暴露该参数**；并在测试里钉死 |
| **GCM `ivlen` 不校验**（实测 1 / 8 / 16 字节都 Ok） | IV 复用 / 非标准 J0 推导 / 跨库不互通 | 绑定层**强制 12 字节** IV，其它长度直接 `ValueError` |
| **CBC 无完整性**：错误 IV 解密返回 Ok（垃圾明文） | 用户可能误以为"解密成功 = 数据可信" | 文档明写"要完整性请用 GCM"；测试固化该行为 |
| **`#define DEBUG 1` 硬编码**（`include/gmssl/error.h`），错误直接 `fprintf(stderr, "file:line:func():")`，无运行时开关 | 校验失败会污染宿主进程 stderr（FastAPI 日志里冒 `sm4_modes.c:191:...`） | **已知瑕疵**：crates.io 依赖是只读的，无法关；写进 README「已知行为」。若未来必须消除，只能走 §9 的 vendor 路线改这一行 |
| SM2 加密明文 **≤ 255 字节**，GmSSL 原生密文是 **DER 编码**（首字节 0x30；255B 明文 → 364B 密文） | 拿 SM2 加密长数据会失败；DER 与前端要的「裸 C1C3C2」不互通 | ① 255B 上限写进 API 文档 + 异常消息；② DER ↔ 裸在库内转换，**对外不暴露**（见 §4.1） |
| `sm2_encrypt` 内部有绕 GmSSL `*outlen=0` 回绕的补丁 | 已由上游处理 | 无需动作，仅记录 |
| 上游为**单人维护**、仓库新（首个版本 2026-05-31）、下载量低 | 停更/跑路风险 | 见 §9 的 vendor 预案（R3），切换成本低 |

## 3. 项目骨架

```
gmssl-fast/
├── .github/workflows/build.yml   # PR 流水 + Release 流水
├── Cargo.toml                    # pyo3 + gmssl-rs；crate-type = ["cdylib"]
├── Cargo.lock                    # 必须提交（--locked 构建，保证可复现）
├── pyproject.toml                # maturin（python-source = "python"）+ 包元数据
├── README.md                     # 安装 / 速查 / 已知行为 / 基准数字
├── docs/plans/                   # 本设计文档
├── src/                          # ← Rust 只做算法原语
│   ├── lib.rs                    # pymodule 装配（模块名 `_core`）
│   ├── errors.rs                 # GmsslError → Python 异常映射（唯一映射点）
│   ├── sm2.rs / sm3.rs / sm4.rs  # 参数校验 + 类型转换
│   └── sm2_fmt.rs                # DER ↔ 裸 C1C3C2 / 裸 r‖s（纯安全 Rust）
├── python/gmssl_fast/            # ← Python 侧写 API，改接口不用碰 Rust
│   ├── __init__.py               # 现代 API：SM2 / SM3 / SM4
│   ├── compat.py                 # drop-in 门面：Sm2Cipher / Sm3Cipher / Sm4Cipher
│   └── py.typed
├── tests/                        # Python 集成测试（GM/T 向量 + fastapiadmin golden 对拍）
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

# SM2 —— 裸格式是唯一行为，没有任何格式参数
sm2 = gm.SM2(private_key=d, public_key=p)   # 也可 gm.SM2.generate()
ct  = sm2.encrypt(b"...")                   # 裸 C1C3C2；公钥兼容 128 / 130 字符
pt  = sm2.decrypt(ct)                       # 内部按「原样 / 剥掉 04」两候选试解
sig = sm2.sign(b"...")                      # -> bytes(64) 裸 r‖s
ok  = sm2.verify(b"...", sig)               # -> bool
```
（ZA/E 由 GmSSL 内部按默认 ID `1234567812345678` 计算——**调用方不需要任何曲线常数**。）
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

### 4.1 SM2 线格式（接入 fastapiadmin 的硬门槛）

对接目标 fastapiadmin（`backend/app/utils/sm_crypto.py`，2026-09 由 `gmssl` 迁到 `snowland-smx`）
的对外契约**冻结在 39 条测试**里，其 SM2 是**裸格式**，而 GmSSL / `gmssl-rs` 输出的是 **DER**：

| 项 | fastapiadmin 契约（冻结） | `gmssl-rs` 原生 | 是否需要转换 |
|---|---|---|---|
| SM2 密文 | 裸 C1C3C2 = `x(32)‖y(32)‖C3(32)‖C2(n)`，长度 `96+n`，首字节 ≠ `0x30` | **DER** SEQUENCE（实测 255B 明文 → 364B） | **必须** |
| SM2 签名 | 裸 r‖s = 64 字节 / 128 hex，首字符 ≠ `'30'` | **DER** SEQUENCE{INTEGER r, INTEGER s}（实测 71~72B） | **必须** |
| SM2 公钥 | 130 字符 `04‖X‖Y`，内部归一化为 128 | 未压缩 `04‖X‖Y` | 兼容两种长度即可 |
| SM4 | CBC + PKCS7，输出 `iv(16)‖ciphertext` | `Sm4Cbc::encrypt(key, iv, pt)` 自带 PKCS7 | 拼装属消费方，无需转换 |
| SM3 / 密码哈希 | 64 hex；`salt$hash`（salt 32 hex + hash 64 hex） | `Sm3::digest` | 无需转换 |

**实现：纯安全 Rust 手写 DER ↔ 裸格式编解码**（`src/sm2_fmt.rs`），结构已由 GmSSL 源码确认
（`sm2_lib.c:161` 签名 / `:695` 密文，用 `asn1_integer_to_der` + `asn1_octet_string_to_der`
+ `asn1_sequence_header_to_der`）：

- 解析必须处理 **INTEGER 前导 `0x00`**（x/y/r/s 高位为 1 时）与**长形式长度**（C2 最长 255 字节 → `0x81`/`0x82`）
- 反向组装时，对高位为 1 的值补 `0x00`
- **不新增 unsafe、不调用未暴露的 C 符号**：`gmssl-rs-sys` 里没有 `sm2_do_encrypt` /
  `sm2_ciphertext_to_der` / `sm2_signature_to_der`（GmSSL C 层有，但 Rust 绑层没暴露）

**解密兼容性（照搬项目做法，别自己发明）**：**不做**「首字节是 `0x04` 就剥离」的启发式——
裸格式 x 坐标的首字节本身就可能等于 `0x04`（约 1/256 ≈ 0.39% 的密文会被吃错）。改为
**候选逐个试解**：先按原样解，失败再剥掉首字节重试；C3 是完整性摘要，错误解释只会失败、
不会解出错误明文。项目里 `GOLDEN_SM2_CT_LEADING_04` 就是为锁定这条回归准备的。

**签名摘要天然对齐**：项目自行拼装 `ZA = SM3(ENTL‖ID‖a‖b‖xG‖yG‖xA‖yA)`（ID 默认
`1234567812345678`）再算 `E = SM3(ZA‖M)`；而 GmSSL 的 `sm2_sign_init` 内部做的就是这套，
默认 ID 相同（已实测「默认 ID 签名可被显式同 ID 验签 = true」）→ **不需要自算摘要**。

**接入代价**：迁移后项目侧只剩「设置注入 + ORM 胶水」，详见 §11。

### 4.2 「傻瓜式」接口：库吸收全部算法细节

用户诉求：用库时**不希望再出现曲线常数、ZA 拼装、摘要派生、格式转换、PKCS7、IV 打包**这些杂项。
边界划分：

| 进库（本库职责） | 留在消费方（项目胶水） |
|---|---|
| SM2/SM3/SM4 全部算法细节、裸格式编解码、ZA/ID、04 前缀兼容、两候选试解、PKCS7、`iv‖ct` 打包 | 从 `settings` 读密钥、SQLAlchemy `TypeDecorator`、FastAPI 依赖注入 |

```python
# 接 §4 示例
sm4 = gm.SM4(key)                            # 16 字节密钥
blob = sm4.encrypt(b"...")                   # 随机 IV → 返回 iv(16)‖ct，PKCS7 自动
sm4.decrypt(blob)                            # 自动取前 16 字节当 IV
gm.sm3_password_hash("admin123")             # -> "salt$hash"（salt = secrets.token_hex(16)）
gm.sm3_password_verify("admin123", stored)   # -> bool；格式不合法直接 False，不抛异常
```

**drop-in 门面 `gmssl_fast.compat`**（为从 `gmssl` / `snowland-smx` / 自研 util 迁移的用户，
方法名与签名逐一对齐旧实现）：

| 方法 | 签名 | 行为 |
|---|---|---|
| `Sm2Cipher.encrypt` | `(public_key: str, data: bytes) -> bytes` | 裸 C1C3C2；公钥 128 / 130 字符都可 |
| `Sm2Cipher.decrypt` | `(private_key: str, ct: bytes) -> bytes` | 两候选试解（不做首字节启发式） |
| `Sm2Cipher.sign` | `(priv: str, pub: str, data: bytes) -> str` | 返回 128 hex 裸 r‖s；`pub` 仅为兼容签名保留（ZA 用私钥内嵌公钥算） |
| `Sm2Cipher.verify` | `(public_key: str, data: bytes, sig: str) -> bool` | 接受 128 hex 裸 r‖s |
| `Sm3Cipher.hash / generate_salt / hash_password / verify_password` | 同旧实现 | `SM3(password + salt)`、`salt$hash` |
| `Sm4Cipher.encrypt / decrypt / generate_key / get_config_key` | 同旧实现 | `iv(16)‖ct` + PKCS7；`get_config_key()` 默认读环境变量 `SM4_KEY`，可用 `compat.configure(sm4_key=...)` 覆盖 |

对齐依据：`fastapiadmin/backend/app/utils/sm_crypto_util.py` 只用到 `Sm2Cipher` 的 4 个、
`Sm3Cipher` 的 4 个、`Sm4Cipher` 的 4 个方法（已逐条核对源码）。

## 5. 构建与 wheel 策略

- `pyo3 = { version = "0.29", features = ["extension-module", "abi3-py38"] }`
  （abi3-py38 在 0.29.2 仍受支持，目标到 abi3-py315）→ **每平台 1 个 whl**。
- `crate-type = ["cdylib"]`；Python 3.8+。
- 构建前置：**Rust 1.83+ / C 编译器 / CMake**。wheel 使用者三者都不需要。
- 构建命令（**无需任何环境变量**）：
  ```bash
  maturin build --release --locked
  ```
  `GMSSL_CMAKE_DEFINES` 是上游留的透传通道，写法为 `KEY=value`（cmake-rs 自己加 `-D`），
  当前用不到（见 §1、§10）。
- macOS 出**两个独立 wheel**（arm64 / x86_64），不做 universal2：GmSSL 是 C 代码，
  universal2 要求 CMake 同时按两架构编译（`cmake` crate 不会自动传
  `CMAKE_OSX_ARCHITECTURES`），是已知坑，收益只是少一个包。
- ✅ **manylinux 容器里的 cmake（原「最大未知项」）已有结论**：CI 的 Linux 腿
  （`manylinux: auto`）构建成功，且校验了产物带 `manylinux` 标签。流水线仍保留幂等写法
  （`command -v cmake || python3 -m pip install cmake` + 无条件 `cmake --version`），防镜像变动。

## 6. CI/CD

1. **PR 流水**（`ubuntu-latest`）：`maturin develop --locked` → `pytest` →
   `cargo clippy -- -D warnings` → `cargo fmt --check`。正确性门禁不依赖全平台矩阵。
2. **Release 流水**（`v*` tag）：**3 个 target** 各出 1 个 wheel
   （`x86_64-unknown-linux-gnu` manylinux auto / `aarch64-apple-darwin` /
   `x86_64-apple-darwin`；Windows 见 §10），每平台构建后上传 artifact，
   最后**单独一个 job** 用 `pypa/gh-action-pypi-publish` 发布
   （不要在矩阵里各自 publish，会重复/竞争）。
   `workflow_dispatch` 也能跑整套矩阵（不发 PyPI）——不发版时验证平台构建用。
3. 首次发布先走 TestPyPI 全流程；`PYPI_API_TOKEN` 进 GitHub Secrets。
4. 维护者流程：`maturin develop` 调试 → 改版本号（Cargo.toml + pyproject.toml）→
   `git tag v0.1.0 && git push origin v0.1.0` → CI 出包。

## 7. 测试策略

- **标准向量**（正确性命根子）：GM/T 0004（SM3）、GM/T 0002（SM4）、GM/T 0003（SM2）。
  已实测可用的锚点：
  - SM3("abc") = `66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0`
  - SM4 分组：k = pt = `0123456789abcdeffedcba9876543210` → `681edf34d206965e86b3e94f536e4246`
- **对接验收（最高优先级）**：移植 fastapiadmin `tests/core/test_sm_crypto.py` 的 golden 向量做
  **双向交叉对拍**，且必须逐位一致：
  - `GOLDEN_SM2_CT`（明文 `fastapiadmin-国密契约`，密文长度 = `96 + 25`）→ 本库能解出原文
  - `GOLDEN_SM2_CT_LEADING_04`（首字节为 `0x04` 的**合法裸**密文）→ 必须能解出原文
    （锁定「不做首字节启发式」这条）
  - `GOLDEN_SM2_SIG`（128 hex 裸 r‖s）→ 本库验签通过
  - 反向：**本库产出的密文/签名 → 项目侧 `Sm2Cipher` 必须能解开/验过**
  - `GOLDEN_PWD`（`salt$hash`）、`GOLDEN_SM4_BLOCK_CIPHER`（全零 IV 下 CBC 首块 =
    `99ce75c0ca2949d3eb87bd2d831f3510`）、`SM3_ABC_VECTOR`
- **参数校验测试（安全门）**：GCM tag ≠ 16 必须抛错；GCM nonce ≠ 12 必须抛错；
  CBC 输入非块倍数必须抛错；SM2 明文 > 255 必须抛错；篡改 tag / 错误 aad /
  错误消息 / 错误 ID 必须拒绝。
- **交叉比对**：与 `cryptography` 或 GmSSL CLI 对拍（可选，本地跑）。
- Rust 单测只测纯逻辑（PKCS7 填充 / ECB 拼装 / hex），不重复 C 层测试。
- 🔒 **断言不得依赖概率（硬规则，2026-09-24 CI 实锤后立）**：`assert_ne!(raw[0], 0x30)`
  打在**随机**密文上——裸格式 x 坐标首字节本身就有约 1/256 概率等于 `0x30`
  （8000 次采样实测：密文 0.537%、签名 0.375%）→ 一轮 CI 约 **0.8%~1.2% 概率假失败**，
  本地几次全凭运气过。规则：
  1. 随机产生的值只断言**不变量**（长度 / 往返 / 互相验证）；
  2. 字节级契约只对**固定向量**（`GOLDEN_*`）断言；
  3. 「随机性被正确使用」（随机盐 / 随机 IV）改为 **monkeypatch 注入**后断言调用与结果，
     而不是「两次取到不同值」。
  已做成机械防线：`scripts/lint_test_asserts.py`（CI 的 test job 里跑，本地门禁同样跑）。
- ✅ **库侧没有 1/256 级失败路径**（源码核实）：GmSSL 自己就处理了两类随机性——
  `sm2_lib.c:511` 的 `do{...}while(sm2_bn_is_zero(k))` 与 `:529` 的
  `if (all_zero(...)) goto retry`（KDF 全零时重选 k）。
  这正是 **pysmx 需要调用方写 10 次重试（`_new_sm2_signature` / 加密重试）、而 GmSSL 不需要**的原因。

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

### 8.1 库级实测（`benches/bench.py`，2026-09-24）

上表是 C 层基线（密钥对象在循环外构造一次）。下表是**通过 Python API 调用**的实测，
读者实际拿到的是这一组。口径一致：release 构建、一次性大缓冲、SM2 各 2000 次、
每项取 3 次最快；测试机 macOS 26.5.2 / **x86_64（Rosetta）** / CPython 3.9.6。

| 操作 | 库级实测 | 对比 C 层基线 |
|---|---|---|
| SM3 | **158.8 MiB/s** | 持平 |
| SM4-CBC | **93.6 MiB/s** | 持平 |
| SM4-GCM | **39.6 MiB/s** | 持平 |
| SM2 签名 | **2528 ops/s** | 持平（已优化，见下） |
| SM2 验签 | **1588 ops/s** | 持平 |

**SM2 签名曾比 C 层基线低 45%**（1395 vs 2538 ops/s）：`sign_raw` 每次调用都走
`scalar_key()` → 手拼 PKCS#8 DER → `Sm2Key::from_private_key_der()`，而 **GmSSL 解析时会
校验 `[1]` 公钥字段与标量是否匹配（一次额外的 EC 乘法）**；C 层基线把密钥构造放在循环外。

✅ **已优化（2026-09-24）**：新增 `_core.Sm2KeyHandle`（`#[pyclass]`，持有已解析的
`Sm2Key`），Python 侧 `SM2` 实例与 `compat`（`lru_cache(maxsize=8)`）各缓存一份 →
**1395 → 2528 ops/s，追平 C 层基线**。语义等价由 3 条新测试锁住
（句柄路径 ≡ 逐次解析路径、公钥句柄拒绝私钥操作、同一 `SM2` 实例只建一次句柄）。

**纯 Python 对照**（`snowland-smx`，就是既有 `sm_crypto.py` 用的那个；同机、同条件）：

| 操作 | 本库 | snowland-smx | 倍数 |
|---|---|---|---|
| SM3 | 158.98 MiB/s | 0.29 MiB/s | 557× |
| SM4-CBC | 94.77 MiB/s | 0.12 MiB/s | 819× |
| SM2 签名 | 2512 ops/s | 314 ops/s | **8.0×** |
| SM2 验签 | 1580 ops/s | 162 ops/s | **9.7×** |

⚠️ **结论：性能不是这次迁移的主因**。SM2（fastapiadmin 真正的热点，每请求一次签名）
只快 **4.5× / 9.6×**，而且 pysmx 的 315 ops/s 本来就够用；SM3/SM4 的三个数量级
差距只出现在大缓冲吞吐上（纯 Python 逐块循环 vs C）。迁移收益应表述为：
**接口傻瓜化 + 安全门（GCM tag/nonce 长度）+ 少维护 ~470 行易错代码**。
对外沟通时**别拿 SM3 的倍数去形容 SM2**（早期 README 的对照表只列了 SM3/SM4，
容易给人“快 500 倍”的整体印象，已补上 SM2 行纠正）。

⚠️ **arm64 数字未实测**（本机 Rust 是 Rosetta x86_64）→ README 已标注「待 CI 补测」。

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
4. 需要 GmSSL 3.2.0 的新特性；
5. **需要 Windows 支持**（CI 实测 MSVC 构建不过，见 §10；需要给 GmSSL 补 `WIN32` 宏）。

做法：把 `gmssl-rs` + `gmssl-rs-sys` 源码 vendor 进本仓库（Apache-2.0，合法），
改 build.rs 的开关与源码版本。**注意**：R3 必须先验证"打开加速后 SM2 签名是否
回升"（3.2.0 未加速时 SM2 签名比 3.1.1 慢 5.7 倍）。

## 10. 未决 / 风险

- **集成层划分已定**（见 §4.2）：`CommonCryptogramUtil` / `Sm4CbcTypeHandler` 留消费方；
  `PwdUtil` 的功能（`salt$hash`）收进库（`sm3_password_hash/verify`）。
- **arm64 原生性能未测**：本机无法测（工具链是 Rosetta x86_64、无 rustup）。
  arm64 **wheel** 已由 CI 产出且可用；但性能数字仍需在 arm64 上跑一次 `benches/bench.py`
  才能写进 README（不能拿 Rosetta x86_64 的数字代替）。
- **上游单点维护**：见 §9 R3 预案。
- **manylinux 容器是否自带 cmake（原「最大未知项」）→ 已有答案**：CI 的 Linux 腿
  （`manylinux: auto`）**构建通过**，产物也校验了带 `manylinux` 标签。流水线仍保留幂等写法
  （`command -v cmake || python3 -m pip install cmake` + 无条件 `cmake --version`）防镜像变动。
- **Windows 不支持（新增，CI 实测 3 次）**：`x86_64-pc-windows-msvc` 已在矩阵中移除。
  根因有两层：① GmSSL 3.1.1 的 `include/gmssl/api.h`、`socket.h`、`dylib.h` 用
  `#ifdef WIN32`（而 MSVC 只预定义 `_WIN32`）；② 正常 MSVC+CMake 会由平台模块
  `Windows-MSVC.cmake` 给出 `/DWIN32`，但 **cmake-rs 会自己设 `CMAKE_C_FLAGS` /
  `CMAKE_C_FLAGS_RELEASE`，把它顶掉** → 代码走 POSIX 分支 → `C1083: 缺少 dlfcn.h / netdb.h`。
  试过 `CMAKE_C_FLAGS=/DWIN32` 与（VS 生成器才认的）
  `CMAKE_C_FLAGS_RELEASE=/DWIN32;/MD;/O2;/Ob2;/DNDEBUG`，宏均未到达 cl.exe。
  → **要拿下 Windows 必须走 R3**（vendor + 自控构建，顺带给 GmSSL 补
  `#if defined(_WIN32) && !defined(WIN32)` → `#define WIN32`）。用户实际部署目标是 Linux 服务，
  当前不阻塞。
- ✅ **SM2 签名的密钥缓存（已完成，有实测依据）**：库级曾只有 1395 ops/s（比 C 层基线低 45%，
  全花在每次调用重新解析 PKCS#8、含一次 EC 乘法校验公钥）。已新增 `_core.Sm2KeyHandle`
  （`#[pyclass]` 持已解析密钥），`SM2` 实例与 `compat`（`lru_cache(maxsize=8)`）各缓存一份 →
  **2528 ops/s（追平 C 层基线）**。验签本来就持平，未动。
  注：`compat` 的静态方法没有实例可挂缓存，所以用 `lru_cache` 按 `(私钥, 公钥)` 缓存；
  上限 8 条，避免密钥多变时无限增长。
- **PyPI 占名**：`gmssl-fast` 当前 404（未占用），但名字随时可能被抢，尽早发布 0.1.0。

## 11. fastapiadmin 迁移（第二阶段）

**库先行**，分两阶段：

- **阶段 1（本仓库）**：交付 `gmssl-fast` wheel —— Rust core + Python API + `compat` 门面。
- **阶段 2（fastapiadmin）**：把加密层缩减成「设置注入 + ORM 胶水」，其余交给库。

| 现状（`backend/app/utils/`） | 迁移后 |
|---|---|
| `sm_crypto.py` **约 470 行**：曲线常数 `a/b/xG/yG`、ZA 前缀、`_compute_sm2_digest`、`_new_sm2_signature`（含重试）、`_candidate_ciphertexts`、`_strip_04`、PKCS7、IV 拼接 | **删除该文件** |
| `sm_crypto_util.py` 里 `CommonCryptogramUtil` 每方法 3~5 行 | 每方法 1 行（调用库） |
| `PwdUtil.set_password_hash / verify_password` | 直接换成 `gm.sm3_password_hash / sm3_password_verify` |
| `Sm4CbcTypeHandler`（SQLAlchemy `TypeDecorator`） | 保留（ORM 胶水），内部改调库的 `SM4` |
| `from app.utils.sm_crypto import Sm2Cipher, Sm3Cipher, Sm4Cipher` | 改指 `gmssl_fast.compat`（或让 `sm_crypto.py` 退化成 5 行 re-export，则调用方零改动） |

**验收（迁移完成的唯一标准）**：
1. `backend/tests/core/test_sm_crypto.py` **39 条原样跑绿**（含 golden 密文 / 签名 / 密码哈希）；
2. **反向对拍**：库产出的密文 / 签名 → 旧 `pysmx` 实现能解开 / 验过；
3. **三端登录实测**：Web / UniApp / Flutter 的密文都能被新后端解密（沿用原流程）；
4. **存量数据不动**：库里的 `salt$hash` 与日志里的签名继续可用。

⚠️ 迁移**不得改动**：前端（`sm-crypto` / `gm_crypto`）、数据库已有数据、`salt$hash` 格式、
SM4 的 `iv‖ct` 布局。
