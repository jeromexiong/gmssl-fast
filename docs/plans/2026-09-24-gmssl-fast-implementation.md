# gmssl-fast 实施计划（阶段 1：库）

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 交付一个 `pip install gmssl-fast` 即可用的国密库——Rust/PyO3 静态链接 GmSSL 3.1.1，对外只暴露**裸格式**（裸 C1C3C2 密文、裸 r‖s 签名），并提供与 fastapiadmin 旧实现逐一对齐的 `compat` 门面。

**Architecture:** 两层。Rust 侧（`gmssl_fast._core`，PyO3 + `gmssl-rs 0.1.1`）只做**算法原语**与裸/DER 格式转换（纯安全 Rust）；Python 侧（`python/gmssl_fast/`）写现代 API（`SM2`/`SM3`/`SM4`）与 `compat` 门面（`Sm2Cipher`/`Sm3Cipher`/`Sm4Cipher`）。改接口不必碰 Rust。

**Tech Stack:** Rust 1.83+（本机 1.98）、pyo3 0.29、maturin 1.15、`gmssl-rs = "0.1.1"`、pytest。设计依据：`docs/plans/2026-09-24-gmssl-fast-design.md`。

## Global Constraints

- **依赖**：只允许 `gmssl-rs = "0.1.1"` + `pyo3`（+ 测试用 `pytest`）。不得引入其它 crate / Python 运行时依赖。
- **构建前置**：Rust / C 编译器 / **CMake**。所有构建命令必须带
  `GMSSL_CMAKE_DEFINES="-DCMAKE_POLICY_VERSION_MINIMUM=3.5"`（CMake 4 兼容，实测必需）。
- **Python 目标**：`abi3-py38`，`requires-python = ">=3.8"`；每平台 1 个 wheel，共 4 个
  （`manylinux_2_28_x86_64` / `macosx_*_arm64` / `macosx_*_x86_64` / `win_amd64`）。
- **裸格式是唯一对外行为**：代码里**不得出现** `fmt=` 参数；DER 只允许出现在 `src/sm2_fmt.rs` 与 Rust 原语内部。
- **安全门（不得放宽）**：SM4-GCM 的 tag 固定 16 字节、nonce 固定 12 字节，两个参数都不暴露给调用方。
- **不写 unsafe**：`src/sm2_fmt.rs` 必须纯安全 Rust；unsafe 只存在于上游 `gmssl-rs` 内部。
- **命名**：PyPI 包 `gmssl-fast`；Python 模块 `gmssl_fast`；Rust 扩展模块 `gmssl_fast._core`。
- **提交信息**：约定式提交（`feat:` / `test:` / `build:` / `ci:` / `docs:` / `chore:`）。
- **每任务收尾门禁**：`cargo fmt --check` + `cargo clippy --all-targets -- -D warnings` + `GMSSL_CMAKE_DEFINES=... cargo test` + `pytest -q` 全绿才提交。
- **本机环境警告**：本机 Rust 工具链是 `x86_64-apple-darwin`（Rosetta），`maturin develop` 产出的是 **x86_64** 产物；
  **arm64 必须靠 CI 验证**，不要在 README 里写未实测的 arm64 数字。
- **禁止宣传数字**：不得使用「SM4 190MB/s」「SM2 签名 11 万次/秒」等未实测说法；性能数字一律来自 `benches/` 实测。

---

## 文件结构

| 文件 | 职责 |
|---|---|
| `Cargo.toml` / `Cargo.lock` | Rust 包定义；**lock 必须提交**（`--locked` 可复现构建） |
| `pyproject.toml` | maturin 配置（`python-source = "python"`、`module-name = "gmssl_fast._core"`） |
| `src/lib.rs` | 只做 pymodule 装配（不放算法逻辑） |
| `src/errors.rs` | `GmsslError` → Python 异常映射（唯一映射点） |
| `src/sm3.rs` | SM3 原语：`sm3`、`sm3_hmac`、`sm3_pbkdf2` |
| `src/sm4.rs` | SM4 原语：CBC(PKCS7)、CTR、GCM、ECB(块级拼装) |
| `src/sm2_fmt.rs` | DER ↔ 裸格式编解码（纯安全 Rust，**本项目最关键的 60 行**） |
| `src/sm2.rs` | SM2 原语：生成/导入/导出、签名验签、加解密（内部走 `sm2_fmt`） |
| `python/gmssl_fast/__init__.py` | 现代 API：`SM2` / `SM3` / `SM4` / `sm3_*` 函数 |
| `python/gmssl_fast/compat.py` | drop-in 门面：`Sm2Cipher` / `Sm3Cipher` / `Sm4Cipher` + `configure()` |
| `python/gmssl_fast/py.typed` | 类型标注标记（空文件） |
| `tests/` | pytest：GM/T 向量、边界、fastapiadmin golden 对拍 |
| `benches/bench.py` | 性能基准脚本（产出 README 数字） |
| `.github/workflows/build.yml` | PR 流水 + Release 流水 |

**阶段 2（fastapiadmin 迁移）不在本计划内**——它依赖本阶段产出的 wheel，见设计 §11。

---

## Task 1: 打通构建链路（最小可运行 wheel）

**Files:**
- Create: `Cargo.toml`, `pyproject.toml`, `.gitignore`, `src/lib.rs`, `src/errors.rs`, `src/sm3.rs`, `python/gmssl_fast/__init__.py`, `python/gmssl_fast/py.typed`, `tests/test_sm3.py`

**Interfaces:**
- Produces: `gmssl_fast._core.sm3(data: bytes) -> bytes`（32 字节摘要）；`gmssl_fast.sm3(data)` 同名转发。

- [ ] **Step 1: 准备本地 venv 与工具链**

```bash
cd /Users/jerome/Developer/tauri/gmssl-fast
python3 -m venv .venv
.venv/bin/pip install -U pip maturin pytest
cmake --version | head -1   # 需要 >= 3.6；若是 4.x，下面命令必须带 GMSSL_CMAKE_DEFINES
```

- [ ] **Step 2: 写失败测试**

`tests/test_sm3.py`：
```python
import gmssl_fast

SM3_ABC = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"

def test_sm3_standard_vector():
    assert gmssl_fast.sm3(b"abc").hex() == SM3_ABC
    assert gmssl_fast.sm3_hex(b"abc") == SM3_ABC
```

- [ ] **Step 3: 跑测试确认失败**

Run: `.venv/bin/pytest tests/test_sm3.py -q`
Expected: FAIL —— `ModuleNotFoundError: No module named 'gmssl_fast'`

- [ ] **Step 4: 写构建配置与最小实现**

`Cargo.toml`：
```toml
[package]
name = "gmssl-fast"
version = "0.1.0"
edition = "2021"
rust-version = "1.83"
publish = false

[lib]
name = "_core"
crate-type = ["cdylib"]

[dependencies]
gmssl-rs = "0.1.1"
pyo3 = { version = "0.29", features = ["extension-module", "abi3-py38"] }
```

`pyproject.toml`：
```toml
[build-system]
requires = ["maturin>=1.15,<2.0"]
build-backend = "maturin"

[project]
name = "gmssl-fast"
version = "0.1.0"
description = "基于 GmSSL 的国密算法（SM2/SM3/SM4）Python 扩展，静态链接、零系统依赖"
requires-python = ">=3.8"
license = { text = "Apache-2.0" }

[tool.maturin]
python-source = "python"
module-name = "gmssl_fast._core"
features = ["pyo3/extension-module"]
```

`src/sm3.rs`：
```rust
use pyo3::prelude::*;
use pyo3::types::PyBytes;

#[pyfunction]
pub fn sm3<'py>(py: Python<'py>, data: &[u8]) -> Bound<'py, PyBytes> {
    PyBytes::new(py, &gmssl_rs::Sm3::digest(data))
}
```

`src/lib.rs`：
```rust
mod sm3;
use pyo3::prelude::*;

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sm3::sm3, m)?)?;
    Ok(())
}
```

`python/gmssl_fast/__init__.py`：
```python
from ._core import sm3

__all__ = ["sm3"]


def sm3_hex(data: bytes) -> str:
    return sm3(data).hex()
```

`python/gmssl_fast/py.typed`：空文件。

`.gitignore`：`.venv/`、`target/`、`dist/`、`__pycache__/`、`*.egg-info/`

- [ ] **Step 5: 构建并跑测试**

Run: `GMSSL_CMAKE_DEFINES="-DCMAKE_POLICY_VERSION_MINIMUM=3.5" .venv/bin/maturin develop --release && .venv/bin/pytest tests/test_sm3.py -q`
Expected: PASS（首次构建会 CMake 编译 GmSSL 3.1.1，约 1–3 分钟）

- [ ] **Step 6: 提交**

```bash
git add -A && git commit -m "feat: 打通 PyO3+maturin 构建链路，暴露 SM3 原语"
```
> ⚠️ 提交前确认 `Cargo.lock` 已入库；`git status --porcelain` 左列不得有意外文件。

---

## Task 2: SM3 完整能力（HMAC / PBKDF2 / 密码哈希）

**Files:**
- Modify: `src/sm3.rs`, `src/lib.rs`, `python/gmssl_fast/__init__.py`
- Test: `tests/test_sm3.py`

**Interfaces:**
- Produces: `_core.sm3_hmac(key: bytes, data: bytes) -> bytes`、`_core.sm3_pbkdf2(pwd: bytes, salt: bytes, iterations: int, dklen: int) -> bytes`；
  公开 API `sm3_hmac(key, data) -> bytes`、`sm3_pbkdf2(pwd, salt, iterations, dklen) -> bytes`、
  `sm3_password_hash(password: str) -> str`（返回 `salt$hash`）、`sm3_password_verify(password: str, stored: str) -> bool`。

- [ ] **Step 1: 写失败测试**（含 **fastapiadmin golden**）

`tests/test_sm3.py` 追加：
```python
GOLDEN_PWD = ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa$"
              "d213b154ddba7eda7f38786f4675d1e3b926d32192a7306e7bcb8d2ea62c68fc")

def test_password_hash_matches_fastapiadmin_format():
    # salt 固定为 32 个 'a'（16 字节），hash = SM3((password + salt).encode())
    salt = "a" * 32
    assert gmssl_fast.sm3_hex(("admin123" + salt).encode()) == GOLDEN_PWD.split("$")[1]

def test_password_verify_accepts_golden_stored_value():
    assert gmssl_fast.sm3_password_verify("admin123", GOLDEN_PWD) is True
    assert gmssl_fast.sm3_password_verify("wrong", GOLDEN_PWD) is False
    assert gmssl_fast.sm3_password_verify("admin123", "no-dollar-sign") is False

def test_password_hash_roundtrip():
    stored = gmssl_fast.sm3_password_hash("admin123")
    assert gmssl_fast.sm3_password_verify("admin123", stored) is True
    assert stored.split("$")[0] != gmssl_fast.sm3_password_hash("x").split("$")[0]  # 盐随机

def test_sm3_hmac_and_pbkdf2():
    assert gmssl_fast.sm3_hmac(b"key", b"data").hex() == \
        "88a5a14b0fcf4a8a7b0c5084b8ee36e70efca4e8467fa264c3231bf16463b425"
    assert len(gmssl_fast.sm3_pbkdf2(b"password", b"salt", 10000, 32)) == 32
```

- [ ] **Step 2: 跑测试确认失败**

Run: `.venv/bin/pytest tests/test_sm3.py -q`
Expected: FAIL —— `AttributeError: module 'gmssl_fast' has no attribute 'sm3_hmac'`

- [ ] **Step 3: 实现 Rust 原语**

`src/sm3.rs` 追加（`Sm3Hmac::mac`、`gmssl_rs::sm3::sm3_pbkdf2`）：
```rust
#[pyfunction]
pub fn sm3_hmac<'py>(py: Python<'py>, key: &[u8], data: &[u8]) -> Bound<'py, PyBytes> {
    PyBytes::new(py, &gmssl_rs::Sm3Hmac::mac(key, data))
}

#[pyfunction]
pub fn sm3_pbkdf2<'py>(
    py: Python<'py>, pwd: &[u8], salt: &[u8], iterations: usize, dklen: usize,
) -> PyResult<Bound<'py, PyBytes>> {
    let mut out = vec![0u8; dklen];
    gmssl_rs::sm3::sm3_pbkdf2(pwd, salt, iterations, &mut out)
        .map_err(crate::errors::to_py_err)?;
    Ok(PyBytes::new(py, &out))
}
```
> 注意 `sm3_pbkdf2` 是 `pub fn` 但**没有 re-export 到 crate 根**，必须写 `gmssl_rs::sm3::sm3_pbkdf2`。
> 上游约束：salt ≤ 64 字节、iterations ≥ 10000。

`src/lib.rs` 注册两个新函数。

- [ ] **Step 4: 实现 Python 层**

`python/gmssl_fast/__init__.py`：加 `sm3_hmac`、`sm3_pbkdf2` 转发，以及：
```python
import secrets


def sm3_password_hash(password: str) -> str:
    """返回 'salt$hash'：salt = 16 字节随机值的 hex，hash = SM3((password + salt).encode())。"""
    salt = secrets.token_hex(16)
    return f"{salt}${sm3_hex((password + salt).encode('utf-8'))}"


def sm3_password_verify(password: str, stored: str) -> bool:
    if "$" not in stored:
        return False
    salt, expected = stored.split("$", 1)
    return sm3_hex((password + salt).encode("utf-8")) == expected
```
> ⚠️ 这两个函数的语义**逐位复刻** `fastapiadmin/backend/app/utils/sm_crypto.py` 的 `Sm3Cipher.hash_password/verify_password`；
> `verify` 遇到格式不合法必须**返回 False 而不是抛异常**（旧实现如此，39 条测试依赖）。

- [ ] **Step 5: 跑测试确认通过**

Run: `GMSSL_CMAKE_DEFINES="-DCMAKE_POLICY_VERSION_MINIMUM=3.5" .venv/bin/maturin develop --release && .venv/bin/pytest tests/test_sm3.py -q`
Expected: PASS

- [ ] **Step 6: 提交** `feat: SM3 补齐 HMAC / PBKDF2 / 密码哈希（对齐 fastapiadmin 格式）`

---

## Task 3: SM4 原语与 API（CBC / CTR / GCM / ECB）

**Files:**
- Create: `src/sm4.rs`；Modify: `src/lib.rs`, `python/gmssl_fast/__init__.py`；Test: `tests/test_sm4.py`

**Interfaces:**
- Produces: `_core.sm4_cbc_encrypt(key, iv, pt) -> bytes`（PKCS7）、`_core.sm4_cbc_decrypt(key, iv, ct) -> bytes`、
  `_core.sm4_ctr_xor(key, ctr, data) -> bytes`、`_core.sm4_gcm_encrypt(key, nonce, aad, pt) -> (ct, tag)`、
  `_core.sm4_gcm_decrypt(key, nonce, aad, ct, tag) -> bytes`、`_core.sm4_ecb_encrypt(key, pt) -> bytes`（自拼 PKCS7）；
  Python：`gmssl_fast.SM4(key)`（`encrypt(pt, iv=None) -> iv‖ct` / `decrypt(blob) -> pt`，`mode="cbc"|"ctr"|"ecb"`）、
  `gmssl_fast.SM4GCM(key, nonce)`（`encrypt(pt, aad=b"") -> (ct, tag)` / `decrypt(ct, tag, aad=b"") -> pt`）。

- [ ] **Step 1: 写失败测试**

`tests/test_sm4.py`：
```python
import pytest
import gmssl_fast

KEY = bytes.fromhex("0123456789abcdeffedcba9876543210")


def test_cbc_with_zero_iv_first_block_is_known_answer():
    blob = gmssl_fast.SM4(KEY, mode="cbc", iv=bytes(16)).encrypt(KEY)
    assert blob[16:32] == bytes.fromhex("99ce75c0ca2949d3eb87bd2d831f3510")   # 跳过前 16 字节 IV


def test_cbc_roundtrip_and_iv_handling():
    blob = gmssl_fast.SM4(KEY).encrypt(b"hello 国密")
    assert blob[:16] != bytes(16)          # IV 随机
    assert gmssl_fast.SM4(KEY).decrypt(blob) == b"hello 国密"


def test_cbc_pkcs7_pads_block_aligned_input():
    blob = gmssl_fast.SM4(KEY, mode="cbc", iv=bytes(16)).encrypt(bytes(16))
    assert len(blob) == 16 + 32            # 16B 输入 → 整块填充


def test_gcm_roundtrip_and_rejects_tampering():
    gcm = gmssl_fast.SM4GCM(KEY, bytes(12))
    ct, tag = gcm.encrypt(b"secret", aad=b"hdr")
    assert len(tag) == 16
    assert gcm.decrypt(ct, tag, aad=b"hdr") == b"secret"
    bad = bytearray(tag); bad[0] ^= 1
    with pytest.raises(gmssl_fast.GmsslAuthError):
        gcm.decrypt(ct, bytes(bad), aad=b"hdr")
    with pytest.raises(gmssl_fast.GmsslAuthError):
        gcm.decrypt(ct, tag, aad=b"other")


def test_gcm_rejects_wrong_nonce_length():
    with pytest.raises(ValueError):
        gmssl_fast.SM4GCM(KEY, bytes(1))     # 上游不校验 ivlen，库必须拦
    with pytest.raises(ValueError):
        gmssl_fast.SM4GCM(KEY, bytes(16))


def test_ecb_matches_block_cipher():
    assert gmssl_fast.SM4(KEY, mode="ecb").encrypt(KEY)[:16] == \
        bytes.fromhex("681edf34d206965e86b3e94f536e4246")


def test_cbc_rejects_non_block_aligned_ciphertext():
    blob = gmssl_fast.SM4(KEY).encrypt(b"x")
    with pytest.raises(gmssl_fast.GmsslValueError):
        gmssl_fast.SM4(KEY).decrypt(blob[:20])
```
> GM/T 0002 分组向量由两条断言覆盖：`test_cbc_with_zero_iv_first_block_is_known_answer`
> （全零 IV 下 CBC 首块 == ECB(明文块)）与 `test_ecb_matches_block_cipher`（`681edf34d206965e86b3e94f536e4246`）。

- [ ] **Step 2: 跑测试确认失败**

Run: `.venv/bin/pytest tests/test_sm4.py -q`
Expected: FAIL —— `AttributeError: module 'gmssl_fast' has no attribute 'SM4'`

- [ ] **Step 3: 实现 Rust 原语（含安全门）**

要点：
- CBC 直接用 `Sm4Cbc::encrypt/decrypt`（自带 PKCS7 与长度校验）。
- CTR 用 `Sm4Ctr::encrypt`（同一函数即解密）。
- **GCM 硬编码 `tag_len = 16`**（`Sm4Gcm::encrypt(key, nonce, aad, pt, 16)`）；解密拒绝 `tag.len() != 16`。
- **nonce 必须 12 字节**，否则 `PyValueError`（上游不校验，实测 1/8/16 都放行）。
- ECB 用 `Sm4Key::new(&key).encrypt_block/decrypt_block` 循环 + 自己实现 PKCS7（纯安全 Rust，约 30 行）。
- 所有 `GmsslError` 经 `src/errors.rs::to_py_err` 翻译：`LibraryError("sm4_gcm_decrypt")` → `GmsslAuthError`，其余 → `GmsslValueError`。

`src/errors.rs`：
```rust
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::PyErr;
use gmssl_rs::GmsslError;

pyo3::create_exception!(gmssl_fast, GmsslError, pyo3::exceptions::PyException);
pyo3::create_exception!(gmssl_fast, GmsslValueError, GmsslError);
pyo3::create_exception!(gmssl_fast, GmsslAuthError, GmsslError);
pyo3::create_exception!(gmssl_fast, GmsslVerificationError, GmsslError);

pub fn to_py_err(e: GmsslError) -> PyErr { /* 按变体与上下文分派 */ }
```

- [ ] **Step 4: 实现 Python 层 `SM4` / `SM4GCM`**

```python
class SM4:
    def __init__(self, key: bytes, mode: str = "cbc", iv: bytes | None = None): ...
    def encrypt(self, plaintext: bytes, iv: bytes | None = None) -> bytes: ...   # cbc/ctr 返回 iv(16)‖ct；**ecb 不加前缀**
    def decrypt(self, blob: bytes) -> bytes: ...                                  # cbc 取前 16 字节当 IV；ecb 全量当密文
```

- [ ] **Step 5: 跑测试确认通过**

Run: `GMSSL_CMAKE_DEFINES="-DCMAKE_POLICY_VERSION_MINIMUM=3.5" .venv/bin/maturin develop --release && .venv/bin/pytest tests/test_sm4.py -q`
Expected: PASS

- [ ] **Step 6: 提交** `feat: SM4 四模式 + GCM 安全门（tag=16/nonce=12 不暴露）`

---

## Task 4: SM2 裸格式编解码（`src/sm2_fmt.rs`，纯 Rust 单测）

**Files:**
- Create: `src/sm2_fmt.rs`；Modify: `src/lib.rs`（`mod sm2_fmt;`）

**Interfaces:**
- Produces（仅 Rust 内部，不暴露给 Python）：
```rust
pub fn sig_der_to_raw(der: &[u8]) -> Result<[u8; 64], GmsslError>;   // SEQUENCE{INTEGER r, INTEGER s} -> r‖s
pub fn sig_raw_to_der(raw: &[u8]) -> Result<Vec<u8>, GmsslError>;
pub fn ct_der_to_raw(der: &[u8]) -> Result<Vec<u8>, GmsslError>;     // SEQUENCE{x,y,C3,C2} -> x‖y‖C3‖C2
pub fn ct_raw_to_der(raw: &[u8]) -> Result<Vec<u8>, GmsslError>;     // 反方向；C2 长度 = raw.len()-96
```

结构依据（GmSSL 3.1.1 `src/sm2_lib.c:161` 与 `:695`）：
- 签名 = `SEQUENCE { INTEGER r(32), INTEGER s(32) }`
- 密文 = `SEQUENCE { INTEGER x(32), INTEGER y(32), OCTET STRING C3(32), OCTET STRING C2(n) }`

- [ ] **Step 1: 写失败单测**（`src/sm2_fmt.rs` 内 `#[cfg(test)] mod tests`）

覆盖四类边界：
```rust
#[test] fn sig_roundtrip()                                  // 随机 r/s 往返
#[test] fn sig_integer_with_leading_zero()                   // r 高位为 1（DER 里有 0x00 前导）
#[test] fn sig_rejects_wrong_length()                        // raw 不是 64 字节
#[test] fn ct_roundtrip_short_and_255()                      // C2 = 1 字节与 255 字节
#[test] fn ct_handles_long_form_length()                     // C2 长度 > 127 → 0x81/0x82
#[test] fn ct_rejects_too_short()                            // raw < 96 字节
```

- [ ] **Step 2: 跑测试确认失败**

Run: `GMSSL_CMAKE_DEFINES="-DCMAKE_POLICY_VERSION_MINIMUM=3.5" cargo test --lib`
Expected: FAIL —— 编译错误（函数未定义）

- [ ] **Step 3: 实现编解码（纯安全 Rust）**

要点：
- 解析 DER 必须先读 tag 与长度（支持短形式与长形式 `0x81/0x82`），再读内容。
- INTEGER 解析后**去掉前导 `0x00`**，再左补零到 32 字节；若去掉后 > 32 字节 → 报错。
- OCTET STRING C3 必须恰好 32 字节。
- 反向组装时：值首字节 ≥ `0x80` 时补 `0x00`；长度 ≤ 127 用短形式，否则 `0x81`/`0x82`。
- 不得使用 `unwrap()`；全部返回 `Result`。

- [ ] **Step 4: 跑测试确认通过**

Run: `GMSSL_CMAKE_DEFINES="-DCMAKE_POLICY_VERSION_MINIMUM=3.5" cargo test --lib`
Expected: PASS（全部 6 条）

- [ ] **Step 5: 用真实样本加固**

用 Task 5 里 GmSSL 实际产出的 DER 密文/签名各取一例，作为**十六进制常量**写成 golden 单测（避免只测自己造的样本）。

- [ ] **Step 6: 提交** `feat: SM2 裸格式编解码（纯安全 Rust，含长形式长度与前导零边界）`

---

## Task 5: SM2 原语与 API

**Files:**
- Create: `src/sm2.rs`；Modify: `src/lib.rs`, `python/gmssl_fast/__init__.py`；Test: `tests/test_sm2.py`

**Interfaces:**
- Produces：`_core.sm2_generate() -> (priv_hex, pub_hex)`、`_core.sm2_public_from_private(priv_hex) -> pub_hex`、
  `_core.sm2_encrypt_raw(pub_hex, data) -> bytes`、`_core.sm2_decrypt_raw(priv_hex, ct) -> bytes`、
  `_core.sm2_sign_raw(priv_hex, data) -> bytes`、`_core.sm2_verify_raw(pub_hex, data, sig) -> bool`；
  Python：`gmssl_fast.SM2(private_key=None, public_key=None)`，方法 `generate()`、
  `encrypt(data) -> bytes`、`decrypt(ct) -> bytes`、`sign(data) -> bytes`、`verify(data, sig) -> bool`、
  `public_key_hex`、`private_key_hex`。

- [ ] **Step 1: 写失败测试（含 fastapiadmin golden）**

`tests/test_sm2.py`：
```python
import pytest
import gmssl_fast

GOLDEN_PRIV = "fef1cd14d44d8a57afa854312a2fb11155638a9d6444d8a35db0e75cf4949246"
GOLDEN_PUB = ("046574bf3f968a9fc217ce48f65543c64be1a6a8dc8325ffed3125e425fb09626"
              "b3996ca6e16bc109c3e43a1133a2c16485f4f67dd0d8dded6b837f4e9dca2ea21")
GOLDEN_MSG = "fastapiadmin-国密契约".encode()
GOLDEN_CT = bytes.fromhex(
    "5e2ad5aa14c202bcb8653d1edcb4c13a89a7c959a50d6056679ccc8229b69ce0"
    "4cd1df4597e9bdfb05007785a514af83a70f09a66767784522b18da00fe9a75a"
    "f2262f8d9d6b18a303953eb121947f8540dbeef01003e6dc09f9aa6850929245"
    "a6b8b306e770b524180f61aebfb1e2c151918747d7a401c8a6")
GOLDEN_SIG = ("6512c757cb3e105aac6e6d9ca66f9d9b9badaba2eb45ec04768df6be2ed37e0e"
              "45619e22909951cc909fbe8e5ca2acc47b22a44b35e99856e8e4f3daf947e6ce")
GOLDEN_CT_LEADING_04 = bytes.fromhex(
    "044a6aab51879c22a823c7e9c305978679fbe222f37f8492c25b61fd295e7621"
    "0274dadbe2d1585ab5266e54661c02fd5f839e90b1f74e16ff7c369059417052"
    "d7d3498ea4527a2ccb9772694461a9c1778df1948e9f95b27af0942997c58446"
    "d5ca11a5bcfcbc29b4a7ffe4483cc3373f5928198b3bd9b0e0")

def test_ciphertext_is_raw_c1c3c2_without_asn1():
    sm2 = gmssl_fast.SM2(public_key=GOLDEN_PUB)
    ct = sm2.encrypt(GOLDEN_MSG)
    assert len(ct) == 64 + 32 + len(GOLDEN_MSG)
    assert ct[0] != 0x30                       # 首字节 0x30 说明被 ASN.1 包装

def test_decrypts_golden_ciphertext():
    assert gmssl_fast.SM2(private_key=GOLDEN_PRIV).decrypt(GOLDEN_CT) == GOLDEN_MSG

def test_decrypts_golden_ciphertext_whose_x_starts_with_0x04():
    assert GOLDEN_CT_LEADING_04[:1] == b"\x04"          # 样本前提
    assert gmssl_fast.SM2(private_key=GOLDEN_PRIV).decrypt(GOLDEN_CT_LEADING_04) == GOLDEN_MSG

def test_verifies_golden_signature():
    assert gmssl_fast.SM2(public_key=GOLDEN_PUB).verify(GOLDEN_MSG, bytes.fromhex(GOLDEN_SIG))

def test_signature_is_raw_rs_64_bytes():
    sm2 = gmssl_fast.SM2(private_key=GOLDEN_PRIV, public_key=GOLDEN_PUB)
    sig = sm2.sign(GOLDEN_MSG)
    assert len(sig) == 64 and sig[0] != 0x30
    assert sm2.verify(GOLDEN_MSG, sig) is True
    assert sm2.verify(b"other", sig) is False

def test_rejects_plaintext_over_255_bytes():
    with pytest.raises(gmssl_fast.GmsslValueError):
        gmssl_fast.SM2(public_key=GOLDEN_PUB).encrypt(bytes(256))

def test_public_key_accepts_128_and_130_chars():
    assert gmssl_fast.SM2(public_key=GOLDEN_PUB[2:]).encrypt(b"x")     # 128 字符
    assert gmssl_fast.SM2(public_key=GOLDEN_PUB).encrypt(b"x")         # 130 字符
```

- [ ] **Step 2: 跑测试确认失败**

Run: `.venv/bin/pytest tests/test_sm2.py -q`
Expected: FAIL —— `AttributeError: module 'gmssl_fast' has no attribute 'SM2'`

- [ ] **Step 3: 实现 Rust 原语**

要点：
- `Sm2Key::generate()`、`Sm2Key::from_private_key_pem/to_private_key_pem`（PEM 仅用于内部往返，不暴露文件 IO）。
- 公私钥 hex 互转：私钥 32 字节 hex；公钥用 `to_public_key_der()` 解析出未压缩点，输出 `04‖X‖Y` 的 65 字节 hex（130 字符）。
- **加密**：`gmssl_rs::sm2::sm2_encrypt` → DER → `sm2_fmt::ct_der_to_raw` → 裸。
- **解密（两候选试解，顺序写死）**：
  1. 先按原样 `raw → DER → sm2_decrypt`；
  2. 失败且 `raw[0] == 0x04` 时，剥掉首字节再走一遍；
  3. 两次都失败 → `GmsslValueError`。
  > ⚠️ **禁止**「首字节是 0x04 就剥离」的启发式：裸格式 x 坐标首字节本身可能就是 0x04（fastapiadmin 的 `GOLDEN_SM2_CT_LEADING_04` 就是为锁定这条回归准备的）。
- **签名/验签**：`Sm2Signer::sign(&key, None, data)` → DER → `sig_der_to_raw`；验签反向。`None` 表示用 GmSSL 默认 ID `1234567812345678`（与 fastapiadmin 一致，实测等价）。

- [ ] **Step 4: 实现 Python 层 `SM2`**

```python
class SM2:
    def __init__(self, private_key: str | None = None, public_key: str | None = None): ...
    @classmethod
    def generate(cls) -> "SM2": ...
    @property
    def private_key_hex(self) -> str: ...
    @property
    def public_key_hex(self) -> str: ...      # 130 字符，含 04 前缀
```

- [ ] **Step 5: 跑测试确认通过**

Run: `GMSSL_CMAKE_DEFINES="-DCMAKE_POLICY_VERSION_MINIMUM=3.5" .venv/bin/maturin develop --release && .venv/bin/pytest tests/test_sm2.py -q`
Expected: PASS（7 条全绿，含 4 条 golden）

- [ ] **Step 6: 提交** `feat: SM2 裸格式 API（含 04 前缀两候选试解与 golden 对拍）`

---

## Task 6: `compat` 门面（fastapiadmin drop-in）

**Files:**
- Create: `python/gmssl_fast/compat.py`；Modify: `python/gmssl_fast/__init__.py`（re-export）；Test: `tests/test_compat.py`

**Interfaces:**
- Produces：`gmssl_fast.compat.Sm2Cipher` / `Sm3Cipher` / `Sm4Cipher`，以及 `gmssl_fast.compat.configure(sm4_key: str | None = None) -> None`。
  方法签名必须与 `fastapiadmin/backend/app/utils/sm_crypto.py` **逐字一致**（见下表）。

| 方法 | 签名 |
|---|---|
| `Sm2Cipher.encrypt` | `(public_key: str, data: bytes) -> bytes` |
| `Sm2Cipher.decrypt` | `(private_key: str, ciphertext: bytes) -> bytes` |
| `Sm2Cipher.sign` | `(private_key: str, public_key: str, data: bytes) -> str` |
| `Sm2Cipher.verify` | `(public_key: str, data: bytes, signature: str) -> bool` |
| `Sm3Cipher.hash` | `(data: bytes) -> str` |
| `Sm3Cipher.generate_salt` | `() -> str` |
| `Sm3Cipher.hash_password` | `(password: str, salt: str \| None = None) -> tuple[str, str]` |
| `Sm3Cipher.verify_password` | `(password: str, stored_value: str) -> bool` |
| `Sm4Cipher.get_config_key` | `() -> bytes` |
| `Sm4Cipher.generate_key` | `() -> bytes` |
| `Sm4Cipher.encrypt` | `(key: bytes, plaintext: bytes, iv: bytes \| None = None) -> bytes` |
| `Sm4Cipher.decrypt` | `(key: bytes, data: bytes) -> bytes` |

- [ ] **Step 1: 写失败测试**

`tests/test_compat.py`（直接搬 fastapiadmin 的调用形态）：
```python
import os
import pytest
from gmssl_fast import compat

def test_sm2_staticmethod_call_shape():
    ct = compat.Sm2Cipher.encrypt(GOLDEN_PUB, GOLDEN_MSG)
    assert compat.Sm2Cipher.decrypt(GOLDEN_PRIV, ct) == GOLDEN_MSG
    sig = compat.Sm2Cipher.sign(GOLDEN_PRIV, GOLDEN_PUB, GOLDEN_MSG)
    assert len(sig) == 128 and sig[0] != "3"
    assert compat.Sm2Cipher.verify(GOLDEN_PUB, GOLDEN_MSG, sig) is True

def test_sm3_password_shape():
    salt, h = compat.Sm3Cipher.hash_password("admin123")
    assert compat.Sm3Cipher.verify_password("admin123", f"{salt}${h}") is True
    assert compat.Sm3Cipher.verify_password("admin123", "bad") is False

def test_sm4_outputs_iv_prefixed_blob():
    key = compat.Sm4Cipher.generate_key()
    blob = compat.Sm4Cipher.encrypt(key, b"hello")
    assert compat.Sm4Cipher.decrypt(key, blob) == b"hello"

def test_get_config_key_reads_env_then_configure(monkeypatch):
    monkeypatch.setenv("SM4_KEY", "00" * 16)
    assert compat.Sm4Cipher.get_config_key() == bytes(16)
    compat.configure(sm4_key="11" * 16)
    assert compat.Sm4Cipher.get_config_key() == bytes.fromhex("11" * 16)
    compat.configure(sm4_key=None)
```

- [ ] **Step 2: 跑测试确认失败**

Run: `.venv/bin/pytest tests/test_compat.py -q`
Expected: FAIL —— `ImportError: cannot import name 'compat'`

- [ ] **Step 3: 实现 `compat.py`**

要点：全部是薄转发，不重复实现算法。
```python
_sm4_key: str | None = None

def configure(*, sm4_key: str | None = None) -> None:
    global _sm4_key
    _sm4_key = sm4_key

class Sm4Cipher:
    @staticmethod
    def get_config_key() -> bytes:
        key_hex = _sm4_key or os.environ.get("SM4_KEY", "")
        if not key_hex:
            raise ValueError("SM4_KEY 未配置：请设置环境变量或用 compat.configure(sm4_key=...)")
        return bytes.fromhex(key_hex)
```
- `Sm2Cipher.sign(priv, pub, data)` 的 `pub` **只为兼容签名保留**，内部按私钥内嵌公钥算 ZA（结果与旧实现一致）。
- `Sm4Cipher.encrypt` 返回 `iv‖ct`（`iv=None` 时随机 16 字节）；`decrypt` 取前 16 字节当 IV。

- [ ] **Step 4: 跑测试确认通过**

Run: `.venv/bin/pytest tests/test_compat.py -q`
Expected: PASS

- [ ] **Step 5: 提交** `feat: compat 门面（Sm2/Sm3/Sm4Cipher，对齐 fastapiadmin 静态方法签名）`

---

## Task 7: 与 fastapiadmin 双向对拍（跨库交叉验证）

**Files:**
- Create: `tests/test_cross_fastapiadmin.py`、`tests/golden.py`（把 golden 常量集中到一处）

**Interfaces:**
- Consumes：Task 2/3/5/6 的全部公开 API。Produces：无（纯验证）。

- [ ] **Step 1: 抽出 golden 常量**

把 Task 2/5 里内联的 `GOLDEN_*` 移到 `tests/golden.py`，**逐字复制**自
`/Users/jerome/Developer/AI/fastapiadmin/backend/tests/core/test_sm_crypto.py`（第 28–72 行），并加注释标明来源与日期。

- [ ] **Step 2: 写双向对拍测试**

```python
# 方向一：fastapiadmin 的 golden → 本库（Task 5 已覆盖解密/验签）
# 方向二：本库产出 → 旧 pysmx 实现能解开/验过（可选依赖，缺失则 skip）
pysmx = pytest.importorskip("pysmx.SM2")

def test_library_ciphertext_decrypts_with_pysmx():
    ct = gmssl_fast.SM2(public_key=GOLDEN_PUB).encrypt(b"cross-check")
    assert pysmx.SM2.Decrypt(ct.hex(), GOLDEN_PRIV)[:len(b"cross-check")] == b"cross-check"

def test_library_signature_verifies_with_pysmx():
    sig = gmssl_fast.SM2(private_key=GOLDEN_PRIV, public_key=GOLDEN_PUB).sign(b"cross-check")
    # 用与 fastapiadmin 相同的方式算 E，再调 pysmx.Verify
    ...
```

- [ ] **Step 3: 跑对拍**

Run: `.venv/bin/pip install snowland-smx && .venv/bin/pytest tests/test_cross_fastapiadmin.py -q`
Expected: PASS（两个方向都过；若未装 `snowland-smx`，测试应被 skip 而不是报错）

- [ ] **Step 4: 提交** `test: 与 fastapiadmin golden 双向对拍（含可选 pysmx 交叉验证）`

---

## Task 8: CI 与发布流水

**Files:**
- Create: `.github/workflows/build.yml`

- [ ] **Step 1: 写 PR 流水**（只要 Linux，快）

```yaml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with: { components: rustfmt, clippy }
      - name: 确认 manylinux/ubuntu 有 cmake
        run: cmake --version
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install -U maturin pytest
      - run: cargo fmt --check
      - run: cargo clippy --all-targets -- -D warnings
      - run: cargo test
        env: { GMSSL_CMAKE_DEFINES: "-DCMAKE_POLICY_VERSION_MINIMUM=3.5" }
      - run: maturin develop --release
        env: { GMSSL_CMAKE_DEFINES: "-DCMAKE_POLICY_VERSION_MINIMUM=3.5" }
      - run: pytest -q
```

- [ ] **Step 2: 验证 Linux 侧 cmake**

Run: 触发一次 PR 流水，或在本地容器里跑 `docker run --rm -v $PWD:/w -w /w python:3.12-slim bash -c "apt-get update && apt-get install -y cmake && cmake --version"`
Expected: 有 cmake；**若 maturin-action 的 manylinux 镜像里没有 cmake**，在 Release 流水加
`before-script-linux: yum install -y cmake || apt-get install -y cmake`。这条是本计划最大的未知项，必须实测。

- [ ] **Step 3: 写 Release 流水**（4 个 target × abi3 = 4 个 wheel）

- `matrix.target`: `x86_64-unknown-linux-gnu`（manylinux auto）/ `aarch64-apple-darwin` /
  `x86_64-apple-darwin` / `x86_64-pc-windows-msvc`
- 每个 job：`maturin build --release --locked` → 上传 artifact
- **单独一个 publish job**（`needs: build`）用 `pypa/gh-action-pypi-publish`；
  ⚠️ **不要在矩阵里各自 publish**（会重复/竞争）
- 环境变量：所有 build 步骤都要 `GMSSL_CMAKE_DEFINES`
- 首次先 `repository-url: https://test.pypi.org/legacy/`；`PYPI_API_TOKEN` 走 Secrets

- [ ] **Step 4: 验证**

Run: `git tag v0.1.0 && git push origin v0.1.0`（先推 TestPyPI 配置）
Expected: 4 个 wheel 产出，且 `pip install --index-url https://test.pypi.org/simple/ gmssl-fast` 后
`pytest tests/ -q` 全绿 —— **这是 arm64 数字与产物的唯一验证途径**（本机是 Rosetta x86_64）。

- [ ] **Step 5: 提交** `ci: PR 流水 + 4 平台 abi3 wheel release 流水（TestPyPI 优先）`

---

## Task 9: 基准脚本、README 与已知行为

**Files:**
- Create: `benches/bench.py`、`README.md`（若 Task 1 未建）；Modify: `docs/plans/2026-09-24-gmssl-fast-design.md` §8（回填实测）

- [ ] **Step 1: 写基准脚本**

`benches/bench.py`：SM3（64 MiB）、SM4-CBC（64 MiB）、SM4-GCM（64 MiB）、SM2 签名/验签（2000 次），
输出 MiB/s 与 ops/s；并与纯 Python（`gmssl` 包，可选）对比。
参考基线（M2/Rosetta/x86_64，未加速的 GmSSL 3.1.1）：SM3 157.5 MiB/s、SM4-CBC 94.4 MiB/s、
SM4-GCM 39.0 MiB/s、SM2 签名 2538 ops/s、验签 1584 ops/s。

- [ ] **Step 2: 跑基准并把数字写进 README**

Run: `.venv/bin/python benches/bench.py`
Expected: 数字与本库实测一致；README 里明确标注**测试机与架构**，arm64 未实测就写"待 CI 补测"。

- [ ] **Step 3: README 必写的「已知行为」**

1. SM2 加密明文上限 **255 字节**（GmSSL 限制），别拿它加密长数据；
2. **CBC 不提供完整性**（错误 IV 会解出垃圾明文而不报错）——要完整性用 GCM；
3. GmSSL 硬编码 `DEBUG 1`，**校验失败会往 stderr 打 `文件:行号:函数():`**，这是上游行为、库无法关闭；
4. SM4-GCM 只有一次性 API，加密 N 字节需要约 N 字节额外内存；
5. 安装不需要 Rust/GCC/GmSSL；从源码构建需要 **CMake**。

- [ ] **Step 4: 提交** `docs: README 与实测基准（含 5 条已知行为）`

---

## 完成定义（阶段 1）

- [x] `pip install gmssl-fast` 后，`tests/` 全部通过（含 4 条 fastapiadmin golden 与双向对拍）
      —— 用**真 wheel** 验证：`maturin build --release --locked` → `pip install dist/*.whl` → `pytest` 58 passed
- [ ] 4 个平台各产出 1 个 abi3 wheel，且在 CI 上跑过测试
      —— **未完成**：流水线已就绪，但尚未 push 到 GitHub 触发；本机只能产出 x86_64 macOS 轮子
- [x] 代码里不存在 `fmt=` 参数、不存在 `unsafe`、不存在暴露给调用方的 GCM tag 长度
      —— grep 复核：`unsafe` 只出现在 `src/sm2_fmt.rs` 的注释里；`GCM_TAG_LEN` 是常量、不是入参
- [x] README 的性能数字全部来自 `benches/` 实测，且标注测试机架构（Rosetta x86_64，arm64 标「待补测」）
- [x] `docs/plans/2026-09-24-gmssl-fast-design.md` §8 回填实测数字（新增 8.1 库级实测）

**下一步**：阶段 2（fastapiadmin 迁移）单独成计划，验收标准见设计 §11。

---

## 执行状态（2026-09-24）

每个任务一次提交；收尾时门禁为 `cargo fmt --all --check` ✓、
`cargo clippy --all-targets --locked -- -D warnings` ✓、`cargo test --locked` 16 passed ✓、
`pytest -q` 58 passed ✓。

| 任务 | 提交 | 备注 |
|---|---|---|
| 设计文档 v2 | `0c3b69c` | 另有 `1b2f749`（SM2 线格式）、`3d4a301`（傻瓜式接口 + §11 迁移） |
| 实施计划 | `d476a02` | 本文档 |
| 1 PyO3 + maturin 链路、SM3 原语 | `7176810` | 首次跑通 vendored GmSSL 3.1.1 的 CMake 编译 |
| 2 SM3 HMAC / PBKDF2 / 密码哈希 | `77c6e68` | |
| 3 SM4 四模式 + GCM 安全门 | `1645e6e` | tag 硬编码 16、nonce 强制 12 |
| 4 SM2 裸格式编解码 | `30aa9a7` | 纯安全 Rust，14 个单测 |
| 5 SM2 API + golden 对拍 | `1196b86` | 存量密文/签名可直接读 |
| 6 compat 门面 | `4fea7c0` | 含 `sm2_public_key` 注入的取舍 |
| 7 与存量实现双向对拍 | `628df2d` | 与 snowland-smx 逐字节一致 |
| 8 CI + 4 平台发布流水 | `92a9650` | cmake 用幂等兜底 + 首跑日志自证 |
| 9 README + 基准 | `acda5c4` | 顺手定位了 SM2 签名慢 45% 的根因 |

### 与计划的偏差（均已记录理由）

1. **`cargo test` 需要 pyo3-free 核心**：否则测试要链接 libpython（计划未预见，实测必须改）。
2. **`extension-module` 只写在 `pyproject.toml`**：写进 `Cargo.toml` 会让 `cargo test` 链接失败。
3. **CI 测试链路改为「构建 wheel → 装 wheel → pytest」**：CI 没有 venv，`maturin develop` 用不了；
   顺带把打包本身也纳入验证。
4. **manylinux 的 cmake 未能在真容器里实测**：本机无 docker、podman 拉不到 maturin 镜像 →
   改为幂等安装兜底 + 无条件 `cmake --version`，让首跑把答案变成事实。
5. **SM2 签名性能**：库级 1395 ops/s 低于 C 层基线 2538 ops/s，根因是每次调用重建 PKCS#8
   （GmSSL 校验公钥字段 = 一次额外 EC 乘法）；已登记为后续可选优化（设计 §10）。
