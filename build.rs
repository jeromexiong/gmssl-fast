//! 构建脚本：只为 Windows/MSVC 放宽链接。
//!
//! crates.io 上的 `gmssl-rs` 0.1.1 声明了两个 **GmSSL 3.2.0 才有**的符号：
//! `x509_key_cleanup` 与 `zuc256_generate_keystream`（在 3.1.1 里后者只是
//! `zuc.h` 里的一个宏）。而它依赖的 `gmssl-rs-sys` 0.1.0 构建的是 **GmSSL 3.1.1**
//! ——这一对在 crates.io 上本身就不自洽：
//!
//! - macOS / Linux：静态库按需取成员，那两个 CGU 没被拉进链接，所以能过；
//! - Windows/MSVC：随 CGU 一起被拉进来，于是
//!   `error LNK2019: unresolved external symbol x509_key_cleanup / zuc256_generate_keystream`
//!   → `fatal error LNK1120: 2 unresolved externals`。
//!
//! 本库只暴露 SM2 / SM3 / SM4，不暴露 X509 / ZUC，这两个符号不会被调用，
//! 所以让链接器放行而不是去动上游字节。
//!
//! ⚠️ 代价要说清楚：**真缺符号时不再在链接期失败，而是到调用时才崩**。
//! 因此 CI 的 Windows 腿必须「装真轮子 + 跑 pytest」（见
//! `.github/workflows/build.yml` 的「Windows 冒烟 + 全量测试」步骤），
//! 由运行期证据兜底，而不是靠这行链接参数自证。
fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        println!("cargo:rustc-link-arg=/FORCE:UNRESOLVED");
    }
}
