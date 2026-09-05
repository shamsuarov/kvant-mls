// In-crate uniffi-bindgen — guarantees the binding generator is the EXACT same uniffi version as the
// runtime (a separately-installed uniffi-bindgen that drifts a patch version fails to generate).
// Run via: cargo run --bin uniffi-bindgen -- generate --library <so> --language kotlin --out-dir <dir>
fn main() {
    uniffi::uniffi_bindgen_main()
}
