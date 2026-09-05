//! NOT a fuzz target — a one-shot seed emitter for Target A (process_stateful). Builds the fixture once
//! and writes its two VALID templates (valid_commit, valid_app) into the given corpus dir, so libFuzzer
//! starts from real, decryptable messages and mutates toward the crypto-deep edges. Run once before the
//! campaign:  cargo run --bin emit_seeds -- <corpus-dir>
fn main() {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "corpus/process_stateful".to_string());
    kvant_mls::fuzz_api::emit_seeds_a(&dir);
    eprintln!("emitted Target-A seeds into {dir}");
}
