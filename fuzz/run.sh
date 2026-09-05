#!/usr/bin/env bash
# Build + run ONE Tier-1 fuzz target under ASAN (the primary sanitizer).
#
#   ./run.sh <target> [smoke|<seconds>]
#       <target>  decode_identity | mls_message_in | key_package_in
#       smoke     ~25s seeded proof-of-life, must stay crash-free (default)
#       <seconds> a longer bounded run (e.g. 3600). The 24-48h campaign is `<seconds>=0` (unbounded)
#                 inside tmux/nohup — see README "Exit criteria".
#
# overflow-checks + debug-assertions are baked into fuzz/Cargo.toml's [profile.release], so an integer
# overflow in a vector-count/length computation panics (libFuzzer catches it) instead of wrapping.
# Build out-of-tree on the Linux FS — /mnt/c (9p) is slow for cargo's many small writes.
set -euo pipefail
# shellcheck disable=SC1091
source "$HOME/.cargo/env"
cd "$(dirname "$0")"

TARGET="${1:?usage: run.sh <target> [smoke|seconds]}"
MODE="${2:-smoke}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/kvant-mls-fuzz-target}"

SECS=25
[ "$MODE" != "smoke" ] && SECS="$MODE"

echo "[run] target=$TARGET asan max_total_time=${SECS}s target_dir=$CARGO_TARGET_DIR"
# `cargo +nightly fuzz` → nightly toolchain (sanitizer support). corpus/<target> is the seed dir.
exec cargo +nightly fuzz run "$TARGET" -- -max_total_time="$SECS" -print_final_stats=1
