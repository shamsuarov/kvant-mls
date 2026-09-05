#!/usr/bin/env bash
# One-time, NO-SUDO bootstrap of the fuzzing toolchain inside WSL Ubuntu.
# Installs rustup (stable + nightly + rust-src) and cargo-fuzz into ~/.cargo and ~/.rustup. Needs only
# g++/make/curl (already present on this box). Idempotent — safe to re-run.
#
# Why WSL: cargo-fuzz / libFuzzer need -Zsanitizer (nightly) and a Unix sanitizer runtime; the Windows
# MSVC toolchain cannot do it, and MSAN is Linux-only. ASAN's runtime ships inside rustc-nightly, and
# libFuzzer is built from libfuzzer-sys's vendored sources with g++ — so NO sudo / apt is required.
set -euo pipefail

if ! command -v rustup >/dev/null 2>&1; then
  echo "[bootstrap] installing rustup (no sudo)…"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable --profile minimal
fi
# shellcheck disable=SC1091
source "$HOME/.cargo/env"

echo "[bootstrap] installing nightly + rust-src (cargo-fuzz builds std with the sanitizer)…"
rustup toolchain install nightly --profile minimal -c rust-src

if ! command -v cargo-fuzz >/dev/null 2>&1; then
  echo "[bootstrap] installing cargo-fuzz…"
  cargo install cargo-fuzz
fi

echo "[bootstrap] DONE:"
rustc +nightly --version
cargo fuzz --version
