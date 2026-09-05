#!/usr/bin/env bash
# Tier-2 (STATEFUL) campaign — SEPARATE from the Tier-1 campaign.sh and its corpus. Feeds (mutated) VALID
# MLS messages / op-programs into the VERIFIED spike so libcrux actually runs (HPKE/AEAD/ML-KEM/Ed25519 —
# the Route-2 paths Tier-1 never exercised). Detached tmux sessions, N workers over a SHARED ext4 corpus.
#
# 🔴 Tier-2 corpus lives under ~/kvant-fuzz/corpus-tier2/<target> (CORPUS_BASE) — the Tier-1 corpus is
#    NEVER touched. The 48h-crash-free start stamp is preserved across restarts (same binary).
# Lanes (13900KS / 28 threads; Tier-1 idle after closure so Tier-2 takes the share):
#   fuzz-t2-proc   process_stateful  asan  ×8   — Target A, primary (libcrux-dense single-message)
#   fuzz-t2-msan   process_stateful  msan  ×4   — Target A under portable libcrux (NOW meaningful: libcrux runs)
#   fuzz-t2-ops    op_sequence       asan  ×4   — Target B (op programs; consistency + PCS invariants; costlier)
set -uo pipefail
# shellcheck disable=SC1091
source "$HOME/.cargo/env"
DIR="$(cd "$(dirname "$0")" && pwd)"
LANE_SH="$DIR/lanes/fuzz-lane.sh"
export CORPUS_BASE="$HOME/kvant-fuzz/corpus-tier2"

# Seed Target A from the emitted valid templates if the ext4 corpus is still empty (op_sequence self-seeds).
mkdir -p "$CORPUS_BASE/process_stateful" "$CORPUS_BASE/op_sequence"
if [ -z "$(ls -A "$CORPUS_BASE/process_stateful" 2>/dev/null)" ]; then
  echo "[seed] emitting Target-A valid templates → $CORPUS_BASE/process_stateful"
  ( cd "$DIR" && cargo +nightly build --release --bin emit_seeds >/dev/null 2>&1 \
    && ./target/release/emit_seeds "$CORPUS_BASE/process_stateful" ) || echo "[seed] emit failed (continuing; libFuzzer will bootstrap)"
fi

up() { # up <session> <lane-id> <target> <mode> <workers>
  local s="$1"
  if tmux has-session -t "$s" 2>/dev/null; then echo "[skip] $s already running (kill-session first to re-tune)"; return; fi
  tmux new-session -d -s "$s" "CORPUS_BASE='$CORPUS_BASE' bash '$LANE_SH' '$2' '$3' '$4' '$5'"
  echo "[up]   $s  → $3 ($4) ×$5 workers"
}

up fuzz-t2-proc  t2_proc  process_stateful  asan  8
up fuzz-t2-msan  t2_msan  process_stateful  msan  4
up fuzz-t2-ops   t2_ops   op_sequence       asan  4

echo "--- Tier-2 launching; workers stagger in over a few seconds ---"
sleep 3
tmux ls 2>/dev/null | grep -E 't2|sync' || true
echo "monitor:  bash $DIR/status.sh    (Tier-2 lanes: t2_proc / t2_msan / t2_ops)"
