#!/usr/bin/env bash
# Launch / re-launch the long Tier-1 fuzz campaign: 3 ASAN targets + 1 MSAN(codec) lane, each a DETACHED
# tmux session running N parallel workers over a SHARED, PRESERVED corpus on the fast ext4 FS. Plus a
# fuzz-sync session mirroring ext4 → repo. tmux daemonizes → all of it survives this shell, the launching
# session, and the WSL console closing. Idempotent: a lane whose tmux session already exists is SKIPPED
# (so a plateaued / continuous lane like decode_identity is left undisturbed). Re-tune a lane:
# `tmux kill-session -t <sess>` then re-run.
#
# Worker split tuned for the 13900KS (28 threads): mls = primary share, decode_identity = 1 (plateaued).
set -uo pipefail
# shellcheck disable=SC1091
source "$HOME/.cargo/env"
DIR="$(cd "$(dirname "$0")" && pwd)"
LANE_SH="$DIR/lanes/fuzz-lane.sh"

# One-time: migrate the accumulated repo corpus onto ext4 (preserves all; additive no-clobber). Fast after
# the first run. Workers then reload from ext4 instead of the slow 9p /mnt/c bridge.
migrate() { local t="$1"; mkdir -p "$HOME/kvant-fuzz/corpus/$t"; cp -an "$DIR/corpus/$t/." "$HOME/kvant-fuzz/corpus/$t/" 2>/dev/null || true; }
echo "[corpus] migrating accumulated corpus → ext4 (one-time, preserves every file)…"
migrate mls_message_in
migrate key_package_in
echo "[corpus] done."

up() { # up <session> <lane-id> <target> <mode> <workers>
  local s="$1"
  if tmux has-session -t "$s" 2>/dev/null; then echo "[skip] $s already running (kill-session first to re-tune)"; return; fi
  tmux new-session -d -s "$s" "bash '$LANE_SH' '$2' '$3' '$4' '$5'"
  echo "[up]   $s  → $3 ($4) ×$5 workers"
}

up fuzz-mls   mls_message_in   mls_message_in   asan   12   # PRIMARY: WIRE deserialize (Welcome/Commit/App/GroupInfo)
up fuzz-kp    key_package_in   key_package_in   asan   6    # Add path
up fuzz-id    decode_identity  decode_identity  asan   1    # plateaued → just bank crash-free time
up fuzz-msan  msan_mls         mls_message_in   msan   4    # MSAN codec lane (portable libcrux)

# corpus mirror ext4 → repo (git-visibility + backup), every 30 min
if ! tmux has-session -t fuzz-sync 2>/dev/null; then
  tmux new-session -d -s fuzz-sync "bash '$DIR/sync-corpus.sh'"
  echo "[up]   fuzz-sync (ext4 → repo corpus mirror, every 30m)"
fi

echo "--- launching; workers stagger in over a few seconds ---"
sleep 3
tmux ls 2>/dev/null || true
echo "monitor:  bash $DIR/status.sh"
