#!/usr/bin/env bash
# Re-tune worker counts WITHOUT resetting the crash-free clock or the corpus. The binary is unchanged, the
# corpus is the shared ext4 dir, and fuzz-lane.sh preserves <lane>.start — so only the worker PROCESSES
# restart; the 48h clock keeps counting and no corpus is lost. decode_identity (fuzz-id) is left untouched
# and continuous. Use to free cores for gaming, then restore.
#   Usage:  scale.sh <mls-workers> <kp-workers> <msan-workers>
#   Game :  scale.sh 4 2 2        (≈9 fuzz threads incl id → ~19 free for Dota)
#   Full :  scale.sh 12 6 4       (back to full campaign)
set -uo pipefail
# shellcheck disable=SC1091
source "$HOME/.cargo/env"
DIR="$(cd "$(dirname "$0")" && pwd)"
LANE_SH="$DIR/lanes/fuzz-lane.sh"
MLS="${1:?usage: scale.sh <mls> <kp> <msan>}"; KP="${2:?}"; MSAN="${3:?}"

retune() { # retune <session> <lane> <target> <mode> <workers>
  tmux kill-session -t "$1" 2>/dev/null && echo "  killed $1" || true
  sleep 1
  tmux new-session -d -s "$1" "bash '$LANE_SH' '$2' '$3' '$4' '$5'"
  echo "  $1 → ×$5 workers (clock + corpus preserved)"
}

echo "[scale] re-tuning mls=$MLS kp=$KP msan=$MSAN (decode_identity untouched)…"
retune fuzz-mls  mls_message_in mls_message_in asan "$MLS"
retune fuzz-kp   key_package_in key_package_in asan "$KP"
retune fuzz-msan msan_mls       mls_message_in msan "$MSAN"
sleep 2
tmux ls 2>/dev/null || true
echo "monitor: bash $DIR/status.sh"
