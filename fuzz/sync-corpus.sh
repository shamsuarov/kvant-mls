#!/usr/bin/env bash
# Mirror the fast ext4 working corpus (~/kvant-fuzz/corpus) back into the repo (fuzz/corpus) every 30 min,
# for git-visibility and an extra backup. ext4 is the live source of truth during the run (and persists
# across reboots); the repo copy is a periodic snapshot. ADDITIVE ONLY (cp -an / no --delete): never
# removes an accumulated input. Runs in its own tmux session (fuzz-sync).
set -uo pipefail
FUZZ_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK="$HOME/kvant-fuzz/corpus"
while true; do
  if [ -d "$WORK" ]; then
    for d in "$WORK"/*/; do
      [ -d "$d" ] || continue
      t="$(basename "$d")"
      mkdir -p "$FUZZ_DIR/corpus/$t"
      cp -an "$d." "$FUZZ_DIR/corpus/$t/" 2>/dev/null || true
    done
    echo "[sync $(date '+%Y-%m-%d %H:%M')] ext4 → repo corpus mirrored"
  fi
  sleep 1800
done
