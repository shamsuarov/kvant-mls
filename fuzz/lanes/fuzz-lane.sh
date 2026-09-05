#!/usr/bin/env bash
# One fuzz LANE = N parallel libFuzzer workers over a SHARED corpus. libFuzzer's default -reload=1 cross-
# pollinates: each worker writes coverage-increasing inputs into the corpus dir, the others reload them —
# so N independent instances on one corpus dir == native -jobs parallelism, with cleaner per-worker logs.
#   Usage: fuzz-lane.sh <lane-id> <target> <asan|msan> <workers>
#
# 🔴 Working corpus lives on the WSL ext4 FS (~/kvant-fuzz/corpus/<target>), NOT /mnt/c — the 9p bridge is
#    far too slow for N workers reloading a large corpus. ext4 PERSISTS across reboots, and sync-corpus.sh
#    mirrors it back to the repo (fuzz/corpus) every 30 min for git-visibility + backup. The corpus is
#    SHARED + PRESERVED, never reset (campaign.sh seeds ext4 from the accumulated repo corpus once).
# 🔴 The 48h-crash-free START STAMP is preserved across restarts (same binary → adding workers is stronger
#    crash-free evidence, not a new build → the clock must NOT reset). Per-worker log: <lane>.w<i>.log.
set -uo pipefail
# shellcheck disable=SC1091
source "$HOME/.cargo/env"

LANE="${1:?usage: fuzz-lane.sh <lane> <target> <asan|msan> <workers>}"
TARGET="${2:?missing target}"
MODE="${3:-asan}"
WORKERS="${4:-1}"
FUZZ_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LOGDIR="$HOME/kvant-fuzz/logs"; mkdir -p "$LOGDIR"
cd "$FUZZ_DIR"

[ -f "$LOGDIR/$LANE.start" ] || date +%s > "$LOGDIR/$LANE.start"   # preserve the crash-free clock on restart
echo "$WORKERS" > "$LOGDIR/$LANE.workers"

LF=(-max_total_time=0 -rss_limit_mb=4096)
# CORPUS_BASE lets a separate campaign (e.g. Tier-2) use its OWN ext4 corpus tree without touching the
# Tier-1 corpus. Default = the Tier-1 location, so Tier-1 lanes are byte-for-byte unchanged.
CORPUS="${CORPUS_BASE:-$HOME/kvant-fuzz/corpus}/$TARGET"   # fast ext4 working corpus, SHARED by all workers of this target
mkdir -p "$CORPUS"
# seed ext4 from the accumulated repo corpus only if ext4 is still empty (campaign.sh normally migrates first)
[ -z "$(ls -A "$CORPUS" 2>/dev/null)" ] && cp -an "$FUZZ_DIR/corpus/$TARGET/." "$CORPUS/" 2>/dev/null || true

if [ "$MODE" = "msan" ]; then
  export CARGO_TARGET_DIR="$HOME/.cache/kvant-mls-fuzz-msan"
  export RUSTFLAGS="-C target-feature=-avx2,-avx,-sse4.2 ${RUSTFLAGS:-}"
  ART="$FUZZ_DIR/artifacts/$LANE"
else
  export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/kvant-mls-fuzz-target}"
  ART="$FUZZ_DIR/artifacts/$TARGET"
fi
mkdir -p "$ART"   # crashes land in the repo (rare writes; want them visible immediately)

echo "[lane $LANE] launching $WORKERS× $MODE worker(s) on $TARGET, ext4 corpus $CORPUS"
for i in $(seq 1 "$WORKERS"); do
  if [ "$MODE" = "msan" ]; then
    cargo +nightly fuzz run --sanitizer memory "$TARGET" "$CORPUS" -- "${LF[@]}" -artifact_prefix="$ART/" \
      > "$LOGDIR/$LANE.w$i.log" 2>&1 &
  else
    cargo +nightly fuzz run "$TARGET" "$CORPUS" -- "${LF[@]}" -artifact_prefix="$ART/" \
      > "$LOGDIR/$LANE.w$i.log" 2>&1 &
  fi
  sleep 1   # stagger so N workers don't stampede the cargo build-dir lock at startup
done
echo "[lane $LANE] all workers launched (pids: $(jobs -p | tr '\n' ' '))"
wait   # hold the tmux session open while the workers run
