#!/usr/bin/env bash
# Campaign status — crash-free? coverage growing or plateau? how many execs, how many workers? Safe to run
# anytime from any shell (reads tee'd logs + corpus mtimes + live PIDs; independent of tmux). Plateau proxy:
# libFuzzer writes a NEW corpus file only when an input expands coverage, so "last new edge" age == time
# since coverage last grew. Exit per lane: last-new-edge > 24h (plateau) AND 48h crash-free elapsed.
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
LOGDIR="$HOME/kvant-fuzz/logs"
TGT="x86_64-unknown-linux-gnu/release"
now=$(date +%s)
age() { local s=$(( now - $1 )); printf '%dh%02dm' $(( s/3600 )) $(( (s%3600)/60 )); }

row() { # row <session> <lane> <corpus-target> <artifact-dir> <binpat> [corpus-base]
  local sess="$1" lane="$2" ct="$3" art="$4" binpat="$5" cbase="${6:-$HOME/kvant-fuzz/corpus}"
  # prefer the fast ext4 working corpus; fall back to the repo copy (e.g. for an un-migrated lane like id)
  local corp="$DIR/corpus/$ct"
  [ -d "$cbase/$ct" ] && corp="$cbase/$ct"
  # this lane's worker logs (multi-worker .wN.log, or legacy single .log)
  local logs=()
  compgen -G "$LOGDIR/$lane.w*.log" >/dev/null 2>&1 && logs=("$LOGDIR/$lane".w*.log)
  [ ${#logs[@]} -eq 0 ] && [ -f "$LOGDIR/$lane.log" ] && logs=("$LOGDIR/$lane.log")

  echo "──── $sess  [$lane] ────"
  # workers: live PIDs vs intended
  local live intended=0
  live=$(pgrep -fc "$binpat" 2>/dev/null || echo 0)
  [ -f "$LOGDIR/$lane.workers" ] && intended=$(cat "$LOGDIR/$lane.workers")
  if [ "$live" -gt 0 ]; then echo "  state   : RUNNING · workers $live/$intended"
  else echo "  state   : STOPPED ⚠  workers 0/$intended  (crashed/finished/not-launched — check)"; fi
  [ -f "$LOGDIR/$lane.start" ] && echo "  elapsed : $(age "$(cat "$LOGDIR/$lane.start")")  (need 48h crash-free)"
  # crashes
  local nc=0; [ -d "$art" ] && nc=$(find "$art" -type f -name 'crash-*' 2>/dev/null | wc -l)
  if [ "$nc" -eq 0 ]; then echo "  crashes : 0  (crash-free ✓)"
  else echo "  crashes : $nc  🔴 REPRODUCERS:"; find "$art" -type f -name 'crash-*' 2>/dev/null | sed 's/^/              /'; fi
  # 🔴 EDGE-coverage plateau — THE real criterion ("24h без новых рёбер"). cov = edges (code). If cov is
  # flat across recent pulses, all reachable code is covered = plateau. (The corpus "last new input" below
  # ALSO counts new value-profile FEATURES, which tail off forever and are NOT new edges — don't confuse them.)
  if [ ${#logs[@]} -gt 0 ]; then
    local covs maxcov atmax tot
    covs=$(cat "${logs[@]}" 2>/dev/null | grep -aoE 'cov: [0-9]+' | grep -oE '[0-9]+')
    maxcov=$(printf '%s\n' "$covs" | sort -n | tail -1)
    if [ -n "$maxcov" ]; then
      tot=$(printf '%s\n' "$covs" | tail -2000 | grep -c .)
      atmax=$(printf '%s\n' "$covs" | tail -2000 | grep -c "^$maxcov$")
      echo "  edges   : cov=$maxcov · flat in $atmax/$tot recent pulses  ($([ "$atmax" = "$tot" ] && echo 'EDGES PLATEAUED ✓' || echo 'edges still moving'))"
    fi
  fi
  # corpus growth (NOTE: new files include value-profile features, NOT only new edges — see edges above)
  if [ -d "$corp" ]; then
    local n newest
    n=$(find "$corp" -type f 2>/dev/null | wc -l)
    newest=$(find "$corp" -type f -printf '%T@\n' 2>/dev/null | sort -n | tail -1 | cut -d. -f1)
    if [ -n "$newest" ]; then echo "  corpus  : $n files · last new input $(age "$newest") ago (incl. ft, ≠ new edges)"
    else echo "  corpus  : $n files"; fi
  fi
  # aggregate exec/s across workers + latest cov/ft (from the freshest worker log)
  if [ ${#logs[@]} -gt 0 ]; then
    local sum fresh pulse
    sum=$(for l in "${logs[@]}"; do grep -aoE 'exec/s: [0-9]+' "$l" 2>/dev/null | tail -1 | grep -oE '[0-9]+'; done | awk '{s+=$1} END{print s+0}')
    fresh=$(ls -t "${logs[@]}" 2>/dev/null | head -1)
    pulse=$(grep -aE '^#[0-9]+' "$fresh" 2>/dev/null | tail -1 | grep -aoE 'cov: [0-9]+ ft: [0-9]+')
    echo "  speed   : ~${sum} exec/s aggregate · ${pulse:-no pulse yet}"
  fi
}

echo "════════ KVANT-MLS FUZZ CAMPAIGN @ $(date '+%Y-%m-%d %H:%M') ════════"
row fuzz-mls   mls_message_in   mls_message_in   "$DIR/artifacts/mls_message_in"  "fuzz run mls_message_in "
row fuzz-kp    key_package_in   key_package_in   "$DIR/artifacts/key_package_in" "fuzz run key_package_in "
row fuzz-id    decode_identity  decode_identity  "$DIR/artifacts/decode_identity" "fuzz run decode_identity"
row fuzz-msan  msan_mls         mls_message_in   "$DIR/artifacts/msan_mls"       "sanitizer memory mls_message_in"
# Tier-2 (stateful) lanes — separate corpus-tier2 tree; libcrux actually runs here.
T2="$HOME/kvant-fuzz/corpus-tier2"
if tmux has-session -t fuzz-t2-proc 2>/dev/null || [ -d "$T2" ]; then
  echo "════════ TIER-2 (stateful — libcrux exercised) ════════"
  row fuzz-t2-proc t2_proc process_stateful "$DIR/artifacts/process_stateful" "fuzz run process_stateful "        "$T2"
  row fuzz-t2-msan t2_msan process_stateful "$DIR/artifacts/t2_msan"          "sanitizer memory process_stateful" "$T2"
  row fuzz-t2-ops  t2_ops  op_sequence      "$DIR/artifacts/op_sequence"      "fuzz run op_sequence "             "$T2"
fi
echo "──────────────────────────────────────────────"
echo "tmux:"; tmux ls 2>/dev/null | sed 's/^/  /' || echo "  (no sessions)"
echo "attach live:  tmux attach -t fuzz-mls   (Ctrl-b d to detach)"
