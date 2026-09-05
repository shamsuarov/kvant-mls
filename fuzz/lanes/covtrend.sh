#!/usr/bin/env bash
# Diagnose mls plateau: is EDGE coverage (cov) flat (true code-coverage plateau) while only FEATURES (ft)
# keep growing (value-profile/counter long tail)? cov flat ⇒ all reachable code is covered.
set -uo pipefail
for w in 1 6 12; do
  L="$HOME/kvant-fuzz/logs/mls_message_in.w$w.log"
  [ -f "$L" ] || continue
  echo "==== worker $w  ($(wc -l < "$L") lines) ===="
  echo "first: $(grep -aoE 'cov: [0-9]+ ft: [0-9]+' "$L" | head -1)"
  echo "last : $(grep -aoE 'cov: [0-9]+ ft: [0-9]+' "$L" | tail -1)"
  echo "cov distribution over the LAST 3000 pulses (count × cov-value):"
  grep -aoE 'cov: [0-9]+' "$L" | tail -3000 | sort | uniq -c | tail -8
done
echo "==== global max cov (edges) across all 12 mls workers ===="
cat "$HOME"/kvant-fuzz/logs/mls_message_in.w*.log 2>/dev/null | grep -aoE 'cov: [0-9]+' | grep -oE '[0-9]+' | sort -n | tail -1
echo "==== global max ft (features) across all 12 mls workers ===="
cat "$HOME"/kvant-fuzz/logs/mls_message_in.w*.log 2>/dev/null | grep -aoE 'ft: [0-9]+' | grep -oE '[0-9]+' | sort -n | tail -1
