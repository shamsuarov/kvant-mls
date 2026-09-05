#!/usr/bin/env bash
# Edge-coverage (cov) plateau check across all lanes: is cov flat (true code-coverage plateau) while only
# ft grows? Reports per lane: first/last cov-ft + how long cov has been at its max (the real plateau age).
set -uo pipefail
check() { # check <lane> <logglob>
  local lane="$1"; shift
  local logs=( "$@" )
  local merged="/tmp/.cov_$lane"
  cat "${logs[@]}" 2>/dev/null | grep -aoE 'cov: [0-9]+ ft: [0-9]+' > "$merged" || true
  [ -s "$merged" ] || { echo "==== $lane: no data ===="; return; }
  local maxcov
  maxcov=$(grep -oE 'cov: [0-9]+' "$merged" | grep -oE '[0-9]+' | sort -n | tail -1)
  echo "==== $lane ===="
  echo "  max cov (edges) : $maxcov"
  echo "  max ft (features): $(grep -oE 'ft: [0-9]+' "$merged" | grep -oE '[0-9]+' | sort -n | tail -1)"
  # of the pulses at max cov, how many vs total → how saturated
  local atmax total
  total=$(wc -l < "$merged")
  atmax=$(grep -c "cov: $maxcov " "$merged" || echo 0)
  echo "  pulses at max-cov: $atmax / $total"
  echo "  last line: $(tail -1 "$merged")"
}
check decode_identity "$HOME"/kvant-fuzz/logs/decode_identity.log "$HOME"/kvant-fuzz/logs/decode_identity.w*.log
check mls_message_in  "$HOME"/kvant-fuzz/logs/mls_message_in.w*.log
check key_package_in  "$HOME"/kvant-fuzz/logs/key_package_in.w*.log
check msan_mls        "$HOME"/kvant-fuzz/logs/msan_mls.w*.log
