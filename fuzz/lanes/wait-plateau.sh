#!/usr/bin/env bash
# Wait until decode_identity crosses the 24h coverage-plateau: the newest corpus file (== last coverage-
# increasing input) is >= 24h old. Polls once a minute, reports the moment it crosses (or NOT_YET if the
# poll window elapses first). decode_identity corpus is on /mnt/c (it was never migrated to ext4).
set -uo pipefail
CORP="$HOME/kvant-fuzz/corpus/decode_identity"
[ -d "$CORP" ] || CORP="/mnt/c/Users/<you>/kvant/app-rn/android/kvant-mls/fuzz/corpus/decode_identity"
for _ in $(seq 1 75); do   # ~75 min ceiling
  now=$(date +%s)
  newest=$(find "$CORP" -type f -printf '%T@\n' 2>/dev/null | sort -n | tail -1 | cut -d. -f1)
  if [ -n "$newest" ]; then
    age=$(( now - newest ))
    if [ "$age" -ge 86400 ]; then
      printf 'PLATEAU_CROSSED decode_identity last-new-edge=%dh%02dm (>=24h) at %s\n' \
        $(( age/3600 )) $(( (age%3600)/60 )) "$(date '+%Y-%m-%d %H:%M')"
      exit 0
    fi
  fi
  sleep 60
done
echo "NOT_YET after poll window (relaunch)"
