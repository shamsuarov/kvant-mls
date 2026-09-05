#!/usr/bin/env bash
# Poll the MSAN lane log until it either starts fuzzing (libFuzzer banner / pulse) or fails to build,
# then print the tail. Used once after launch to resolve MSAN's fate (MSAN + libfuzzer-sys is fragile).
L="$HOME/kvant-fuzz/logs/msan_mls.log"
for _ in $(seq 1 90); do   # up to ~6 min
  if grep -qaE 'INFO: Running|INFO: Seed|INFO: .*loaded|^#[0-9]+|error\[|error:|^error|SUMMARY: MemorySanitizer|cannot find|undefined reference|MemorySanitizer: use-of-uninitialized' "$L" 2>/dev/null; then
    break
  fi
  sleep 4
done
echo "=== MSAN verdict tail ==="
tail -30 "$L" 2>/dev/null
echo "=== running? ==="
if grep -qaE '^#[0-9]+|INFO: Running|INFO: Seed' "$L" 2>/dev/null && ! grep -qaE 'error\[|^error:|SUMMARY: MemorySanitizer' "$L" 2>/dev/null; then
  echo "MSAN_FUZZING_OK"
else
  echo "MSAN_NOT_FUZZING (built-failed or sanitizer-error — see tail)"
fi
