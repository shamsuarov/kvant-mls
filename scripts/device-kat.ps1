# device-kat.ps1 — D1: build the standalone KAT runner (src/bin/kat.rs) for aarch64 from the CURRENT
# tree, push it to every connected Android device and verify the M1 auditor-pinned ML-KEM-768 vectors
# (pk c12e9e39… / ss 78dbb52f…, lib.rs PIN_*) reproduce BYTE-IDENTICALLY on each SoC.
#
# The runner links the exact same lib (same features, libcrux-ml-kem =0.0.10 portable path — simd128
# is not in the feature graph) as the production .so, so a PASS here is a PASS for the shipped code.
#
# Usage: powershell -File scripts\device-kat.ps1   (from anywhere; paths are script-relative)
$ErrorActionPreference = "Stop"
$crate = Split-Path -Parent $PSScriptRoot
$adb = "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe"
if (-not (Test-Path $adb)) { $adb = "adb" } # fall back to PATH

$PIN_PK = "c12e9e39db6758fc2ba63a638785b04f8efe3d7df23ba09803b4e39ba2fbc707"
$PIN_SS = "78dbb52f99672a2fee9001f5b7f0e91917551c7eb2137ca220058cc4918f9322"

Write-Host "== 1/3 cross-compile the KAT runner (aarch64-linux-android, release) =="
Push-Location $crate
cargo ndk -t arm64-v8a -P 26 build --release --bin kat
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "cargo-ndk build failed" }
Pop-Location
$bin = Join-Path $crate "target\aarch64-linux-android\release\kat"
$hash = (Get-FileHash $bin -Algorithm SHA256).Hash.ToLower()
Write-Host "runner: $bin"
Write-Host "sha256: $hash"

Write-Host "== 2/3 devices =="
$serials = (& $adb devices) | Select-Object -Skip 1 | Where-Object { $_ -match "\tdevice$" } | ForEach-Object { ($_ -split "\t")[0] }
if (-not $serials) { throw "no devices attached (adb devices is empty) — connect both phones (ROG6 USB / S10+ WiFi-adb) and re-run" }
Write-Host ("found: " + ($serials -join ", "))

Write-Host "== 3/3 run KAT on each device =="
$fail = $false
foreach ($s in $serials) {
    $model = (& $adb -s $s shell getprop ro.product.model).Trim()
    $soc   = (& $adb -s $s shell getprop ro.soc.model).Trim()
    $rel   = (& $adb -s $s shell getprop ro.build.version.release).Trim()
    $abi   = (& $adb -s $s shell getprop ro.product.cpu.abi).Trim()
    Write-Host "`n---- $s : $model / SoC=$soc / Android $rel / $abi ----"
    if ($abi -ne "arm64-v8a") { Write-Host "SKIP: not arm64-v8a"; continue }
    & $adb -s $s push $bin /data/local/tmp/kvant-kat | Out-Null
    & $adb -s $s shell chmod 755 /data/local/tmp/kvant-kat
    $out = & $adb -s $s shell /data/local/tmp/kvant-kat
    $out | ForEach-Object { Write-Host "  $_" }
    $pk = ($out | Select-String "KAT_PK_SHA256=(.*)").Matches.Groups[1].Value.Trim()
    $ss = ($out | Select-String "KAT_SS_SHA256=(.*)").Matches.Groups[1].Value.Trim()
    $ok = ($out | Select-String "KAT_PINNED_OK=(.*)").Matches.Groups[1].Value.Trim()
    $all = ($out | Select-String "DEVKAT_ALL_OK=(.*)").Matches.Groups[1].Value.Trim()
    if ($pk -eq $PIN_PK -and $ss -eq $PIN_SS -and $ok -eq "true" -and $all -eq "true") {
        Write-Host "  ✅ PASS on $model ($soc): ML-KEM byte-identical to the host PIN + AEAD/sig vectors OK"
    } else {
        Write-Host "  ❌ FAIL on $model ($soc): see the vector lines above — STOP, report (no rebuild-until-green)"
        $fail = $true
    }
    & $adb -s $s shell rm -f /data/local/tmp/kvant-kat
}
if ($fail) { exit 1 }
Write-Host "`n✅ device-KAT: all connected arm64 devices byte-identical (runner sha256 $hash)"
