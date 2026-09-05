# build-mls-aar.ps1 — cross-compile kvant-mls for Android (arm64 + x86_64), drop the .so into the
# app's jniLibs, and generate the uniffi Kotlin bindings. Run from this crate dir AFTER the toolchain
# install (rustup targets + cargo-ndk + uniffi-bindgen + ANDROID_NDK_HOME set).
#
# Build flow: (1) host `cargo build` FIRST to resolve deps + confirm the X-Wing ciphersuite exists
# (fix Cargo.toml/lib.rs against the real API, commit Cargo.lock); THEN (2) this script for Android.
$ErrorActionPreference = "Stop"
$crate    = Split-Path -Parent $PSScriptRoot
$appMain  = Join-Path $crate "..\app\src\main"
$jniLibs  = Join-Path $appMain "jniLibs"
$ktOut    = Join-Path $appMain "java"   # uniffi generates com/kvantrn/mls/... bindings here

Write-Host "== 1/3 host build (resolve deps + verify X-Wing ciphersuite) =="
cargo build --release
if ($LASTEXITCODE -ne 0) { throw "host build failed — fix Cargo.toml/lib.rs against the real OpenMLS API, then re-run" }

Write-Host "== 2/3 cross-compile .so for arm64-v8a + x86_64 (minSdk 26) =="
# cargo-ndk maps Android ABIs → Rust targets and places .so under jniLibs/<abi>/.
cargo ndk -t arm64-v8a -t x86_64 -P 26 -o $jniLibs build --release
if ($LASTEXITCODE -ne 0) { throw "cargo-ndk cross-compile failed (libcrux-on-ARM is the #1 risk to verify here)" }

Write-Host "== 3/3 generate uniffi Kotlin bindings from the built library =="
$soArm = Join-Path $jniLibs "arm64-v8a\libkvant_mls.so"
# Use the IN-CRATE bindgen (cargo run --bin uniffi-bindgen) so it's the exact uniffi version.
cargo run --bin uniffi-bindgen -- generate --library $soArm --language kotlin --out-dir $ktOut
if ($LASTEXITCODE -ne 0) { throw "uniffi-bindgen failed" }

# ⛔ ЗДЕСЬ БЫЛО КОПИРОВАНИЕ МОСТА, И ОНО БЫЛО МИНОЙ.
#
# Скрипт клал `kvant-mls/android/KvantMlsModule.kt` ПОВЕРХ рабочего
# `app/src/main/java/com/kvantrn/KvantMlsModule.kt`. Вторая копия жила отдельно и отставала: на
# 2026-08-11 это записали в IOS-PORT-ANALYSIS как 🟡 «запуск as-written регрессирует B1» — и не
# починили. К 2026-08-27 отставание выросло с одного слоя B1 до ДЕВЯТИ методов: весь мост C4
# (m3PeekFrame / m3MergePending / m3ClearPending / m3GroupEpoch / m3GroupStateFp), m3Drop, m3IsLive,
# m3KekForm и m3SetGroupRoles. То есть сборка .so молча отменила бы многоадминные гонки и проверку
# полномочий на состав — правки, которые именно этой сборкой и вводятся в строй.
#
# Источник истины ОДИН: файл в app/src/main/java. Устаревшая копия удалена, шаг убран, а сторож
# (kvant-mls/bridge-single-source.test.mjs) краснеет, если вторая копия появится снова.

Write-Host "== 4/4 ЭФФЕКТ, А НЕ ОТЧЁТ: биндинг и бинарь обязаны совпасть =="
# Дисциплина та же, что в mlsSelfHeal: «сделано» заявляется после ПЕРЕЧИТЫВАНИЯ результата, а не
# после того, как все шаги вернули ноль. Здесь это дёшево и ловит настоящий отказ: uniffi сверяет
# контрольные суммы биндинга и бинаря ПРИ ЗАГРУЗКЕ, то есть рассинхрон всплывает на устройстве
# (apiChecksumMismatch) — а тут он всплывает на сборке, у того, кто его создал.
$ktFile = Join-Path $ktOut "uniffi\kvant_mls\kvant_mls.kt"
if (-not (Test-Path $ktFile)) { throw "биндинг не сгенерирован: $ktFile" }
foreach ($abi in @("arm64-v8a", "x86_64")) {
  $so = Join-Path $jniLibs "$abi\libkvant_mls.so"
  if (-not (Test-Path $so)) { throw "нет .so для $abi — cargo-ndk отработал не полностью" }
  $bytes = [System.IO.File]::ReadAllBytes($so)
  $text  = [System.Text.Encoding]::ASCII.GetString($bytes)
  $syms  = [regex]::Matches((Get-Content $ktFile -Raw), 'uniffi_kvant_mls_checksum_[a-z_0-9]+') |
           ForEach-Object { $_.Value } | Sort-Object -Unique
  if ($syms.Count -lt 10) { throw "в биндинге подозрительно мало контрольных сумм ($($syms.Count)) — проверять нечем" }
  $missing = @($syms | Where-Object { -not $text.Contains($_) })
  if ($missing.Count -gt 0) {
    throw "$abi : биндинг ссылается на $($missing.Count) символ(ов), которых в .so НЕТ — например $($missing[0]). Это тот самый рассинхрон, который иначе увидит только устройство."
  }
  Write-Host ("   {0}: {1} контрольных сумм биндинга найдено в .so" -f $abi, $syms.Count)
}

Write-Host "✅ done. .so → $jniLibs ; uniffi-биндинги → $ktOut"
Write-Host "   Мост KvantMlsModule.kt НЕ копируется и не трогается — он живёт в app/src/main/java"
Write-Host "   как единственный источник; сторож kvant-mls/bridge-single-source.test.mjs это держит."
Write-Host "   Дальше: собрать APK (compileReleaseKotlin ДО установки) и записать провенанс."
