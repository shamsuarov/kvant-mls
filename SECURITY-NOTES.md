# kvant-mls — security dependency notes (M2 backlog)

> UNTRACKED, like the rest of the spike. For the auditor + the M2 plan. Created 2026-06-30 after a
> `cargo audit` / `npm audit` / `gitleaks` sweep run alongside the Tier-1 fuzz campaign.

## ✅ Tier-1 fuzz — EXIT SUMMARY (closed on the PRIMARY criterion, not the floor)

> ### 🔒 CLOSED 2026-07-01
> **Tier-1 deserialize fuzzing formally CLOSED.** 63h13m crash-free on all 4 lanes (criterion 48h — met with
> +15h margin), edge-coverage plateau on every target (cov FLAT 2000/2000 recent pulses: `mls_message_in`
> 2191, `key_package_in` 1212, `decode_identity` 160, MSAN `mls_message_in` 2210), **0 defects** under
> ASAN + overflow-checks + debug-assertions, **0 uninitialised reads** under MSAN (portable libcrux), 1e9-execs
> floor exceeded (~10¹⁰). `artifacts/` empty (no crash/leak/timeout). Final corpus preserved: **mls_message_in
> 169,092 + key_package_in 44,570** (ext4 `~/kvant-fuzz/corpus`, persists across reboots; mirrored into the
> repo `fuzz/corpus/` for Tier-2/resume). Campaign stopped, all tmux/fuzz processes terminated, PC freed.
>
> **Auditor statement (FULL primary criterion, NOT the floor):** *Tier-1 deserialize fuzzing — edge-coverage
> plateau + 48h+ crash-free + zero defects under ASAN / overflow-checks / MSAN.*
>
> **Residual (post-vacation):** ~~Tier-2 stateful fuzz~~ — **LAUNCHED 2026-08-05** after the Route-2 bump
> unblocked it (libcrux fixed). Harness = `client::fuzz` (feature=fuzzing) exposing the VERIFIED spike over
> a valid X-Wing fixture; two targets: **process_stateful (A)** = mutated-valid message → dispatch OUTSIDE
> guard (invariant 1 no-panic, invariant 2 Q4 fail-closed no-state-advance on Err), **op_sequence (B)** =
> program of ops over alice/bob/carol (consistency + PCS invariants). 3 tmux lanes on the 13900KS
> (t2_proc asan ×8 / t2_msan ×4 / t2_ops asan ×4), SEPARATE `~/kvant-fuzz/corpus-tier2` (Tier-1 corpus
> untouched). MSAN now MEANINGFUL (Tier-1 MSAN was near-idle — libcrux never ran; Tier-2 decrypts).
> Smoke green (A cov 3915 @169 exec/s, B cov 14674 @33 exec/s, 0 crashes). Exit criterion = same as Tier-1
> (edge-plateau + 48h crash-free + 0 defects). Monitor: `bash fuzz/status.sh` (Tier-2 section). commit 70e7736
> (fuzz-crate bump) + the harness commit.

Campaign: 4 lanes (3 ASAN targets + 1 MSAN codec lane), 12/6/1/4 → wound down to 2/2/1/2 once edges
saturated, WSL2 ext4 corpus, persistent tmux. Started 2026-06-29 ~03:14, closed 2026-07-01 (~63h).

**All 4 targets CLOSED on the PRIMARY criterion = edge-coverage plateau (≥24h, no new рёбра) + 48h crash-free.**
NOT the floor-compromise — the floor is only belt-and-suspenders.

- **Edge coverage flat ≥24h** (cov, across all 12 workers / >10⁹ execs): `decode_identity` **160**,
  `mls_message_in` **2191**, `key_package_in` **1212**, MSAN `mls_message_in` **2210**. Verified via
  `fuzz/lanes/covall.sh` — ~100% of recent pulses at max cov on every lane.
- **48h crash-free** under **ASAN + overflow-checks + debug-assertions**; `mls_message_in` additionally
  under **MSAN (portable libcrux)** — **zero defects, zero uninitialised reads.** (48h gate completes
  ~2026-07-01 03:30; edge-plateau already in hand well before.)
- **1e9-execs floor exceeded** (mls ~10¹⁰) — belt-and-suspenders, NOT the basis of closure.
- 🔴 **Honest caveat:** edge-plateau is the standard EMPIRICAL bar (24h flat across billions of execs), NOT
  a mathematical proof that no deeper edge exists. That is what a fuzzing plateau means, and exactly what
  the auditor specified.
- **Continued corpus growth after plateau = `ft` (value-profile feature diversity), NOT new edges** — the
  expected long tail of a length-prefixed wire format, not an open coverage gap. (Earlier confusion: the
  old `status.sh` "last new edge" actually counted new corpus files incl. features; fixed — it now reports
  `edges: cov=… EDGES PLATEAUED ✓` separately from feature growth.)
- **RESIDUAL (post-vacation):** Tier-2 stateful fuzz (feeds bytes through `process_message` → exercises
  libcrux) — gated behind the libcrux provider bump (Route 1 IMPOSSIBLE — see M2 ROUTE DECISION below).

**Exact wording for the auditor (claim no more than this):**
> *Tier-1 deserialize fuzzing: edge-coverage plateau + 48h crash-free + zero defects under ASAN /
> overflow-checks / MSAN. This is the FULL primary criterion — not the 1e9-execs floor alternative.*

---

## ✅ libcrux crypto provider — 4 HIGH advisories CLOSED on host (Route 2 EXECUTED 2026-08-05)

> ### ✅ ROUTE 2 EXECUTED 2026-08-05 — host-complete; device-KAT re-test pending (SoC session)
> Upstream released the needed provider **2026-08-03**: `openmls_libcrux_crypto 0.4.0-rc.1` +
> `openmls 0.9.0-rc.1` family (crates.io, no fork/vendor needed). Bumped the whole family, exact-pinned:
> openmls `=0.9.0-rc.1` (feature `draft-ietf-mls-pq-ciphersuites` — X-Wing 0x004D moved behind it, SAME
> name/code-point/wire), provider `=0.4.0-rc.1`, traits/memory_storage/basic_credential `=0.6.0-rc.1`,
> tls_codec `0.5`, libcrux-ml-kem `=0.0.10`.
> - **All 4 HIGH GONE** (`cargo audit` = 0 vulnerabilities): poly1305 0.0.4→0.0.6 (≥0.0.5 ✓),
>   chacha20poly1305 0.0.6+0.0.7→0.0.9 single (≥0.0.8 ✓), ed25519 0.0.6→0.0.9 (≥0.0.7 ✓). Only the 3
>   known *unmaintained* warnings remain (bincode/paste/proc-macro-error2, transitive, low).
> - **🎯 HOST KAT BYTE-IDENTICAL on libcrux-ml-kem 0.0.10** (moved 0.0.8→0.0.10 via libcrux-kem 0.0.9
>   exact pin): pk `c12e9e39db6758fc…` / ss `78dbb52f99672a2f…` — exactly the auditor-pinned M1 values.
>   ML-KEM output did NOT shift. **Device re-test on both SoC (ROG6 + S10+, portable/NEON path) still
>   MANDATORY at the device session** — host proves the AVX2 path only.
> - **API drift was minimal, 2 errors total**: (1) X-Wing behind the pq feature (Cargo.toml only);
>   (2) `ProcessedMessageContent` gained `OwnPendingCommit`/`OwnPrivateMessage` (own traffic fanned back
>   by a DS) → both handled FAIL-CLOSED in dispatch.rs (`DispatchReject::OwnEcho` — never auto-merge on
>   the receive path; kvant fan-out excludes self, own commits merge at send time).
>   `UnresolvedAppDataCommit` exists only behind `extensions-draft` — NOT enabled, not in our enum.
> - **Contract-2 StorageProvider trait 0.5→0.6 audited method-by-method**: 72 fns = 57 old + 15 new, but
>   ALL 18 gated additions (15× `virtual-clients-draft`, 3× `extensions-draft`, the latter existed in 0.5
>   as `extensions-draft-08`) are OFF in our build (resolved features verified = default+pq only) → the
>   COMPILED trait surface is IDENTICAL (54 abstract + meta `version()`, zero default bodies — nothing can
>   silently bypass the sealed writes). No classification change; LABEL_KEYSPACE untouched; all boundary
>   tests (freeze-on-reject / keyspace / atomicity) green. 🔴 KEEP `extensions-draft` +
>   `virtual-clients-draft` OFF — enabling either adds unclassified storage methods = Contract-2 re-audit.
> - **No unchecked constructors used** (0.9 added validation-bypass constructors; grep-verified absent).
> - Full suite **65/65 GREEN**, aarch64 + x86_64 cross-compile GREEN, app jniLibs .so refreshed both ABIs
>   (FFI surface unchanged → uniffi bindings untouched).
> - Residual: (a) device-KAT both SoC + M3 device test (one session); (b) move `=0.9.0-rc.1` pins to
>   final 0.9.0 when released (small delta); (c) **fuzz crate (WSL) still on the OLD family — needs the
>   same bump before Tier-2 stateful fuzz** (Tier-2 is otherwise UNBLOCKED now that libcrux is fixed);
>   (d) old sealed `mls-state.bin` blobs from pre-bump builds are NOT migration-tested across
>   openmls 0.8.1→0.9 serialization — irrelevant today (M3 never device-deployed, no real state exists).

## 🛡️ MLS-group ROLES (2026-08-05) — security model + honest residual

Owner-signed genesis + hash-chained role log (the Sender-Keys P0-1/P1 model on the MLS transport;
`crypto-core/mlsroles.js` over the audited `grouplog.js` REUSED AS-IS, 29/29). Key properties:
- **Anchor**: the owner's account Ed25519 pub is read from the MLS TREE (`member_account_keys` FFI,
  read-only) — every leaf entered via the ghost-defense validators, whose `verify_device_bundle`
  requires `cert.account_public_key == pinned key` (ct_eq) + a valid cert signature. A member cannot
  forge the anchor; a forged key never reaches the tree (fail-closed at Add/Welcome).
- **Downgrade protection**: non-owner entries = badsig; owner IMMUTABLE (entry.owner must equal the
  pinned genesis owner — canon-signed, plus an explicit check); replay → noop; rollback rejected;
  withheld entries → gap detected (state freezes at the last verified tip, fail-closed); owner
  equivocation → fork detected + rejected. Genesis pin = first-write-wins; conflicting genesis refused.
- **delete-for-all**: receive-side author-or-admin per the verified chain (member ✗ — tested); no
  pinned roles → author only. Send side stays authz-free (UI gates), like Sender-Keys.
- **🔴 HONEST RESIDUAL (v1, accepted)**: MLS membership COMMITS are NOT role-enforced in the Rust
  receive path — the UI gates add/remove by admin, but an insider bypassing the UI can still commit an
  Add. Ghost-defense still guarantees any added member is a GENUINE certified account (never a ghost);
  the risk class matches the Sender-Keys residual (insider roster-spam). Deterministic commit-authz
  requires roles in the GROUP STATE (a GroupContext extension — "Option A"), which today is blocked by
  the extensions-draft guard below. Also residual: owner-offline (roles freeze), tip-withhold
  detectability without out-of-band tip comparison (same class as P1 — logFingerprint parity later),
  gmreq-style admin requests (owner-only writes in v1).
- **🔴 GUARD (unchanged from Route-2)**: openmls `extensions-draft` / `virtual-clients-draft` STAY OFF —
  enabling either adds unclassified StorageProvider methods = a Contract-2 re-audit. Option A roles
  must NOT be implemented by flipping these flags casually.

## 🔑 Single-use MLS KeyPackage (2026-08-05) — done; 1:1 X3DH checked (NOT the same bug)

MLS KeyPackage was a single REUSABLE KP → one init_key reused across joins (forward-secrecy hole +
replay). FIXED: client publishes a POOL of 10 single-use KPs (`make_key_packages`, each a fresh init_key)
+ a reusable last-resort (`make_last_resort_key_package`, LastResortExtension); server pops one per fetch
(`consumeMkp`, mirrors the X3DH OPK pop) → never served again (replay bound = one add); pool drained →
last-resort fallback (bounded compromise, like X3DH signed-prekey-only). Replenish = full pool republished
each launch (`clearMkps` on re-register). KPs stay opaque base64 (zero-knowledge). Host `single_use_
keypackage_pool_and_last_resort` 69/69; server `mls-kp-pool` 12/12. Ghost-defense/floor unchanged
(kvant_caps declares LastResort as SUPPORTED, not required); KAT byte-identical.

🟢 **1:1 X3DH prekey supply CHECKED — NOT the same bug.** An earlier worry was that the 1:1 path shared
the MLS "single prekey" flaw. It does NOT: `messaging.ts` generates the bundle with `oneTimeCount: 32`
(a pool of 32 one-time prekeys), the server pops+consumes one per `getBundle` (with an anti-drain cap,
KV-07), falls back to signed-prekey-only on exhaustion, and re-register republishes a fresh pool
(replenish). That is a healthy OPK model — the MLS single-KP defect was MLS-specific. No 1:1 change needed.

### (historical) original assessment — 4 HIGH, runtime-CONTAINED, fix was deferred to M2/device-time

`cargo audit` on `app-rn/android/kvant-mls` (the X-Wing provider tree) flagged 4 HIGH advisories, all in
libcrux **symmetric / signature** sub-crates pulled transitively by `openmls_libcrux_crypto 0.3.1`:

| crate | version | advisory | CVSS | issue | fixed in |
|---|---|---|---|---|---|
| `libcrux-poly1305` | 0.0.4 | RUSTSEC-2026-0073 | 8.7 | Panic in standalone MAC operations | ≥ 0.0.5 |
| `libcrux-chacha20poly1305` | 0.0.6 + 0.0.7 | RUSTSEC-2026-0124 | 8.2 | Potential panic on overlong ciphertext buffer | ≥ 0.0.8 |
| `libcrux-ed25519` | 0.0.6 | RUSTSEC-2026-0075 | 8.2 | All-zero key generation on catastrophic RNG failure | ≥ 0.0.7 |

(+ 3 *unmaintained* warnings, low: `bincode 1.3.3`, `paste 1.0.15`, `proc-macro-error2 2.0.1` — transitive.)

### Why this is contained at runtime (not an open hole)
- The two **panic** advisories (poly1305 MAC, chacha20poly1305 overlong-ciphertext) are DoS-via-panic on
  malformed input — exactly the class **Contract-1** addresses. The C1 `catch_unwind` guard wraps every
  untrusted `process_message` / `StagedWelcome` path → a panic becomes a **typed, fail-closed `MlsError`**,
  never a crash/unwind across the FFI. So an A2 peer cannot DoS the client via these.
- The **Tier-1 fuzz targets do NOT call libcrux** (deserialize-only: `decode_identity`, `MlsMessageIn`,
  `KeyPackageIn`). So the running campaign cannot trip these — they are a **Tier-2 (stateful) concern**,
  because Tier-2 feeds bytes through decryption/AEAD where libcrux runs.
- `libcrux-ed25519` all-zero-key only triggers on **catastrophic RNG failure** (getrandom returns zeros) —
  negligible on Android Keystore / a healthy kernel CSPRNG.

### Fix (M2 task, AFTER the fuzz campaign, BEFORE Tier-2 stateful fuzz)

> ### ⭐ M2 ROUTE DECISION — UPDATED 2026-07-02 (Route 1 STRUCK OUT — impossible; fix deferred to device-test time)
> **~~Route 1 (surgical leaf `[patch.crates-io]` of poly1305/chacha20poly1305/ed25519)~~ = IMPOSSIBLE.**
> Empirically proven 2026-07-02 (`cargo update --precise` + a literal `[patch.crates-io]` attempt, then reverted —
> nothing changed in the tree): the vulnerable versions are **HARD-PINNED upstream, one level below the leaf
> crates**, so a leaf-only fix does not exist:
> - `libcrux-chacha20poly1305 0.0.6` requires `libcrux-poly1305 = "=0.0.4"` (EXACT) → can't reach 0.0.5
>   (`error: failed to select a version… =0.0.4; candidate 0.0.5 didn't match`)
> - `libcrux-aead 0.0.6` requires `libcrux-chacha20poly1305 = "=0.0.6"` (EXACT) → can't reach 0.0.8
> - `openmls_libcrux_crypto 0.3.1` requires `libcrux-aead = "^0.0.6"` + `libcrux-ed25519 = "^0.0.6"` → can't reach 0.0.7/0.0.8
> Nothing on crates.io moves these (provider maxes at **0.3.1**). A crates.io→crates.io `[patch]` is rejected
> outright (*"patches must point to different sources"*); a git/path `[patch]` at the fixed versions fails the
> SAME exact-pin check (0.0.5 ∤ `=0.0.4`). **Keeping `openmls_libcrux_crypto 0.3.1` welds the old libcrux in.**
> The earlier Route-1 premise ("patch 3 symmetric crates, KEM safe by construction") was wrong: it assumed the
> leaf crates were independently patchable — they aren't.
>
> **CORRECTED PLAN — the fix REQUIRES moving `openmls_libcrux_crypto` off its 0.3.1 pins. Two options, and BOTH
> require an on-device KAT re-test** (a provider bump can move `libcrux-ml-kem` off 0.0.8 → pk/ss byte-identity
> in question):
>   - **Route 2 (provider bump):** git dep on an `openmls_libcrux_crypto` > 0.3.1 (crates.io has none → git/fork)
>     that uses fixed libcrux. May drag `libcrux-ml-kem` past 0.0.8 (KAT bytes could shift) AND may churn the
>     openmls core past our `openmls = "=0.8.1"` pin (→ client.rs/dispatch.rs API drift). Cleaner than vendoring.
>   - **Vendor+spoof:** copy fixed leaf crates into `vendor/` with their Cargo.toml `version` spoofed back to the
>     pinned numbers so `[patch]` applies; KEM stays 0.0.8 (KAT safe by construction) BUT touches vendored crypto
>     sources, chacha 0.0.8's API likely drifted from 0.0.6/0.0.7 (may not compile), needs TWO spoofed chacha
>     copies (0.0.6 + 0.0.7). Fragile / upstream-desync — **worse than a clean provider bump.**
>
> **🔴 WHEN = DEVICE-TEST TIME (post-vacation).** Group the coordinated provider bump with the deferred M3 device
> test + the KAT re-test on BOTH SoC (ROG6 `N8AIOC1194109KB` + S10+ `R58M31T663D`) — ONE device session, because
> a provider bump that moves `libcrux-ml-kem` puts M1 KAT byte-identity (pk `c12e9e39…` / ss `78dbb52f…`) in
> question. Decision made 2026-07-02: do NOT force a device session now (M3 device test was just deferred to keep
> coding). Until then:
>
> **MITIGATION ACTIVE NOW — Contract-1 contains all 4 HIGH at runtime** (catch_unwind → typed fail-closed
> `MlsError`; the 2 panic advisories become non-crashes across the FFI; ed25519 all-zero-key only on catastrophic
> RNG, negligible on Android Keystore). This is a **DEFERRED fix WITH active mitigation, not an open hole.**
- These are 0.0.x crates → **semver-locked** (cargo treats every 0.0.z as incompatible), so a plain
  `cargo update` will NOT move them past the parent's exact pin (confirmed above).
- **After the eventual provider bump: re-run `cargo audit`** to confirm 0 advisories, rebuild + re-run the host
  test suite (60+), re-run the aarch64 cross-compile, AND the on-device KAT on both SoC.
- Auditor framing: *known, runtime-contained (Contract-1) HIGH advisories in the crypto provider; the surgical
  leaf-patch was found impossible (upstream exact pins), so the source-level fix is a coordinated provider bump
  scheduled at device-test time, with the KAT re-test bundled — Tier-2 stateful fuzz waits on that bump.*

### 🔴 KAT / X-Wing determinism — does the bump risk regressing M1?
M1 KAT (auditor-signed): ML-KEM-768 `seed=[7;64]` → `pk SHA-256 = c12e9e39…`, `coins=[9;32]` →
`ss SHA-256 = 78dbb52f…`, byte-identical host(AVX2) ↔ device(portable/NEON).

**The 3 vulnerable crates are NOT the KEM.** poly1305 = symmetric MAC, chacha20poly1305 = AEAD, ed25519 =
classical signature. The KAT exercises **`libcrux-ml-kem` 0.0.8 ONLY** (`mlkem768::generate_key_pair` /
`encapsulate` / `decapsulate` in lib.rs), and `libcrux-ml-kem` has **no advisory** (it is not in the list).

- **Surgical patch (route 1), keeping `libcrux-ml-kem = "=0.0.8"` pinned → KAT preserved BY CONSTRUCTION.**
  The KEM crate that produces pk/ss is untouched; bumping the AEAD/MAC/sig crates cannot shift ML-KEM output.
  This is the **low-risk path** and the reason the security fix is *decoupled* from the KEM.
- **Wholesale provider bump (route 2) IS the risk:** a newer `openmls_libcrux_crypto` may pull a newer
  `libcrux-kem` → a newer `libcrux-ml-kem` (> 0.0.8). ML-KEM-768 is a FIPS-203 standard so a conformant impl
  *should* reproduce the same pk/ss for the same seed/coins — but 0.0.x libcrux is experimental, and a
  draft→final or encoding change could shift the bytes. **If the bump moves `libcrux-ml-kem`, treat it as a
  potential M1 regression → re-run the on-device KAT (pinnedOk must stay true on both SoC) before accepting.**

**Conclusion (REVISED 2026-07-02):** route 1 (leaf-only patch) is **impossible** — the vulnerable versions are
hard-pinned by `libcrux-aead 0.0.6`/`libcrux-chacha20poly1305 0.0.6` (exact `=`) and `openmls_libcrux_crypto
0.3.1` (`^0.0.6`), and nothing on crates.io moves them. The fix therefore MUST move `openmls_libcrux_crypto` off
its 0.3.1 pins (route 2 provider bump, or vendor+spoof) → a provider bump can shift `libcrux-ml-kem`, so the
on-device KAT re-test is **mandatory** and no longer avoidable. This makes the KAT re-verification part of the
fix regardless of route → schedule the whole thing at **device-test time** (bundle with M3 device test, both SoC).
Until then the 4 HIGH are **runtime-contained by Contract-1** (fail-closed), so deferring is a mitigation-backed
decision, not an open hole.

## 🟡 npm audit — dev-tooling only (not deployed runtime)
- `server/`: 2 high + 2 moderate, ALL in **`node-turn`** (→ `flatted`, `log4js`, `js-yaml`). `node-turn` is
  **local-dev-only** (`server/turn.js`, two-emulator NAT test; prod TURN = coturn). Not in the deployed
  attack surface. `npm audit fix` cleans it (cosmetic).
- `app-rn/`: 8 moderate, all in **RN CLI build-tooling** (`fast-xml-parser`, `js-yaml`) — build-time, not
  shipped in the APK.
- `crypto-core/`, `transport/`, `transport/server/`: **0 vulnerabilities** (the crypto-bearing packages are clean).

## 🟢 gitleaks — 0 live secrets
181 commits, 9 hits, all rule `generic-api-key` (entropy heuristic): a `Cargo.lock` checksum, crypto
domain-separation constants (`senderkey.js`), doc algo-names (`THREAT_MODEL.md`), and test fixtures
(`turncreds.test.mjs`, `proxy.test.js`) — all false positives. The only real one is the **already-rotated**
C2 TURN password in `app-rn/src/call.ts` git history (commits ~2026-06-14, *before* the d536ffa purge);
HEAD is clean and the credential is **dead**. Optional later: `git filter-repo`/BFG to scrub history.
