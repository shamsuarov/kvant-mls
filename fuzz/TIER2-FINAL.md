# Tier-2 fuzzing campaign — FINAL (closed 2026-08-07)

Stateful fuzzing of the MLS crate with libcrux actually exercised (Tier-1 covered decoders; Tier-2
drives real protocol state machines, so it reaches the cryptographic core rather than the parser).

## Closure criterion and what was actually true at the stop

**Criterion:** 48 h crash-free + edge plateau.

**Met:** 48 h crash-free — comfortably. All three lanes ran **49 h 07 m** with **0 crashes**.

**Not met at the moment of stopping:** the edge plateau. This is recorded rather than smoothed over,
because the campaign was closed by an explicit operator decision taken while `t2_msan` was showing a
full plateau (2000/2000 flat pulses), and by the time the closure was executed msan had found one
more edge (`flat in 5/2000`, cov 7019 → 7020). At the stop, **all three lanes were still finding
occasional new edges**:

| Lane | Elapsed | Crashes | Edges (cov) | Plateau state at stop | Corpus | Speed |
|---|---|---|---|---|---|---|
| `t2_proc` (process_stateful, 8 workers) | 49 h 07 m | **0** | 6682 | flat 0/2000 — still moving | 238 529 | ~589 exec/s |
| `t2_msan` (msan_mls, 4 workers) | 49 h 07 m | **0** | 7020 | flat 5/2000 — still moving | 238 529 | ~144 exec/s |
| `t2_ops` (op_sequence, 4 workers) | 49 h 07 m | **0** | 14 842 | flat 0/2000 — still moving | 5 491 | ~13 exec/s |

The honest reading: **the safety result is the 0 crashes over 49 h, not the plateau.** A plateau is
evidence of *saturation* — that the campaign has stopped learning — and that had not been reached.
New edges were still arriving at a slow trickle, so a longer campaign could still surface something.
What can be claimed is what was measured: two days of continuous stateful fuzzing across three lanes,
including a memory-sanitizer lane, produced no crash, no leak and no sanitizer report.

## Artifacts

14 files in `artifacts/op_sequence/`, **all `slow-unit-*`** — inputs that ran slowly, not failures.
No `crash-*`, `leak-*` or `timeout-*` artifact was produced by any lane. That absence is the result.

## Corpus

333 MB, ~238 k files, under `fuzz/corpus/` and deliberately **not committed** (see `fuzz/.gitignore`:
"campaign-grown corpus — archive separately, do not commit"). It was left in place rather than copied
into `artifacts/`: duplicating a third of a gigabyte inside the repo tree buys nothing, and the
corpus is only useful as a warm start for a future campaign, which reads it from where it already is.

To resume rather than restart: `bash fuzz/campaign-tier2.sh` picks the corpus up in place.

## Scope

Ran under WSL (the crate's fuzzing toolchain is Linux-only). With this campaign closed, the WSL
dependency for M3 is retired — nothing else in the M3 tail requires it.
