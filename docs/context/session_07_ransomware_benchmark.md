# Session 07 — Ransomware Detection Benchmark (Akira · Qilin · LockBit 5.0)

**Date:** 2026-06-07
**Commit:** `e63c625`
**Engine:** `agent.monitor_ebpf.DetectionEngine` (velocity_threshold=2, window=3.0s,
silent-encryption: ≥10 writes / ≥3 inodes / entropy ≥7.0 bits within 2.0s)
**Runtime:** Python 3.11.9 (venv) · kernel 6.19.14+kali-amd64
**Harness:** `scripts/benchmark_ransomware.py` (reproducible: `python scripts/benchmark_ransomware.py --runs 5`)

---

## Methodology

Each family's production `Profile` (`simulations/sim_{akira,qilin,lockbit}.py`)
is replayed against a fresh corpus. The harness drives **both** userspace
detection surfaces the eBPF sensor feeds from the kernel:

- `observe_write()` — silent-encryption (entropy burst) + canary-inode writes
- `observe_rename()` — canary-touch (prefix) + velocity-burst (enc-looking ext)

Per file the malware "encrypts", a new **high-entropy** file (`os.urandom`, ≈8
bits) is written to the extension-changed path (drives the write path), then the
rename to the ransomware extension is observed. **Detection fires on whichever
surface trips first** — the instant the real sensor calls `os.kill(pid, SIGSTOP)`.

Per **run**: all 3 traversal orders (`dfs`, `random`, `depth`) are attacked, plus
a separate false-positive workload. Each family is run **5 times**; metrics below
are **min / avg / max across those 5 runs**.

### Metric definitions
| # | Metric | Definition |
|---|---|---|
| 1 | **time-to-kill** | wall-clock from the first file operation to the detection-triggering `observe_*` return (the SIGSTOP point), ms |
| 2 | **files before detection** | count of files encrypted when detection fires (inclusive of the triggering file) |
| 3 | **detection latency** | processing time of the single detecting `observe_*` call, ms |
| 4 | **false-positive rate** | % of benign operations (backup-tool `.bak` renames + 40 low-entropy writes) that raised any alert |
| 5 | **coverage rate** | % of the 3 traversal orders in which the attack was detected |
| 6 | **detection path** | which surface tripped: canary touch / velocity burst / silent encryption |

> **Note on the model.** This is an offline replay against the userspace
> `DetectionEngine` (no live BCC/kernel sensor, no real SIGSTOP). Time-to-kill is
> the wall-clock to the SIGSTOP *decision point*; the `os.kill` syscall itself
> (~microseconds) and kernel scheduling are not included. Detection latencies are
> single-digit-microsecond-to-sub-millisecond because no I/O blocks the hot path.

---

## Results (5 runs/family — min / avg / max)

### Akira — `mode=intermittent`, ext `.akiranew`
| Metric | min | avg | max |
|---|---|---|---|
| time-to-kill (ms) | 0.657 | **0.737** | 0.910 |
| files before detection | 1.67 | **1.67** | 1.67 |
| detection latency (ms) | 0.580 | **0.667** | 0.845 |
| false-positive rate (%) | 0.000 | **0.000** | 0.000 |
| coverage (%) | 100 | **100** | 100 |
| **detection path(s)** | canary touch, velocity burst | | |

### Qilin — `mode=percent`, ext = random 7-char
| Metric | min | avg | max |
|---|---|---|---|
| time-to-kill (ms) | 0.665 | **0.711** | 0.788 |
| files before detection | 1.33 | **1.60** | 2.00 |
| detection latency (ms) | 0.561 | **0.641** | 0.697 |
| false-positive rate (%) | 0.000 | **0.000** | 0.000 |
| coverage (%) | 100 | **100** | 100 |
| **detection path(s)** | canary touch *(+ silent encryption — see below)* | | |

### LockBit 5.0 — `mode=two_pass`, ext = random 16-char
| Metric | min | avg | max |
|---|---|---|---|
| time-to-kill (ms) | 0.636 | **0.818** | 1.245 |
| files before detection | 1.33 | **1.53** | 1.67 |
| detection latency (ms) | 0.598 | **0.718** | 1.121 |
| false-positive rate (%) | 0.000 | **0.000** | 0.000 |
| coverage (%) | 100 | **100** | 100 |
| **detection path(s)** | canary touch, velocity burst | | |

All three families: **100% coverage, 0% false positives, sub-millisecond
time-to-kill, ≤2 files (avg) before detection** in the canary/velocity case.

---

## Detection-path analysis (the key finding)

The three families split into two detection regimes based on their extension:

| Family | Extension | `_looks_encrypted`? | Primary path | Fallback path |
|---|---|---|---|---|
| **Akira** | `.akiranew` (in `_ENC_SUFFIXES`) | ✅ yes | canary touch | **velocity burst** @ file #2 |
| **LockBit 5.0** | random **16**-char | ✅ yes (8–16 alnum rule) | canary touch | **velocity burst** @ file #2 |
| **Qilin** | random **7**-char | ❌ **no** (< 8 chars) | canary touch | **silent encryption** @ file #10 |

**Qilin evades the velocity-burst heuristic.** `_looks_encrypted()` flags a random
extension only when it is **8–16 alphanumeric characters**; Qilin's affiliate
builds use a **7-char** suffix, one character below the floor, so its renames are
never counted toward the velocity window. Qilin therefore depends on:
- a **canary** being reached early (usual case — canaries are dense), or
- the **silent-encryption** entropy detector, which fires at the write-burst
  threshold.

### Deterministic silent-encryption probe (canaries bypassed)
To isolate Qilin's fallback, the attack was re-run with canaries skipped:

```
dfs    : detected at file #10 via SILENT_ENCRYPTION (trigger=write_entropy)
random : detected at file #10 via SILENT_ENCRYPTION (trigger=write_entropy)
depth  : detected at file #10 via SILENT_ENCRYPTION (trigger=write_entropy)
```

So Qilin's **worst case is 10 files encrypted before detection** (the
`_WRITE_BURST_THRESHOLD`), versus ≤2 for Akira/LockBit. This is reflected in
Qilin's higher run-to-run variance in "files before detection" — across four
5-run executions it ranged avg 1.60–2.73 with a single-run max of 4.33 when a
canary happened to sit deep in a random traversal.

---

## Cross-execution stability

The benchmark was executed four times (20 runs/family total). Across all
executions:
- **Coverage = 100%** and **FP = 0%** for every family, every time.
- **Akira / LockBit**: always canary touch or velocity burst; files-before-detection avg 1.5–1.7.
- **Qilin**: always detected; path was canary touch, with silent encryption surfacing in 3 of 4 executions (whenever a random/depth traversal reached 10 encrypted files before a canary).
- time-to-kill stayed in the **0.6–1.25 ms** band for all families.

---

## Takeaways

1. **All three families are contained within ~2 files and <1.3 ms** in the common
   case (canary or velocity), with zero false positives.
2. **Qilin is the weakest case** for the behavioral layer: its 7-char extension
   slips under the 8-char random-extension rule, pushing detection onto canaries
   or the 10-file silent-encryption threshold. If an affiliate build also avoided
   canaries, up to 10 files would be encrypted before the entropy detector fires.
3. **Hardening suggestion (not applied here):** lower the random-extension floor
   in `_looks_encrypted()` from 8 to ~5–6 chars, or add Qilin's known short-suffix
   pattern, to bring Qilin onto the same ≤2-file velocity path as Akira/LockBit.
   This would need an FP re-check against legitimate short extensions (e.g. `.bak`
   is already whitelisted; `.world`, `.cache7` style names would need review).

---

## Reproduce

```bash
cd ~/hybrid-rsentry
venv/bin/python scripts/benchmark_ransomware.py --runs 5
```

The harness is deterministic in structure but uses randomised extensions and the
`random` traversal, so absolute file-counts/latencies vary slightly per run; the
detection-path regimes and the 100%/0% coverage/FP results are stable.
