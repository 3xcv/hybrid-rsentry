#!/usr/bin/env python3
"""
benchmark_ransomware.py — detection benchmark for the 3 production ransomware
simulations (Akira, Qilin, LockBit 5.0) against agent.monitor_ebpf.DetectionEngine.

For each family it replays the attack against a fresh corpus and drives BOTH
userspace detection surfaces the eBPF sensor would feed:
  * observe_write()  — silent-encryption (entropy burst) + canary-inode writes
  * observe_rename() — canary-touch (prefix) + velocity-burst (enc-looking ext)

Per file the malware "encrypts": a new high-entropy file is written (drives the
write path), then the rename to the ransomware extension is observed. Detection
fires on whichever surface trips first — that is the instant the real sensor
would issue SIGSTOP, so time-to-kill is measured from the first operation to
that event.

Metrics (per traversal, aggregated per run, then min/avg/max over 5 runs):
  1. time-to-kill  : wall-clock first-op -> detection (SIGSTOP point), ms
  2. files encrypted before detection (inclusive of the triggering file)
  3. detection latency: processing time of the detecting observe_* call, ms
  4. false-positive rate on benign .bak/.tmp/.log renames + low-entropy writes
  5. coverage rate : % of traversal orders detected
  6. detection path: canary touch / velocity burst / silent encryption

Usage:  python3 scripts/benchmark_ransomware.py [--runs 5]
"""
from __future__ import annotations

import argparse
import os
import shutil
import statistics
import sys
import tempfile
import time
from pathlib import Path

# Allow running from anywhere without PYTHONPATH.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent.monitor_ebpf import DetectionEngine, seed_canaries
from agent.entropy import _shannon_entropy
from simulations.sim_common import populate_corpus, enumerate_targets, _prioritise
from simulations.sim_akira import PROFILE as AKIRA
from simulations.sim_qilin import PROFILE as QILIN
from simulations.sim_lockbit import PROFILE as LOCKBIT

HOST = "00000000-0000-0000-0000-000000000001"
TRAVERSALS = ["dfs", "random", "depth"]
FAMILIES = [("Akira", AKIRA), ("Qilin", QILIN), ("LockBit 5.0", LOCKBIT)]

# Corpus sized for speed while keeping >>10 files and >=3 dirs (silent-enc needs
# 10 writes across >=3 inodes).
CORPUS = dict(dirs=6, depth=3, files_per_dir=5)


def _entropy_fn(path: str) -> float:
    try:
        with open(path, "rb") as f:
            return _shannon_entropy(f.read(65536))
    except OSError:
        return 0.0


def _classify(evt: dict) -> str:
    et = evt.get("event_type")
    if et == "CANARY_TOUCHED":
        return "canary touch"
    if et == "SILENT_ENCRYPTION":
        return "silent encryption"
    if et == "PROCESS_ANOMALY":
        return "velocity burst"
    return et or "unknown"


def _make_sandbox() -> str:
    d = tempfile.mkdtemp(prefix="rsentry_bench_")
    open(os.path.join(d, ".rsentry_sandbox"), "w").close()
    return d


def _run_traversal(profile, traversal: str) -> dict:
    """Replay one attack ordering; return detection metrics or miss."""
    root = _make_sandbox()
    try:
        populate_corpus(root, **CORPUS)
        canaries = seed_canaries([root], per_dir=2)
        engine = DetectionEngine(
            HOST, [root], canaries,
            velocity_threshold=2, window_seconds=3.0,
            self_pid=os.getpid(), entropy_fn=_entropy_fn,
        )
        targets = enumerate_targets(root, traversal, skip_aaa=False)
        targets = _prioritise(targets, profile.priority_exts)

        pid = 31337
        ts = 1000.0
        t_first = None
        for i, path in enumerate(targets):
            # Malware encrypts the file: write high-entropy content to the new
            # (extension-changed) path — this is the observable write + rename.
            new_path = path + "." + profile.ext_fn()
            try:
                Path(new_path).write_bytes(os.urandom(2048))  # ~8 bits entropy
                inode = os.stat(new_path).st_ino
            except OSError:
                inode = 10_000 + i

            if t_first is None:
                t_first = time.perf_counter()

            t0 = time.perf_counter()
            evt = engine.observe_write(pid, 1, profile.name.lower()[:15],
                                       inode, new_path, ts)
            if evt is None:
                evt = engine.observe_rename(pid, 1, profile.name.lower()[:15],
                                            path, new_path, ts=ts)
            latency_ms = (time.perf_counter() - t0) * 1000.0
            ts += 0.001

            if evt is not None:
                return {
                    "detected": True,
                    "files_before_detection": i + 1,
                    "detection_latency_ms": latency_ms,
                    "time_to_kill_ms": (time.perf_counter() - t_first) * 1000.0,
                    "path": _classify(evt),
                }
        return {"detected": False, "files_before_detection": None,
                "detection_latency_ms": None, "time_to_kill_ms": None,
                "path": None}
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _run_fp_check(profile) -> float:
    """
    Benign bulk activity must not alert:
      * a backup tool renaming files to .bak/.tmp/.log (no content rewrite), and
      * a process writing many LOW-entropy files (logs/documents).
    Low entropy must keep the silent-encryption path silent; benign suffixes must
    keep the rename path silent.
    """
    root = _make_sandbox()
    try:
        # low-entropy benign files (repetitive text ~ a few bits of entropy)
        benign = []
        for i in range(40):
            p = Path(root) / f"doc_{i:03d}.txt"
            p.write_bytes((b"normal log line lorem ipsum dolor sit amet\n") * 40)
            benign.append(str(p))
        engine = DetectionEngine(HOST, [root], [], velocity_threshold=2,
                                 self_pid=os.getpid(), entropy_fn=_entropy_fn)
        fp = 0
        tested = 0
        ts = 5000.0
        for path in benign:
            tested += 1
            # benign tool rewrites the file in place (low entropy) then renames it
            try:
                inode = os.stat(path).st_ino
            except OSError:
                inode = 20_000 + tested
            evt = engine.observe_write(9999, 1, "backup-tool", inode, path, ts)
            if evt is None:
                evt = engine.observe_rename(9999, 1, "backup-tool",
                                            path, path + ".bak", ts=ts)
            ts += 0.001
            if evt is not None:
                fp += 1
        return round(fp / max(1, tested) * 100, 3)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _aggregate_run(profile) -> dict:
    results = [_run_traversal(profile, t) for t in TRAVERSALS]
    detected = [r for r in results if r["detected"]]
    paths = sorted({r["path"] for r in detected})
    cov = len(detected) / len(TRAVERSALS) * 100
    fp = _run_fp_check(profile)

    def _avg(key):
        vals = [r[key] for r in detected]
        return statistics.mean(vals) if vals else float("nan")

    return {
        "coverage_pct": cov,
        "files_before_detection": _avg("files_before_detection"),
        "detection_latency_ms": _avg("detection_latency_ms"),
        "time_to_kill_ms": _avg("time_to_kill_ms"),
        "fp_rate_pct": fp,
        "paths": paths,
        "per_traversal": {t: r["path"] for t, r in zip(TRAVERSALS, results)},
    }


def _mmm(values):
    vals = [v for v in values if v == v]  # drop NaN
    if not vals:
        return (float("nan"),) * 3
    return (min(vals), statistics.mean(vals), max(vals))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=5)
    args = ap.parse_args()

    print(f"# Ransomware detection benchmark — {args.runs} runs/family\n")
    all_family_runs = {}
    for fam_name, profile in FAMILIES:
        runs = [_aggregate_run(profile) for _ in range(args.runs)]
        all_family_runs[fam_name] = runs

        ttk = _mmm([r["time_to_kill_ms"] for r in runs])
        files = _mmm([r["files_before_detection"] for r in runs])
        lat = _mmm([r["detection_latency_ms"] for r in runs])
        fp = _mmm([r["fp_rate_pct"] for r in runs])
        cov = _mmm([r["coverage_pct"] for r in runs])
        all_paths = sorted({p for r in runs for p in r["paths"]})

        print(f"## {fam_name}  (mode={profile.mode}, ext={profile.ext_fn()!r})")
        print(f"  time-to-kill ms       min/avg/max = {ttk[0]:.3f} / {ttk[1]:.3f} / {ttk[2]:.3f}")
        print(f"  files before detect   min/avg/max = {files[0]:.2f} / {files[1]:.2f} / {files[2]:.2f}")
        print(f"  detection latency ms  min/avg/max = {lat[0]:.3f} / {lat[1]:.3f} / {lat[2]:.3f}")
        print(f"  false-positive %      min/avg/max = {fp[0]:.3f} / {fp[1]:.3f} / {fp[2]:.3f}")
        print(f"  coverage %            min/avg/max = {cov[0]:.0f} / {cov[1]:.1f} / {cov[2]:.0f}")
        print(f"  detection path(s)     = {', '.join(all_paths)}")
        print(f"  per-traversal (last run) = {runs[-1]['per_traversal']}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
