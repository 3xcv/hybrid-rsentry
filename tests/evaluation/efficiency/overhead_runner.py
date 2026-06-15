#!/usr/bin/env python3
"""
tests/evaluation/efficiency/overhead_runner.py — Resource-overhead paired sweep. [ROOT]

Three conditions per round, all against the IDENTICAL benign workload, fully
paired (pairing controls run-to-run system noise so the delta reflects the agent):
    OFF        — workload alone (baseline)
    ON-audit   — agent monitoring, no LSM enforcement (steady-state monitoring cost)
    ON-enforce — agent enforce+lsm (production cost: monitoring + LSM hooks)

→ monitoring = audit−off, LSM enforcement = enforce−audit, total = enforce−off.

THE BENIGN CHURN IS GUARANTEED NOT TO TRIP CONTAINMENT under enforce+lsm:
  * NO renames  → the kernel rename-velocity auto-block (_block_on_velocity arms
    blocked_pids at >=3 renames / 3s, after which the LSM path_rename hook denies
    with -EPERM) is never triggered. (Renames are what would auto-block a benign
    workload in enforce — this is the key avoidance.)
  * NO deletes  → __calc_score never accumulates (its signals need deletes), so
    behavior_events / the entropy-score containment path never fires.
  * Sequential single write to a FRESH inode each iteration → the write-offset
    NONSEQ counter never climbs → no SILENT_ENCRYPTION.
  * Touches only its own churn_*.dat files in a fresh dir → never a canary
    (AAA_/aaa_/ZZZ_/zzz_), so the canary path_rename/file_permission denies never fire.
  The file_permission LSM hook STILL fires on every write (one canary-map lookup,
  then allow for non-canary) — that per-write hook cost is exactly what the
  enforce−audit contrast measures. The path_rename hook is rename-gated and
  deliberately NOT exercised (see rename avoidance above); we measure the
  per-write file_permission cost, which is the dominant always-on LSM overhead.

Launched UID-1000 via a non-safelisted comm ("file-churn") so the agent does its
FULL monitoring work (kernel probes AND userspace handlers) — worst-case cost.

Integrity guard (reused): warm-up rounds excluded, resumable on round index,
each round wrapped in try/except (failures recorded, never silently dropped),
recorded-vs-planned reconciliation, loud INCOMPLETE banner.

Usage (root):
    sudo -E ~/hybrid-rsentry/venv/bin/python -m tests.evaluation.efficiency.overhead_runner --n 3
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import psutil

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from tests.evaluation import harness
from tests.evaluation.conftest import RESULTS_DIR, read_trials
from tests.evaluation.efficacy.metrics import WARMUP_PREFIX, completeness

OVERHEAD_RAW = RESULTS_DIR / "overhead_raw.json"
OVERHEAD_REPORT = RESULTS_DIR / "overhead_report.json"
SAMPLE_INTERVAL = 0.1          # 100 ms resource sampling
QUIESCE_S = 1.5                # settle between halves so tails don't bleed across
CHURN_FILES = 50               # fixed file set (reused inodes → cache-friendly)
CHURN_OPS = 1_800_000          # write syscalls per half; ~5 s on a ~3µs/syscall box
# (each op = one vfs_write. tune --ops so each half runs ~5-10 s so the fixed
#  per-process launch cost is amortized and the number reflects STEADY STATE.)

# Benign STEADY-STATE churn: open a FIXED set of files once, then do many small
# SEQUENTIAL append-writes round-robin across them. Why this shape (see the
# write-monitoring source):
#   * Reused inodes  → _handle_write's inode→path cache HITS after the first pass,
#     so the agent does NOT /proc/<pid>/fd-scan per write → no userspace
#     saturation at high volume (fresh-file-per-iter would scan every write).
#   * O_APPEND       → each write advances the offset → sequential → the
#     write-offset NONSEQ counter never climbs → no SILENT_ENCRYPTION.
#   * NO rename / NO delete / NO canary → cannot arm blocked_pids, never scores,
#     never trips containment under enforce+lsm.
# It still exercises the full write path every op: kprobe__vfs_write (kernel) +
# the file_permission LSM hook (enforce, per MAY_WRITE) + the userspace
# write-event handler (cheap, cache-hit). The opens at setup are excluded from
# the measured wall-time.
_CHURN_SRC = r"""
import os, sys
target, n, nfiles = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
chunk = b"x" * 64                                  # tiny low-entropy write
fds = [os.open(os.path.join(target, "churn_%03d.dat" % j),
               os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644) for j in range(nfiles)]
try:
    for i in range(n):
        os.write(fds[i % nfiles], chunk)           # sequential append; reused inode
finally:
    for fd in fds:
        try:
            os.close(fd)
        except OSError:
            pass
"""


# --------------------------------------------------------------------------- #
# Resource sampler
# --------------------------------------------------------------------------- #

class _Sampler:
    """Background thread sampling system + (optional) agent resources @ interval.
    Uses only stable psutil accessors (cpu_percent / memory_info / virtual_memory)
    — no version-fragile net_connections."""

    def __init__(self, agent_pid: Optional[int] = None, interval: float = SAMPLE_INTERVAL):
        self.interval = interval
        self.system_cpu: List[float] = []
        self.avail_mem_mb: List[float] = []
        self.agent_cpu: List[float] = []
        self.agent_rss_mb: List[float] = []
        self._proc = psutil.Process(agent_pid) if agent_pid else None
        self._stop = threading.Event()
        self._thr = threading.Thread(target=self._loop, daemon=True)

    def start(self) -> None:
        psutil.cpu_percent(interval=None)          # prime system cpu_percent
        if self._proc is not None:
            try:
                self._proc.cpu_percent(interval=None)   # prime agent cpu_percent
            except psutil.Error:
                pass
        self._thr.start()

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self.system_cpu.append(float(psutil.cpu_percent(interval=None)))
                self.avail_mem_mb.append(psutil.virtual_memory().available / 1e6)
                if self._proc is not None:
                    self.agent_cpu.append(float(self._proc.cpu_percent(interval=None)))
                    self.agent_rss_mb.append(self._proc.memory_info().rss / 1e6)
            except psutil.Error:
                pass

    def stop(self) -> None:
        self._stop.set()
        self._thr.join(timeout=2)


# --------------------------------------------------------------------------- #
# One half (workload run + sampling), and one full 3-condition round
# --------------------------------------------------------------------------- #

def _run_churn(target: Path, ops: int) -> None:
    """Launch the benign churn as UID 1000 via the non-safelisted symlink comm."""
    symlink = Path("/tmp/file-churn")
    if symlink.exists() or symlink.is_symlink():
        symlink.unlink()
    symlink.symlink_to("/usr/bin/python3")          # comm := "file-churn" (not safelisted)
    try:
        p = subprocess.Popen([str(symlink), "-c", _CHURN_SRC,
                              str(target), str(ops), str(CHURN_FILES)],
                             cwd=str(_PROJECT_ROOT),
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             user=harness.OPERATOR_UID, group=harness.OPERATOR_GID)
        p.wait(timeout=600)
    finally:
        if symlink.exists() or symlink.is_symlink():
            symlink.unlink()


def _fresh_corpus(round_id: str, tag: str) -> Path:
    d = harness.EVAL_BASE / f"oh_{round_id}_{tag}"
    if d.exists():
        shutil.rmtree(d, ignore_errors=True)
    d.mkdir(mode=0o777, parents=True)
    os.chown(d, harness.OPERATOR_UID, harness.OPERATOR_GID)
    return d


def _half_off(round_id: str, ops: int) -> dict:
    """OFF baseline: workload alone, sample system resources (no agent)."""
    target = _fresh_corpus(round_id, "off")
    sampler = _Sampler(agent_pid=None)
    sampler.start()
    t0 = time.monotonic_ns()
    _run_churn(target, ops)
    wall_ms = (time.monotonic_ns() - t0) / 1e6
    sampler.stop()
    shutil.rmtree(target, ignore_errors=True)
    return {"wall_ms": wall_ms, "system_cpu": sampler.system_cpu,
            "avail_mem_mb": sampler.avail_mem_mb}


def _half_on(round_id: str, ops: int, *, lsm: bool, enforce: bool, tag: str) -> dict:
    """ON half: fresh agent (audit or enforce+lsm) monitoring the identical workload."""
    watch = _fresh_corpus(round_id, tag)
    stub = harness._StubBackend()
    stub.start()
    agent = None
    log_path = None
    try:
        agent, log_path = harness._start_agent(
            watch, lsm=lsm, enforce=enforce, backend_url=stub.url,
            restart_id=f"{round_id}_{tag}")
        if not harness._wait_ready(log_path, agent, harness.READY_TIMEOUT):
            raise RuntimeError(f"agent ({tag}) did not reach readiness")
        sampler = _Sampler(agent_pid=agent.pid)
        sampler.start()
        t0 = time.monotonic_ns()
        _run_churn(watch, ops)
        wall_ms = (time.monotonic_ns() - t0) / 1e6
        sampler.stop()
        return {"wall_ms": wall_ms, "agent_cpu": sampler.agent_cpu,
                "agent_rss_mb": sampler.agent_rss_mb,
                "system_cpu": sampler.system_cpu, "avail_mem_mb": sampler.avail_mem_mb}
    finally:
        if agent is not None and agent.poll() is None:
            try:
                agent.terminate(); agent.wait(timeout=5)
            except Exception:
                try:
                    agent.kill(); agent.wait(timeout=5)
                except Exception:
                    pass
        stub.stop()
        shutil.rmtree(watch, ignore_errors=True)
        if log_path is not None:
            log_path.unlink(missing_ok=True)


def run_round(round_id: str, ops: int) -> dict:
    """One fully-paired round: OFF → quiesce → audit → quiesce → enforce."""
    running = harness._agent_already_running()
    if running:
        raise RuntimeError(f"an agent.monitor is already running ({running}); a "
                           f"round must own the only agent.")
    off = _half_off(round_id, ops)
    time.sleep(QUIESCE_S)
    audit = _half_on(round_id, ops, lsm=False, enforce=False, tag="audit")
    time.sleep(QUIESCE_S)
    enforce = _half_on(round_id, ops, lsm=True, enforce=True, tag="enforce")
    return {
        "sample_id": round_id,
        "ops": ops,                          # write syscalls per half (for per-op cost)
        "off_wall_ms": off["wall_ms"],
        "audit_wall_ms": audit["wall_ms"],
        "enforce_wall_ms": enforce["wall_ms"],
        "audit_agent_cpu_pct": audit["agent_cpu"],
        "audit_agent_rss_mb": audit["agent_rss_mb"],
        "enforce_agent_cpu_pct": enforce["agent_cpu"],
        "enforce_agent_rss_mb": enforce["agent_rss_mb"],
        "system_cpu_off": off["system_cpu"],
        "system_cpu_audit": audit["system_cpu"],
        "system_cpu_enforce": enforce["system_cpu"],
        "avail_mem_off_mb": off["avail_mem_mb"],
        "avail_mem_audit_mb": audit["avail_mem_mb"],
        "avail_mem_enforce_mb": enforce["avail_mem_mb"],
        "loadavg": os.getloadavg()[0],
        "error": None,
    }


# --------------------------------------------------------------------------- #
# Persistence + aggregation
# --------------------------------------------------------------------------- #

def _append(rec: dict) -> None:
    with open(OVERHEAD_RAW, "a") as fh:
        fh.write(json.dumps(rec, sort_keys=True) + "\n")


def _planned_rounds(n: int) -> Dict[str, str]:
    return {f"round_{i:03d}": "rounds" for i in range(n)}


def write_overhead_report(n_rounds: "int | None" = None) -> dict:
    """Aggregate overhead_raw.json → overhead_report.json (with completeness)."""
    from tests.evaluation.efficiency import overhead_metrics as om
    rounds = read_trials(OVERHEAD_RAW)
    plan = [r for r in rounds if not str(r.get("sample_id", "")).startswith(WARMUP_PREFIX)]
    comp = completeness(plan, _planned_rounds(n_rounds)) if n_rounds is not None else None
    report = {
        "_meta": {
            "n_rounds": len(plan), "n_planned": n_rounds,
            "completeness": comp, "complete": (comp["complete"] if comp else None),
            "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "note": ("paired OFF/audit/enforce; effect size (median paired diff + "
                     "bootstrap CI) leads, Wilcoxon p secondary"),
        },
        "agent_cpu": {"audit": om.agent_cpu_summary(plan, "audit"),
                      "enforce": om.agent_cpu_summary(plan, "enforce")},
        "agent_rss": {"audit": om.agent_rss_summary(plan, "audit"),
                      "enforce": om.agent_rss_summary(plan, "enforce")},
        "workload_slowdown": om.workload_slowdown(plan),
        "system_impact": om.system_impact(plan),
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    OVERHEAD_REPORT.write_text(json.dumps(report, indent=2, default=list))
    return report


# --------------------------------------------------------------------------- #
# Sweep
# --------------------------------------------------------------------------- #

def run_overhead_sweep(n: int = 30, *, warmup_rounds: int = 2, ops: int = CHURN_OPS) -> dict:
    if os.geteuid() != 0:
        raise PermissionError("overhead sweep requires root (starts the agent).")
    completed = {r.get("sample_id") for r in read_trials(OVERHEAD_RAW)}
    n_warm_done = sum(1 for s in completed if str(s).startswith(WARMUP_PREFIX))

    # Warm-up rounds (excluded) — warm dpkg-hash page cache + BPF JIT.
    for i in range(warmup_rounds):
        rid = f"{WARMUP_PREFIX}{i:03d}"
        if rid in completed or n_warm_done > i:
            print(f"[warmup] skip {rid}")
            continue
        print(f"[warmup] {rid} (cache warm-up — EXCLUDED)")
        try:
            _append(run_round(rid, ops))
        except Exception as exc:
            print(f"[warmup] {rid} ERROR (ignored): {type(exc).__name__}: {exc}")

    # Plan rounds.
    for i in range(n):
        rid = f"round_{i:03d}"
        if rid in completed:
            print(f"[round {i+1}/{n}] skip {rid} (already recorded)")
            continue
        try:
            rec = run_round(rid, ops)
            _append(rec)
            print(f"[round {i+1}/{n}] {rid} off={rec['off_wall_ms']:.0f}ms "
                  f"audit={rec['audit_wall_ms']:.0f}ms enforce={rec['enforce_wall_ms']:.0f}ms "
                  f"load={rec['loadavg']:.2f}")
        except Exception as exc:
            _append({"sample_id": rid, "error": f"{type(exc).__name__}: {exc}",
                     "off_wall_ms": None, "audit_wall_ms": None, "enforce_wall_ms": None,
                     "loadavg": os.getloadavg()[0]})
            print(f"[round {i+1}/{n}] {rid} ERROR (recorded): {type(exc).__name__}: {exc}")

    rep = write_overhead_report(n_rounds=n)
    comp = rep["_meta"]["completeness"]
    print(f"\n[overhead] sweep done → {OVERHEAD_RAW}")
    print(f"[overhead] COMPLETENESS: ran {comp['ran']}/{comp['planned']} rounds, "
          f"missing={comp['missing']}, errored={comp['errored']}, complete={comp['complete']}")
    if comp and not comp["complete"]:
        print("\n" + "!" * 72)
        print("WARNING: overhead sweep INCOMPLETE — deltas are NOT over the full planned N.")
        print(f"  ran {comp['ran']}/{comp['planned']}, missing={comp['missing']}, errored={comp['errored']}")
        print("Re-run (resumable) to fill gaps, then --aggregate-only.")
        print("!" * 72)
    return comp


def main() -> int:
    ap = argparse.ArgumentParser(description="Resource-overhead paired sweep (root)")
    ap.add_argument("--n", type=int, default=30, help="paired rounds (3=smoke, 30=real)")
    ap.add_argument("--warmup", type=int, default=2, dest="warmup_rounds")
    ap.add_argument("--ops", type=int, default=CHURN_OPS,
                    help="benign file ops per half (tune so each half runs >=2s)")
    ap.add_argument("--aggregate-only", action="store_true")
    args = ap.parse_args()
    if args.aggregate_only:
        rep = write_overhead_report(n_rounds=args.n)
        comp = rep["_meta"]["completeness"]
        print(f"[overhead] aggregated → {OVERHEAD_REPORT} | "
              f"complete={comp['complete'] if comp else 'n/a'}")
        return 0
    run_overhead_sweep(n=args.n, warmup_rounds=args.warmup_rounds, ops=args.ops)
    return 0


if __name__ == "__main__":
    sys.exit(main())
