#!/usr/bin/env python3
"""
tests/evaluation/efficiency/overhead_metrics.py — Resource-overhead metrics. [NO ROOT]

Pure functions over the per-round records written by overhead_runner.py. Implements
the resource-overhead section of docs/evaluation-design.md §2: a paired
agent-OFF / agent-ON(audit) / agent-ON(enforce+lsm) design, with the three
contrasts the paper reports:

    monitoring overhead      = audit  - off       (steady-state observe/score cost)
    LSM enforcement overhead = enforce - audit     (per-write file_permission hook cost)
    total production overhead= enforce - off       (the honest headline)

EFFECT SIZE LEADS, p-value is secondary. Significance != magnitude: at large N a
negligible, irrelevant overhead can still be "significant" — so every contrast
reports the median paired difference (+ bootstrap CI) alongside the Wilcoxon p.

Wilcoxon signed-rank (scipy) is used because paired resource samples are NOT
normally distributed (non-parametric paired test).

Reuses summary_stats / percentiles / bootstrap_ci_median (efficiency.metrics) and
completeness / WARMUP_PREFIX (efficacy.metrics) — not reinvented.
"""
from __future__ import annotations

import math
from statistics import median
from typing import Dict, List, Optional, Tuple

import numpy as np

from tests.evaluation.efficacy.metrics import WARMUP_PREFIX, completeness  # noqa: F401 (re-export)
from tests.evaluation.efficiency.metrics import (
    bootstrap_ci_median, percentiles, summary_stats,
)

NAN = float("nan")

# Per-round sample-list keys by condition (written by overhead_runner.py).
_CPU_KEY = {"audit": "audit_agent_cpu_pct", "enforce": "enforce_agent_cpu_pct"}
_RSS_KEY = {"audit": "audit_agent_rss_mb", "enforce": "enforce_agent_rss_mb"}
_WALL_KEY = {"off": "off_wall_ms", "audit": "audit_wall_ms", "enforce": "enforce_wall_ms"}
_SYSCPU_KEY = {"off": "system_cpu_off", "audit": "system_cpu_audit", "enforce": "system_cpu_enforce"}


def _plan_rounds(rounds: List[dict]) -> List[dict]:
    """Drop warm-up rounds — never counted toward any overhead metric."""
    return [r for r in rounds if not str(r.get("sample_id", "")).startswith(WARMUP_PREFIX)]


# --------------------------------------------------------------------------- #
# Agent resource footprint (per condition)
# --------------------------------------------------------------------------- #

def agent_cpu_summary(rounds: List[dict], condition: str = "enforce") -> Dict[str, float]:
    """summary_stats over ALL agent CPU% samples pooled across rounds for one
    condition ('audit' or 'enforce'). psutil Process.cpu_percent can exceed 100
    on multicore (documented). Empty → n=0."""
    key = _CPU_KEY[condition]
    samples: List[float] = []
    for r in _plan_rounds(rounds):
        samples.extend(float(v) for v in (r.get(key) or []))
    return summary_stats(samples)


def agent_rss_summary(rounds: List[dict], condition: str = "enforce") -> Dict[str, float]:
    """summary_stats over all agent RSS (MB) samples for one condition."""
    key = _RSS_KEY[condition]
    samples: List[float] = []
    for r in _plan_rounds(rounds):
        samples.extend(float(v) for v in (r.get(key) or []))
    return summary_stats(samples)


# --------------------------------------------------------------------------- #
# Paired contrasts (effect size leads, Wilcoxon secondary)
# --------------------------------------------------------------------------- #

def wilcoxon_paired(on_values: List[float], off_values: List[float]) -> Tuple[float, float]:
    """scipy.stats.wilcoxon on paired (on - off). Non-parametric — paired resource
    samples are not normal. Returns (statistic, p_value). Unequal/empty → (nan,nan);
    all-equal (no difference) → (0.0, 1.0)."""
    on = np.asarray(on_values, dtype=float)
    off = np.asarray(off_values, dtype=float)
    if on.size == 0 or on.size != off.size:
        return (NAN, NAN)
    diffs = on - off
    if np.allclose(diffs, 0.0):
        return (0.0, 1.0)
    try:
        from scipy.stats import wilcoxon
    except ImportError:                     # scipy is a hard dep; flag, don't hand-roll
        raise RuntimeError("scipy is required for Wilcoxon — install scipy")
    try:
        res = wilcoxon(on, off)
        return (float(res.statistic), float(res.pvalue))
    except ValueError:                      # e.g. too few non-zero diffs
        return (NAN, NAN)


def median_paired_diff(on_values: List[float], off_values: List[float]) -> float:
    """median(on - off) — the EFFECT SIZE reported alongside every p-value."""
    if not on_values or len(on_values) != len(off_values):
        return NAN
    return float(median([a - b for a, b in zip(on_values, off_values)]))


def paired_contrast(on_values: List[float], off_values: List[float],
                    seed: int = 0) -> Dict[str, float]:
    """Generic paired-contrast building block. Effect size (median_delta and %)
    leads; Wilcoxon p is secondary. Returns {n, on_p50, off_p50, median_delta,
    median_pct, delta_ci:(lo,hi), wilcoxon_stat, p_value}."""
    n = min(len(on_values), len(off_values))
    on, off = list(on_values[:n]), list(off_values[:n])
    if n == 0:
        return {"n": 0, "on_p50": NAN, "off_p50": NAN, "median_delta": NAN,
                "median_pct": NAN, "delta_ci": (NAN, NAN),
                "wilcoxon_stat": NAN, "p_value": NAN}
    diffs = [a - b for a, b in zip(on, off)]
    pcts = [((a - b) / b * 100.0) for a, b in zip(on, off) if b != 0]
    stat, p = wilcoxon_paired(on, off)
    return {
        "n": n,
        "on_p50": float(np.percentile(on, 50)),
        "off_p50": float(np.percentile(off, 50)),
        "median_delta": float(median(diffs)),
        "median_pct": (float(median(pcts)) if pcts else NAN),
        "delta_ci": bootstrap_ci_median(diffs, seed=seed),
        "wilcoxon_stat": stat,
        "p_value": p,
    }


# --------------------------------------------------------------------------- #
# The three reported contrasts
# --------------------------------------------------------------------------- #

def _wall(rounds: List[dict], cond: str) -> List[float]:
    return [float(r[_WALL_KEY[cond]]) for r in _plan_rounds(rounds)
            if r.get(_WALL_KEY[cond]) is not None]


def _round_mean_syscpu(rounds: List[dict], cond: str) -> List[float]:
    """Per-round MEAN system CPU% for one condition (one value per round)."""
    out: List[float] = []
    for r in _plan_rounds(rounds):
        vals = r.get(_SYSCPU_KEY[cond]) or []
        if vals:
            out.append(float(np.mean(vals)))
    return out


def workload_slowdown(rounds: List[dict]) -> Dict[str, dict]:
    """Paired wall-time contrasts (ms). Three deltas: monitoring (audit−off),
    LSM enforcement (enforce−audit), total production (enforce−off)."""
    off, audit, enf = _wall(rounds, "off"), _wall(rounds, "audit"), _wall(rounds, "enforce")
    return {
        "monitoring":       paired_contrast(audit, off, seed=1),
        "lsm_enforcement":  paired_contrast(enf, audit, seed=2),
        "total_production": paired_contrast(enf, off, seed=3),
    }


def system_impact(rounds: List[dict]) -> Dict[str, dict]:
    """Same three contrasts on per-round mean system-CPU%. The per-syscall kernel
    probe + LSM-hook cost runs in KERNEL context (charged to the workload's
    syscalls), so it shows up HERE (system CPU) and in wall-time — this, not the
    agent-process CPU, is where the LSM-hook cost principally lands."""
    off = _round_mean_syscpu(rounds, "off")
    audit = _round_mean_syscpu(rounds, "audit")
    enf = _round_mean_syscpu(rounds, "enforce")
    return {
        "monitoring":       paired_contrast(audit, off, seed=4),
        "lsm_enforcement":  paired_contrast(enf, audit, seed=5),
        "total_production": paired_contrast(enf, off, seed=6),
    }


def workload_ops(rounds: List[dict]) -> Optional[int]:
    """The fixed write-op count per half (for per-op cost). First non-None 'ops'."""
    for r in _plan_rounds(rounds):
        if r.get("ops"):
            return int(r["ops"])
    return None


def per_op_us(median_delta_ms: float, ops: Optional[int]) -> float:
    """Per-operation overhead in microseconds — workload-length INVARIANT, so it
    reflects steady-state cost not the fixed per-launch cost. NaN if ops unknown."""
    if not ops or median_delta_ms is None or math.isnan(median_delta_ms):
        return NAN
    return median_delta_ms * 1000.0 / ops


def _round_mean_agent_cpu(rounds: List[dict], cond: str) -> List[float]:
    out: List[float] = []
    for r in _plan_rounds(rounds):
        vals = r.get(_CPU_KEY[cond]) or []
        if vals:
            out.append(float(np.mean(vals)))
    return out


def lsm_cpu_cost(rounds: List[dict], seed: int = 7) -> Dict[str, float]:
    """Paired enforce-vs-audit per-round MEAN agent-process CPU%.

    SECONDARY LSM evidence: the LSM hooks execute in KERNEL context (charged to
    the workload's syscall time → wall-time / system-CPU), so the agent-PROCESS
    CPU mostly reflects the userspace event path, which is ≈equal across audit and
    enforce. The principled per-syscall-hook measure is the per-op WALL / system-
    CPU delta (enforce−audit). This contrast is reported for corroboration, with
    that caveat stated."""
    return paired_contrast(_round_mean_agent_cpu(rounds, "enforce"),
                           _round_mean_agent_cpu(rounds, "audit"), seed=seed)
