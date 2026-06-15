#!/usr/bin/env python3
"""
tests/evaluation/efficiency/overhead_test_metrics.py — unit tests for overhead
metrics. [NO ROOT]

scipy is a hard dependency for the Wilcoxon test; the module is skipped (not
hand-rolled) if scipy is unavailable.
"""
from __future__ import annotations

import math
from typing import List

import pytest

pytest.importorskip("scipy", reason="scipy required for Wilcoxon overhead tests")

from tests.evaluation.efficiency import overhead_metrics as om

TOL = 1e-9


def _close(a: float, b: float) -> bool:
    return math.isclose(a, b, abs_tol=TOL)


def _round(rid: str, audit_cpu: List[float], enf_cpu: List[float],
           audit_rss: List[float], enf_rss: List[float],
           off_wall: float, audit_wall: float, enf_wall: float,
           sys_off=None, sys_audit=None, sys_enf=None) -> dict:
    return {
        "sample_id": rid,
        "audit_agent_cpu_pct": audit_cpu, "enforce_agent_cpu_pct": enf_cpu,
        "audit_agent_rss_mb": audit_rss, "enforce_agent_rss_mb": enf_rss,
        "off_wall_ms": off_wall, "audit_wall_ms": audit_wall, "enforce_wall_ms": enf_wall,
        "system_cpu_off": sys_off or [], "system_cpu_audit": sys_audit or [],
        "system_cpu_enforce": sys_enf or [], "error": None,
    }


# --------------------------------------------------------------------------- #
# Agent footprint summaries — exact pooled percentiles
# --------------------------------------------------------------------------- #

def test_agent_cpu_rss_pooled_percentiles_exact():
    rounds = [
        _round("round_000", audit_cpu=[2.0, 2.0], enf_cpu=[4.0, 4.0],
               audit_rss=[100.0], enf_rss=[110.0], off_wall=10, audit_wall=11, enf_wall=12),
        _round("round_001", audit_cpu=[2.0, 2.0], enf_cpu=[4.0, 4.0],
               audit_rss=[100.0], enf_rss=[110.0], off_wall=10, audit_wall=11, enf_wall=12),
        # warm-up must be excluded from pooling
        _round("warmup_000", audit_cpu=[999.0], enf_cpu=[999.0],
               audit_rss=[999.0], enf_rss=[999.0], off_wall=1, audit_wall=1, enf_wall=1),
    ]
    a_cpu = om.agent_cpu_summary(rounds, "audit")
    e_cpu = om.agent_cpu_summary(rounds, "enforce")
    assert a_cpu["n"] == 4 and _close(a_cpu["mean"], 2.0) and _close(a_cpu["p50"], 2.0)
    assert e_cpu["n"] == 4 and _close(e_cpu["mean"], 4.0)
    rss = om.agent_rss_summary(rounds, "enforce")
    assert rss["n"] == 2 and _close(rss["p50"], 110.0)


# --------------------------------------------------------------------------- #
# Paired contrast correctness across the THREE contrasts
# --------------------------------------------------------------------------- #

def test_three_contrasts_known_deltas():
    # Construct walls so each contrast has a KNOWN median delta:
    #   off=10, audit=12 (monitoring +2), enforce=15 (lsm +3 over audit, +5 over off)
    rounds = [_round(f"round_{i:03d}", [3.0], [5.0], [100.0], [120.0],
                     off_wall=10.0, audit_wall=12.0, enf_wall=15.0) for i in range(8)]
    sd = om.workload_slowdown(rounds)
    assert _close(sd["monitoring"]["median_delta"], 2.0)        # audit - off
    assert _close(sd["lsm_enforcement"]["median_delta"], 3.0)   # enforce - audit
    assert _close(sd["total_production"]["median_delta"], 5.0)  # enforce - off
    # breakdown adds up to the total
    assert _close(sd["monitoring"]["median_delta"] + sd["lsm_enforcement"]["median_delta"],
                  sd["total_production"]["median_delta"])
    # % slowdown for total: 5/10 = 50%
    assert _close(sd["total_production"]["median_pct"], 50.0)
    assert sd["total_production"]["n"] == 8


def test_median_paired_diff_and_wilcoxon_runs():
    on = [12.0, 13.0, 11.0, 14.0, 12.5, 13.5]
    off = [10.0, 10.0, 10.0, 10.0, 10.0, 10.0]
    assert _close(om.median_paired_diff(on, off), 2.75)         # median of [2,3,1,4,2.5,3.5]
    stat, p = om.wilcoxon_paired(on, off)
    assert not math.isnan(p) and p < 0.05                       # consistent positive shift
    # all-equal → no difference
    s0, p0 = om.wilcoxon_paired([5.0] * 5, [5.0] * 5)
    assert s0 == 0.0 and p0 == 1.0


def test_significant_but_tiny_reports_magnitude_beside_p():
    # LARGE N, SMALL consistent delta: enforce is 0.5%-CPU above off on every round.
    # Wilcoxon is highly significant (low p) BUT the effect size is small — the
    # whole point of reporting median diff ALONGSIDE p (significance != magnitude).
    n = 60
    off = [20.0 + (i % 3) for i in range(n)]                    # some spread
    on = [v + 0.5 for v in off]                                 # tiny consistent +0.5
    c = om.paired_contrast(on, off)
    assert c["n"] == n
    assert _close(c["median_delta"], 0.5)                       # SMALL magnitude
    assert c["p_value"] < 0.05                                  # yet STATISTICALLY significant
    # the report must not let a tiny effect masquerade as large: magnitude is 0.5
    assert c["median_delta"] < 1.0 < 5.0


def test_paired_contrast_empty_is_nan():
    c = om.paired_contrast([], [])
    assert c["n"] == 0 and math.isnan(c["median_delta"]) and math.isnan(c["p_value"])


def test_system_impact_three_contrasts():
    rounds = [_round(f"round_{i:03d}", [1.0], [1.0], [1.0], [1.0],
                     10.0, 11.0, 12.0,
                     sys_off=[20.0, 20.0], sys_audit=[22.0, 22.0], sys_enf=[25.0, 25.0])
              for i in range(6)]
    si = om.system_impact(rounds)
    assert _close(si["monitoring"]["median_delta"], 2.0)        # 22 - 20
    assert _close(si["lsm_enforcement"]["median_delta"], 3.0)   # 25 - 22
    assert _close(si["total_production"]["median_delta"], 5.0)  # 25 - 20


def test_per_op_us_is_length_invariant():
    # Same per-op cost regardless of how many ops: Δ scales with ops, Δ/op constant.
    assert _close(om.per_op_us(median_delta_ms=10.0, ops=1000), 10.0)    # 10ms/1000 = 10µs
    assert _close(om.per_op_us(median_delta_ms=100.0, ops=10000), 10.0)  # 100ms/10000 = 10µs
    assert math.isnan(om.per_op_us(10.0, None))
    assert math.isnan(om.per_op_us(10.0, 0))


def test_lsm_cpu_cost_enforce_minus_audit():
    # enforce mean agent CPU 5.0, audit 3.0 → LSM CPU cost +2.0 (per-round paired)
    rounds = [_round(f"round_{i:03d}", audit_cpu=[3.0, 3.0], enf_cpu=[5.0, 5.0],
                     audit_rss=[1.0], enf_rss=[1.0], off_wall=1, audit_wall=1, enf_wall=1)
              for i in range(6)]
    c = om.lsm_cpu_cost(rounds)
    assert c["n"] == 6 and _close(c["median_delta"], 2.0)
    assert math.isnan(om.lsm_cpu_cost([])["median_delta"])


def test_workload_ops_reads_recorded_ops():
    rounds = [{"sample_id": "round_000", "ops": 1_800_000, "audit_agent_cpu_pct": []},
              {"sample_id": "warmup_000", "ops": 9, "audit_agent_cpu_pct": []}]
    assert om.workload_ops(rounds) == 1_800_000      # warm-up ignored


def test_bootstrap_determinism_via_contrast():
    on = [12.0, 13.0, 11.0, 14.0, 12.5, 13.5, 15.0, 9.0]
    off = [10.0] * 8
    c1 = om.paired_contrast(on, off, seed=11)
    c2 = om.paired_contrast(on, off, seed=11)
    assert c1["delta_ci"] == c2["delta_ci"]                     # deterministic given seed
    lo, hi = c1["delta_ci"]
    assert lo <= c1["median_delta"] <= hi
