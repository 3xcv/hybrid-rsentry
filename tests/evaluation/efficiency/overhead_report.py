#!/usr/bin/env python3
"""
tests/evaluation/efficiency/overhead_report.py — render the §2 overhead tables. [NO ROOT]

Reads overhead_raw.json (paired rounds), recomputes via overhead_metrics, prints
ASCII tables. EFFECT SIZE leads; the Wilcoxon p is a trailing secondary column.
The three contrasts — monitoring (audit−off), LSM hooks (enforce−audit), total
production (enforce−off) — are all shown so the reader sees both the breakdown
and the production total. Completeness banner first.

Usage:
    python3 -m tests.evaluation.efficiency.overhead_report [path/to/overhead_raw.json]
"""
from __future__ import annotations

import json
import math
import sys
from pathlib import Path
from typing import List

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from tests.evaluation.conftest import read_trials
from tests.evaluation.efficacy.report import _table, _fmt, _ci
from tests.evaluation.efficiency import overhead_metrics as om
from tests.evaluation.efficiency.overhead_runner import OVERHEAD_RAW, OVERHEAD_REPORT

_CONTRAST_LABEL = {
    "monitoring": "monitoring (audit-off)",
    "lsm_enforcement": "LSM hooks (enforce-audit)",
    "total_production": "total prod (enforce-off)",
}


def _pval(p: float) -> str:
    if p is None or (isinstance(p, float) and math.isnan(p)):
        return "n/a"
    return "<0.001" if p < 0.001 else f"{p:.3f}"


def _load_completeness() -> "dict | None":
    if not OVERHEAD_REPORT.is_file():
        return None
    try:
        return json.loads(OVERHEAD_REPORT.read_text()).get("_meta", {}).get("completeness")
    except (OSError, json.JSONDecodeError):
        return None


def completeness_banner(comp: "dict | None") -> str:
    if comp is None:
        return ("[OVERHEAD] Completeness: UNKNOWN — no overhead_report.json. Run the "
                "sweep via overhead_runner.py so recorded-vs-planned can be reconciled.")
    status = "COMPLETE" if comp["complete"] else "*** INCOMPLETE ***"
    line = (f"[OVERHEAD] Completeness: {status}  (ran {comp['ran']}/{comp['planned']} "
            f"rounds; missing={comp['missing']}, errored={comp['errored']})")
    if not comp["complete"]:
        line += "\n  Deltas below are over the RECORDED rounds only — NOT the full planned N."
    return line


def agent_cpu_table(rounds: List[dict]) -> str:
    rows = []
    for cond in ("audit", "enforce"):
        s = om.agent_cpu_summary(rounds, cond)
        rows.append([cond, str(s["n"]), _fmt(s["p50"]), _fmt(s["p95"]),
                     _fmt(s["p99"]), _fmt(s["mean"]), _fmt(s["max"])])
    return _table("[OVERHEAD] Agent CPU (steady-state, %; can exceed 100 on multicore)",
                  ["Condition", "samples", "p50", "p95", "p99", "mean", "max"], rows)


def agent_rss_table(rounds: List[dict]) -> str:
    rows = []
    for cond in ("audit", "enforce"):
        s = om.agent_rss_summary(rounds, cond)
        rows.append([cond, str(s["n"]), _fmt(s["p50"]), _fmt(s["p95"]),
                     _fmt(s["p99"]), _fmt(s["mean"]), _fmt(s["max"])])
    return _table("[OVERHEAD] Agent Memory — RSS (MB)",
                  ["Condition", "samples", "p50", "p95", "p99", "mean", "max"], rows)


def slowdown_table(rounds: List[dict]) -> str:
    sd = om.workload_slowdown(rounds)
    ops = om.workload_ops(rounds)
    rows = []
    for key in ("monitoring", "lsm_enforcement", "total_production"):
        c = sd[key]
        rows.append([_CONTRAST_LABEL[key], str(c["n"]), _fmt(c["off_p50"]),
                     _fmt(c["on_p50"]), _fmt(c["median_delta"]),
                     _fmt(om.per_op_us(c["median_delta"], ops)), _fmt(c["median_pct"]),
                     _ci(c["delta_ci"]), _pval(c["p_value"])])
    title = ("[OVERHEAD] Workload Slowdown (wall-time; Δ/op µs is the steady-state "
             f"headline — invariant to workload length; ops/half={ops})")
    return _table(title,
                  ["Contrast", "n", "off p50 ms", "on p50 ms", "Δ median ms",
                   "Δ/op µs", "Δ %", "Δ median 95% CI", "Wilcoxon p"], rows)


def lsm_cost_table(rounds: List[dict]) -> str:
    """The LSM-hook cost two ways: per-op wall (PRIMARY — kernel-inline cost lands
    in the workload's time) and agent CPU% (SECONDARY — mostly userspace path)."""
    ops = om.workload_ops(rounds)
    wall = om.workload_slowdown(rounds)["lsm_enforcement"]
    cpu = om.lsm_cpu_cost(rounds)
    wlo, whi = wall["delta_ci"]                       # ms → convert CI to per-op µs too
    per_op_ci = (om.per_op_us(wlo, ops), om.per_op_us(whi, ops))
    rows = [
        ["per-op wall (µs/op)  [PRIMARY]", str(wall["n"]),
         _fmt(om.per_op_us(wall["median_delta"], ops)), _ci(per_op_ci),
         _pval(wall["p_value"])],
        ["agent CPU (%)  [secondary]", str(cpu["n"]),
         _fmt(cpu["median_delta"]), _ci(cpu["delta_ci"]), _pval(cpu["p_value"])],
    ]
    return _table("[OVERHEAD] LSM Hook Cost (enforce−audit; kernel-inline → lands in "
                  "wall/system-CPU, not agent CPU)",
                  ["Measure", "n", "Δ median", "Δ median 95% CI", "Wilcoxon p"], rows)


def system_impact_table(rounds: List[dict]) -> str:
    si = om.system_impact(rounds)
    rows = []
    for key in ("monitoring", "lsm_enforcement", "total_production"):
        c = si[key]
        rows.append([_CONTRAST_LABEL[key], str(c["n"]), _fmt(c["median_delta"]),
                     _ci(c["delta_ci"]), _pval(c["p_value"])])
    return _table("[OVERHEAD] System Impact (system-CPU% delta; effect size leads)",
                  ["Contrast", "n", "Δ median %", "Δ median 95% CI", "Wilcoxon p"], rows)


def render(rounds: List[dict]) -> str:
    return "\n\n".join([
        completeness_banner(_load_completeness()),
        agent_cpu_table(rounds),
        agent_rss_table(rounds),
        slowdown_table(rounds),
        lsm_cost_table(rounds),
        system_impact_table(rounds),
    ])


def main() -> int:
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else OVERHEAD_RAW
    rounds = read_trials(src)
    if not rounds:
        print(f"No rounds found at {src}. Run the overhead sweep first.")
        return 1
    print(f"# Overhead report — source: {src} ({len(rounds)} raw round records)\n")
    print(render(rounds))
    return 0


if __name__ == "__main__":
    sys.exit(main())
