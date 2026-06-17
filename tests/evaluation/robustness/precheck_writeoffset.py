#!/usr/bin/env python3
"""
precheck_writeoffset.py — CRITICAL precondition for the write_offset necessity
proof. ROOT-ONLY (run_trial starts the agent).

Runs ONE writeoffset_only trial at BASELINE (all layers on) and asserts the
single thing the necessity proof depends on:

    detected == True  AND  layer_fired == "write_offset"

If it fires entropy / rename / canary / None instead, the sim is NOT isolating
the write-offset layer — STOP and fix the sim before any sweep, because the
`-write_offset` ablation drop would otherwise be attributable to another layer.

Run it under the SAME interpreter the harness uses for the agent:

    cd ~/hybrid-rsentry && set -a && source .env && set +a
    sudo -E ~/hybrid-rsentry/venv/bin/python -m tests.evaluation.robustness.precheck_writeoffset

Exit 0 = PASS (fired write_offset), 1 = FAIL (wrong/no layer), 2 = not root.
It does NOT write to robustness_raw.json — it is a throwaway check.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from tests.evaluation.corpus import malicious_samples as M
from tests.evaluation.harness import run_trial

FAMILY = "writeoffset_only"


def _entry():
    for e in M.malicious_plan(1):
        if e["family"] == FAMILY:
            return e
    raise SystemExit(f"FAIL: family {FAMILY!r} not in malicious_plan — add the "
                     "plan entry first.")


def main() -> int:
    if os.geteuid() != 0:
        print("FAIL: run under sudo (root). See the module docstring.")
        return 2

    wl = M.build_workload(_entry())
    print(f"[precheck] running ONE baseline trial: {wl.sample_id} "
          f"(expected_primary_layer={wl.expected_primary_layer})")
    res = run_trial(wl, lsm=True, enforce=True, response_timeout=30.0)
    d = res.to_dict()

    detected = bool(d.get("detected"))
    layer = d.get("layer_fired")
    print("\n  RESULT:")
    for k in ("sample_id", "detected", "contained", "layer_fired",
              "t_detect", "t_sigstop", "t_kill", "t_complete"):
        print(f"      {k} = {d.get(k)}")

    ok = detected and layer == "write_offset"
    print("\n" + "=" * 72)
    if ok:
        print("PASS ✓ — baseline fired layer=write_offset. write_offset is the sole "
              "catcher; the necessity proof precondition holds. Proceed to the sweep.")
        return 0
    print(f"FAIL ✗ — detected={detected} layer_fired={layer!r} "
          "(needed detected=True, layer=write_offset).")
    print("STOP: do NOT run the sweep. The write_offset necessity proof depends on "
          "write_offset being the sole catcher. Fix the sim "
          "(simulations/sim_writeoffset.py) — e.g. confirm the scattered offsets "
          "stay non-sequential and no rename/delete leaks into the attack path.")
    print("=" * 72)
    return 1


if __name__ == "__main__":
    sys.exit(main())
