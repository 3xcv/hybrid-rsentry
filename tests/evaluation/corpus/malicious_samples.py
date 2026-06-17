#!/usr/bin/env python3
"""
tests/evaluation/corpus/malicious_samples.py — the malicious trial plan. [NO ROOT]

Wraps the four SAFE simulators (sim_akira, sim_qilin, sim_lockbit,
sim_entropy_only) as labeled Workloads for the harness. Every sample is bounded
to --max-files <= 10 (VM-hang guard, design constraint) and labeled malicious by
construction (label=1): the orchestrator launched a known sim, so ground truth is
certain (design §1.3).

`expected_primary_layer` is the design §3.4 HYPOTHESIS for which layer fires
first — it is a label for the analysis, NOT an assertion; the ablation/efficacy
runs are what confirm or refute it.

Two products:
  * malicious_plan(n_per_family) -> list[dict]   (serializable, for manifest.json)
  * build_workload(entry)        -> Workload     (runtime, for harness.run_trial)
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Optional

from tests.evaluation.harness import Workload, OPERATOR_UID, OPERATOR_GID

# The sim `--eval-timestamps` side-channel change has been applied to
# simulations/sim_common.py + sim_entropy_only.py, so the harness now passes
# --eval-timestamps <path> to the sims and t0 / files_touched_before_freeze are
# populated from the JSONL the sims emit (monotonic_ns; see harness._read_sidechannel).
SIMS_SUPPORT_EVAL_TIMESTAMPS = True

# Per-family attack parameters. max_files is capped at 10 everywhere.
FAMILIES: Dict[str, dict] = {
    "akira": {
        "sim_module": "simulations.sim_akira",
        "params": {"traversal": "dfs", "max_files": 10, "delay": 0.1},
        # Akira appends .akiranew → the rename/extension layer is the loud, first
        # signal live; design §3.4 lists entropy/write-offset as backups.
        "expected_primary_layer": "rename",
        "comm": "akira-locker",
    },
    "qilin": {
        "sim_module": "simulations.sim_qilin",
        "params": {"traversal": "dfs", "max_files": 10, "delay": 0.1},
        "expected_primary_layer": "rename",
        "comm": "qilin-locker",
    },
    "lockbit": {
        "sim_module": "simulations.sim_lockbit",
        "params": {"traversal": "dfs", "max_files": 10, "delay": 0.1},
        "expected_primary_layer": "rename",
        "comm": "lockbit-locker",
    },
    "entropy_only": {
        "sim_module": "simulations.sim_entropy_only",
        # entropy_only caps its own docs at 8; keep <=10.
        "params": {"traversal": "dfs", "max_files": 8, "delay": 0.1},
        "expected_primary_layer": "entropy",
        "comm": "entropy-locker",
    },
    "canary_touch": {
        # Renames a SEEDED decoy → caught ONLY by the canary layer (the
        # low-entropy ransom ext means the rename layer won't back it up). The
        # necessity-proof workload for the `-canary` ablation (Robustness §3).
        "sim_module": "simulations.sim_canary",
        "params": {"max_files": 5, "delay": 0.1},
        "expected_primary_layer": "canary",
        "comm": "canary-locker",
        # operates on the agent's decoys in the watch ROOT (seeded at startup),
        # not a fresh corpus zone — see build_workload's special setup.
        "targets_seeded_decoys": True,
    },
    "writeoffset_only": {
        # Encrypts an ALREADY high-entropy file IN PLACE with a scattered,
        # non-sequential write pattern → caught ONLY by the write-offset layer.
        # No rename/extension change (rename layer silent), no canary, and the
        # entropy delta is ≈0 (the file was ~8.0 before and after), so the
        # entropy layer is blind. The necessity-proof workload for the
        # `-write_offset` ablation (closes the documented gap — write_offset had
        # no necessity row). The sim self-prefills the seeded corpus file to
        # ~7.99 entropy, so it needs only ONE file.
        "sim_module": "simulations.sim_writeoffset",
        "params": {"max_files": 1, "delay": 0.1},
        "expected_primary_layer": "write_offset",
        "comm": "writeoffset-locker",
    },
}

_CORPUS_EXTS = (".docx", ".xlsx", ".pdf", ".db", ".jpg", ".vmdk")


def malicious_plan(n_per_family: int = 30) -> List[dict]:
    """Return the serializable malicious trial plan (n_per_family per family)."""
    if n_per_family < 1:
        raise ValueError("n_per_family must be >= 1")
    plan: List[dict] = []
    for family, spec in FAMILIES.items():
        for i in range(n_per_family):
            plan.append({
                "sample_id": f"mal_{family}_{i:03d}",
                "label": 1,
                "family": family,
                "sim_module": spec["sim_module"],
                "params": dict(spec["params"]),
                "expected_primary_layer": spec["expected_primary_layer"],
            })
    return plan


def _seed_corpus(zone: Path, n_files: int = 10) -> None:
    """Create a small, bounded, LOW-entropy corpus owned by UID 1000 so the sim
    (running as 1000) can read/overwrite/rename it. Low entropy makes any
    high-entropy in-place rewrite a clear jump."""
    docs = zone / "documents"
    docs.mkdir(parents=True, exist_ok=True)
    for i in range(n_files):
        ext = _CORPUS_EXTS[i % len(_CORPUS_EXTS)]
        f = docs / f"corpus_{i:03d}{ext}"
        # ~32 KB of repeating text → low entropy baseline.
        f.write_bytes((f"document-{i} ".encode() * 4096)[:32768])
    # Hand the whole zone to the operator UID and make it writable (rename/notes).
    for p in [zone, docs, *docs.iterdir()]:
        try:
            os.chown(p, OPERATOR_UID, OPERATOR_GID)
        except OSError:
            pass
    os.chmod(zone, 0o777)
    os.chmod(docs, 0o777)


def build_workload(entry: dict) -> Workload:
    """Build a runnable Workload from a malicious_plan entry."""
    family = entry["family"]
    spec = FAMILIES[family]
    sim_module = entry["sim_module"]
    params = entry["params"]
    zone_name = f"{family}_zone"
    targets_decoys = spec.get("targets_seeded_decoys", False)

    def setup(watch_dir: Path) -> Path:
        if targets_decoys:
            # canary_touch: the agent already seeded decoys in the watch ROOT at
            # startup (filesystem state IDENTICAL across ablation conditions — the
            # decoys are seeded the same way regardless of ABLATE_CANARY). The sim
            # renames those decoys; no fresh corpus zone is created.
            return watch_dir
        zone = watch_dir / zone_name
        _seed_corpus(zone)
        return zone

    def build_argv(exec_path: str, target: Path, ts_path: Optional[str]) -> List[str]:
        argv = [exec_path, "-m", sim_module,
                "--target", str(target), "--no-restore",
                "--max-files", str(params["max_files"]),
                "--delay", str(params["delay"])]
        if "traversal" in params:
            argv += ["--traversal", params["traversal"]]
        if ts_path:                                   # only when sims support it
            argv += ["--eval-timestamps", ts_path]
        return argv

    return Workload(
        sample_id=entry["sample_id"],
        label=1,
        family_or_class=family,
        setup=setup,
        build_argv=build_argv,
        comm=spec["comm"],
        uses_timestamps=SIMS_SUPPORT_EVAL_TIMESTAMPS,
        expected_primary_layer=entry["expected_primary_layer"],
    )
