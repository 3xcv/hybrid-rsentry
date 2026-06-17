"""
test_simulations.py — smoke tests confirming all simulation modules are importable
and that sim_all references the correct family list.
"""
import importlib


def test_sim_common_importable():
    mod = importlib.import_module("simulations.sim_common")
    assert hasattr(mod, "populate_corpus")
    assert hasattr(mod, "run_attack")


def test_sim_lockbit_importable():
    mod = importlib.import_module("simulations.sim_lockbit")
    assert hasattr(mod, "PROFILE")


def test_sim_akira_importable():
    mod = importlib.import_module("simulations.sim_akira")
    assert hasattr(mod, "PROFILE")


def test_sim_qilin_importable():
    mod = importlib.import_module("simulations.sim_qilin")
    assert hasattr(mod, "PROFILE")


def test_sim_all_has_all_families():
    from simulations.sim_all import _FAMILY_MODULES
    family_names = [label for label, _ in _FAMILY_MODULES]
    assert "LockBit 5.0" in family_names
    assert "Akira" in family_names
    assert "Qilin" in family_names
    assert len(_FAMILY_MODULES) == 3


def test_sim_all_importable():
    mod = importlib.import_module("simulations.sim_all")
    assert hasattr(mod, "run_all")
    assert hasattr(mod, "main")


# --------------------------------------------------------------------------- #
# write-offset-only necessity sim (closes the write_offset necessity-row gap)
# --------------------------------------------------------------------------- #

def test_sim_writeoffset_importable():
    mod = importlib.import_module("simulations.sim_writeoffset")
    assert hasattr(mod, "run_writeoffset_attack")
    assert hasattr(mod, "validate_defense")


def test_sim_writeoffset_offsets_trip_nonseq_at_fifth():
    """The scattered offsets must cross NONSEQ_THRESH on exactly the 5th
    non-sequential write (offset 57344) — the design contract."""
    from simulations.sim_writeoffset import (
        NONSEQ_OFFSETS, NONSEQ_THRESH, FILE_SIZE, _trace_nonseq,
    )
    n_until_fire, fire_idx = _trace_nonseq(NONSEQ_OFFSETS, FILE_SIZE)
    assert n_until_fire == NONSEQ_THRESH == 5
    assert fire_idx == NONSEQ_THRESH - 1            # 0-based index of the 5th write
    assert NONSEQ_OFFSETS[fire_idx] == 57344
    # bounded <= 10 writes total (1 sequential pre-fill + the scatter storm)
    assert 1 + len(NONSEQ_OFFSETS) <= 10
    # every scattered offset is non-sequential vs the running last_end
    last_end = FILE_SIZE
    for off in NONSEQ_OFFSETS:
        assert off != last_end
        last_end = off + 4096


def test_sim_writeoffset_validate_defense_passes(tmp_path):
    """Offline negative-space check: write_offset trips at the 5th write, the
    entropy delta stays < 6.5, and rename/canary stay silent (no root/BCC)."""
    from simulations.sim_writeoffset import validate_defense
    rc = validate_defense(str(tmp_path / "wo_sandbox"))
    assert rc == 0


def test_writeoffset_only_in_malicious_plan():
    """The plan must carry the 6th family with write_offset as its hypothesis."""
    from tests.evaluation.corpus.malicious_samples import FAMILIES, malicious_plan
    assert "writeoffset_only" in FAMILIES
    spec = FAMILIES["writeoffset_only"]
    assert spec["expected_primary_layer"] == "write_offset"
    assert spec["sim_module"] == "simulations.sim_writeoffset"
    plan = malicious_plan(15)
    wo = [e for e in plan if e["family"] == "writeoffset_only"]
    assert len(wo) == 15
    assert len(plan) == 6 * 15                       # 6 families now
