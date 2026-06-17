#!/usr/bin/env python3
"""
sim_writeoffset.py — the ONE workload whose detection uniquely depends on the
write-OFFSET layer (`observe_write_offset` → `trigger=write_offset`,
monitor_ebpf.py:514 / kernel NONSEQ_THRESH path at monitor_ebpf.py:1126).

WHY THIS SIM EXISTS (closes the documented gap — write_offset had no necessity
row)
  The four-layer ablation can only prove the write-offset layer is a *necessary*
  detector if some sample is caught ONLY by it. LockBit/Qilin/Akira land on
  rename; entropy_only lands on the behavioural entropy path; canary_touch lands
  on the canary layer. NONE isolates write_offset, so the `-write_offset`
  ablation row was a no-op against them. This sim is shaped to fall through every
  other layer and land solely on the non-sequential-write-storm detector.

  The real-world scenario it models: ransomware encrypting an ALREADY
  high-entropy file in place — a .zip / .jpg / .mp4 / .vmdk. The entropy gate is
  BLIND here (the file was ~8.0 before and is ~8.0 after → delta ≈ 0), there is
  no rename, no extension change, no canary — the scattered read-modify-write
  offset pattern is the only thing that betrays it.

THE LAYERS IT THREADS (thresholds confirmed in monitor_ebpf.py):

  A. FIRE write_offset  (the ONLY trigger)
     Per-inode kernel woff_t{last_end, nonseq}: a write whose offset != last_end
     increments nonseq; offset == last_end RESETS it. nonseq >= NONSEQ_THRESH(5)
     → silent_enc=1 → SILENT_ENCRYPTION(trigger=write_offset) and the PID is
     contained as layer=write_offset (monitor_ebpf.py:1126-1147, 1515-1532). The
     userspace mirror observe_write_offset() uses the same _NONSEQ_THRESHOLD(5);
     even if its per-PID counter lags the kernel, _handle_write's
     `or engine._make_event(..., trigger="write_offset")` fallback (line 1519)
     keeps the fired layer = write_offset.
        → Phase 1 (pre-fill) is ONE sequential write from offset 0 → establishes
          the inode baseline (last_end), nonseq=0, no alert.
        → Phase 2 issues 7 scattered 4 KB writes at offsets that are each
          != the running last_end. Traced:
            base last_end=65536 (pre-fill)
            32768 -> nonseq 1   8192 -> 2   49152 -> 3   16384 -> 4
            57344 -> 5  *** FIRES ***   (24576, 40960 = +2 margin)
          Total writes = 1 + 7 = 8  (<= the --max-files<=10 / VM-hang bound).
        (If the corpus seeder's own write already advanced the inode baseline,
         the storm only fires one write SOONER — still write_offset, never a
         different layer. The margin absorbs the off-by-one either way.)

  B. ENTROPY layer stays silent — TWO independent guarantees
     (1) STRUCTURAL: the entropy layer (_handle_behavior, layer=entropy) only
         runs when behavior_events fires, which needs proc score >= SCORE_ALERT
         (50). The only score signal is DELETES (__calc_score has no writes-only
         path). This sim issues ZERO deletes / renames / child-spawns, so the
         score never approaches 50 and the entropy path is never reached. The
         burst-entropy path (observe_write) needs >=10 writes AND >=3 inodes; we
         do 8 writes on 1 inode.
     (2) DELTA GATE (belt-and-suspenders matching the design framing): if entropy
         WERE sampled, entropy_fn -> EntropyEngine.observe() returns the rolling
         DELTA (max-min) once a file is >= HIGH_ENTROPY_ABSOLUTE(7.2). We pre-fill
         to ~7.99 and rewrite with ~7.99 content → delta ≈ 0.0 < the 6.5 gate →
         the entropy layer would not fire even if it were reached.

  C. RENAME / CANARY stay silent
     Same inode, same path, same extension — no os.rename is ever issued (rename
     layer silent). We operate ONLY on our own seeded corpus file and never an
     AAA_/aaa_/ZZZ_/zzz_ canary inode (canary layer silent).

SAFETY (benign sim — no cipher, no key)
  * Content is os.urandom — high entropy, but NOTHING is encrypted and no
    original bytes are derivable from it. It operates on a throwaway seeded
    corpus file inside --target.
  * --validate-defense runs inside a sentinel-guarded Sandbox (no root/BCC) and
    proves: write_offset trips at the 5th non-sequential write, the entropy delta
    stays < 6.5, no rename is issued, and the target is not a canary.

USAGE
    # Live (root + running eBPF sensor) — operate on a seeded corpus dir:
    sudo -E python3 -m simulations.sim_writeoffset \
         --target /tmp/rsentry_agent_watch/writeoffset_zone --no-restore \
         --max-files 1 --delay 0.1

    # Offline negative-space validation (no root, no BCC):
    python3 -m simulations.sim_writeoffset --validate-defense \
         --target /tmp/rsentry_sandbox
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple

from simulations.sim_common import (
    ATTACKER_PID, ATTACKER_PPID, DefenseResult, EvalTimestampWriter, Sandbox,
    build_validation_engine, file_entropy, populate_corpus, _set_comm,
)

NAME = "WRITEOFFSET_ONLY"

CANARY_PREFIXES = ("AAA_", "aaa_", "ZZZ_", "zzz_")

# Geometry — see analysis A. FILE_SIZE is <= the 64 KB entropy read window so the
# whole file is high-entropy when sampled. BLOCK is one scattered write.
FILE_SIZE = 65536
BLOCK = 4096

# Scattered offsets for the non-sequential storm. Each is verified at build time
# (and in --validate-defense) to differ from the running last_end, so nonseq
# climbs monotonically and crosses NONSEQ_THRESH(5) on the 5th entry (57344).
# The last two (24576, 40960) are margin beyond the threshold.
NONSEQ_OFFSETS: Tuple[int, ...] = (32768, 8192, 49152, 16384, 57344, 24576, 40960)

DEFAULT_KEEPALIVE_S = 20.0    # stay alive for the SIGSTOP→isolate→SIGKILL pipeline
NONSEQ_THRESH = 5             # mirror of monitor_ebpf NONSEQ_THRESH / _NONSEQ_THRESHOLD


# --------------------------------------------------------------------------- #
# Target selection
# --------------------------------------------------------------------------- #

def _select_target(root: str) -> Path:
    """Pick ONE non-canary corpus file under root (seed a corpus if empty)."""
    def _is_doc(p: Path) -> bool:
        return (p.is_file()
                and not p.name.startswith(CANARY_PREFIXES)
                and p.name != ".rsentry_sandbox")

    docs = sorted(p for p in Path(root).rglob("*") if _is_doc(p))
    if not docs:
        populate_corpus(root)
        docs = sorted(p for p in Path(root).rglob("*") if _is_doc(p))
    if not docs:
        # Last resort: synthesize a single file so the sim always has a victim.
        d = Path(root) / "documents"
        d.mkdir(parents=True, exist_ok=True)
        f = d / "writeoffset_target.bin"
        f.write_bytes(b"document " * 4096)
        return f
    return docs[0]


# --------------------------------------------------------------------------- #
# Live attack
# --------------------------------------------------------------------------- #

def run_writeoffset_attack(root: str,
                           delay: float = 0.1,
                           keepalive_s: float = DEFAULT_KEEPALIVE_S,
                           ts_writer: Optional["EvalTimestampWriter"] = None) -> dict:
    """Drive the running eBPF sensor toward layer=write_offset ONLY.

    Phase 1: pre-fill the target IN PLACE with high-entropy bytes (sequential,
             one write) → models an already-compressed file and seeds the inode's
             write-offset baseline.
    Phase 2: scattered 4 KB in-place writes (same inode, no rename) → the kernel
             nonseq counter crosses NONSEQ_THRESH(5) → SILENT_ENCRYPTION
             (trigger=write_offset).
    Phase 3: sleep (no writes) so the PID is alive for containment.
    """
    target = _select_target(root)
    stats = {"target": str(target), "prefill_bytes": 0, "scatter_writes": 0,
             "offsets": list(NONSEQ_OFFSETS), "entropy_before": 0.0,
             "entropy_after": 0.0}

    if target.name.startswith(CANARY_PREFIXES):     # defense in depth
        raise RuntimeError(f"refusing to operate on a canary inode: {target}")

    fd = os.open(str(target), os.O_RDWR | os.O_CREAT, 0o644)
    try:
        # ---- Phase 1: high-entropy in-place pre-fill (sequential baseline) ----
        if ts_writer is not None:
            ts_writer.touch(str(target), "prefill")     # first touch == t0
        prefill = os.urandom(FILE_SIZE)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, prefill)
        os.ftruncate(fd, FILE_SIZE)
        os.fsync(fd)
        stats["prefill_bytes"] = FILE_SIZE
        stats["entropy_before"] = round(file_entropy(str(target)), 3)
        if delay > 0:
            time.sleep(delay)

        # ---- Phase 2: scattered non-sequential writes (the write_offset storm)-
        for off in NONSEQ_OFFSETS:
            if ts_writer is not None:
                ts_writer.touch(str(target), "scatter_write")
            os.lseek(fd, off, os.SEEK_SET)
            os.write(fd, os.urandom(BLOCK))     # same inode, no rename, high entropy
            os.fsync(fd)
            stats["scatter_writes"] += 1
            if delay > 0:
                time.sleep(delay)
        stats["entropy_after"] = round(file_entropy(str(target)), 3)

        # Close the side-channel writer now (end of the active attack); t0 and
        # every per-write touch are already recorded.
        if ts_writer is not None:
            ts_writer.close()

        # ---- Phase 3: stay alive for SIGSTOP→isolate→SIGKILL ------------------
        deadline = time.time() + keepalive_s
        while time.time() < deadline:
            time.sleep(0.2)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass

    return stats


# --------------------------------------------------------------------------- #
# Offline negative-space validation (no root): prove write_offset trips at the
# 5th non-seq write, the entropy delta stays sub-gate, and rename/canary stay
# silent — so live detection can only be layer=write_offset.
# --------------------------------------------------------------------------- #

def _trace_nonseq(offsets: Tuple[int, ...], baseline_end: int) -> Tuple[int, Optional[int]]:
    """Replay the kernel/userspace non-seq counter purely in Python.
    Returns (nonseq_writes_until_fire, index_that_fires) — index is 0-based into
    `offsets`, or None if the threshold is never reached."""
    last_end = baseline_end
    nonseq = 0
    fire_idx: Optional[int] = None
    for i, off in enumerate(offsets):
        if off != last_end:
            nonseq += 1
            if nonseq >= NONSEQ_THRESH and fire_idx is None:
                fire_idx = i
                nonseq = 0          # kernel resets after firing
        else:
            nonseq = 0
        last_end = off + BLOCK
    return (fire_idx + 1 if fire_idx is not None else 0), fire_idx


def validate_defense(target: str) -> int:
    with Sandbox(target) as sb:
        sb.arm()
        engine = build_validation_engine(sb.root_real)
        doc = sb.corpus_files()[0]
        p = sb.assert_inside(doc)
        inode = p.stat().st_ino

        # (0) Pre-fill the file to high entropy IN PLACE (the "already ~8.0"
        #     baseline) and capture its entropy BEFORE the encrypting writes.
        with open(p, "r+b") as fh:
            fh.seek(0)
            fh.write(os.urandom(FILE_SIZE))
            fh.truncate(FILE_SIZE)
            fh.flush()
            os.fsync(fh.fileno())
        entropy_before = file_entropy(str(p))

        # (1) WRITE-OFFSET layer must FIRE. Feed the engine the baseline (one
        #     sequential write) then the scattered storm and capture the event.
        engine.observe_write_offset(
            ATTACKER_PID, ATTACKER_PPID, "writeoffset-sim",
            inode, 0, FILE_SIZE, str(p), ts=0.0,
        )
        wo_evt = None
        fired_at = None
        last_end = FILE_SIZE
        for i, off in enumerate(NONSEQ_OFFSETS):
            with open(p, "r+b") as fh:
                fh.seek(off)
                fh.write(os.urandom(BLOCK))
                fh.flush()
                os.fsync(fh.fileno())
            r = engine.observe_write_offset(
                ATTACKER_PID, ATTACKER_PPID, "writeoffset-sim",
                inode, off, BLOCK, str(p), ts=float(i + 1),
            )
            if r is not None and wo_evt is None:
                wo_evt = r
                fired_at = i + 1            # 1-based count of non-seq writes
            last_end = off + BLOCK
        write_offset_fired = (
            wo_evt is not None
            and wo_evt.get("event_type") == "SILENT_ENCRYPTION"
            and wo_evt.get("details", {}).get("trigger") == "write_offset"
        )
        # Independent pure-Python trace of WHERE it should fire (== 5th write).
        n_until_fire, _ = _trace_nonseq(NONSEQ_OFFSETS, FILE_SIZE)
        fires_at_fifth = (n_until_fire == NONSEQ_THRESH and fired_at == NONSEQ_THRESH)

        # (2) ENTROPY delta sub-gate: pre-fill ~8.0 and rewrite ~8.0 → delta ≈ 0.
        #     We measure the on-disk file before vs after the storm; the gate the
        #     live entropy layer applies is entropy_fn(path) >= 6.5 where entropy_fn
        #     returns the DELTA once a file is high-entropy.
        entropy_after = file_entropy(str(p))
        entropy_delta = abs(entropy_after - entropy_before)
        entropy_subgate = entropy_delta < 6.5

        # (3) no rename issued; target is not a canary.
        no_canary = not p.name.startswith(CANARY_PREFIXES)
        no_rename = (p.stat().st_ino == inode)    # same inode → never renamed

        ok = write_offset_fired and fires_at_fifth and entropy_subgate and no_canary and no_rename
        result = DefenseResult(
            family=NAME,
            defense="write-offset layer necessity (negative space)",
            signal="layer=write_offset (non-sequential write storm)",
            fired=ok,
            files_harmed=0,                      # audited on Sandbox __exit__
            detail={
                "nonseq_threshold": NONSEQ_THRESH,
                "nonseq_writes_until_fire": fired_at,
                "fires_at_fifth_write": fires_at_fifth,
                "fire_offset": NONSEQ_OFFSETS[NONSEQ_THRESH - 1],
                "total_scatter_writes": len(NONSEQ_OFFSETS),
                "write_offset_trigger": (wo_evt or {}).get("details", {}).get("trigger"),
                "entropy_before": round(entropy_before, 3),
                "entropy_after": round(entropy_after, 3),
                "entropy_delta": round(entropy_delta, 3),
                "entropy_delta<6.5_gate": entropy_subgate,
                "renames_issued": 0,
                "same_inode(no_rename)": no_rename,
                "canary_touched": False,
                "note": "live containment (layer=write_offset) is observable only "
                        "under the running eBPF sensor; this offline check proves "
                        "the non-seq storm trips the write-offset detector while "
                        "the entropy/rename/canary layers stay silent so it is the "
                        "sole catcher.",
            },
        )
    print(result.banner())
    return 0 if result.fired else 1


# --------------------------------------------------------------------------- #
# Live main
# --------------------------------------------------------------------------- #

def live_main(ap: argparse.ArgumentParser) -> int:
    args = ap.parse_args()
    root = args.target

    if not os.path.isdir(root):
        print(f"[{NAME}] creating target dir: {root}")
        os.makedirs(root, exist_ok=True)
        populate_corpus(root)

    # Refuse to operate inside a git repo (corpus writes could corrupt refs).
    check = Path(root).resolve()
    for _ in range(10):
        if (check / ".git").is_dir():
            print(f"[{NAME}] ERROR: target {root} is inside a git repo — aborting")
            return 1
        if check.parent == check:
            break
        check = check.parent

    print(f"[{NAME}] starting write-offset-only simulation | delay={args.delay}")

    ts_writer = None
    if getattr(args, "eval_timestamps", None):
        ts_writer = EvalTimestampWriter(args.eval_timestamps)
        ts_writer.start(os.getpid())

    try:
        stats = run_writeoffset_attack(
            root,
            delay=args.delay if args.delay is not None else 0.1,
            ts_writer=ts_writer,
        )
    finally:
        if ts_writer is not None:
            ts_writer.close()

    print(f"[{NAME}] done | target={stats['target']} "
          f"prefill={stats['prefill_bytes']}B scatter_writes={stats['scatter_writes']} "
          f"entropy {stats['entropy_before']}→{stats['entropy_after']} "
          f"(delta={round(abs(stats['entropy_after'] - stats['entropy_before']), 3)})")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Write-offset-only simulator (safe) — caught ONLY by the "
                    "write-offset layer (non-sequential write storm, "
                    "trigger=write_offset)")
    # Mirror add_common_args' surface (the harness passes --target/--no-restore/
    # --max-files/--delay[/--traversal][/--eval-timestamps]); --max-files and
    # --traversal are accepted for parity but this sim operates on ONE file.
    ap.add_argument("--target", required=True, help="dir to simulate on")
    ap.add_argument("--no-restore", action="store_true",
                    help="accepted for harness parity (corpus is throwaway)")
    ap.add_argument("--max-files", type=int, default=1,
                    help="accepted for parity; the storm targets ONE inode")
    ap.add_argument("--delay", type=float, default=None)
    ap.add_argument("--traversal", default="dfs")            # accepted, unused
    ap.add_argument("--eval-timestamps", default=None, metavar="PATH")
    ap.add_argument("--validate-defense", action="store_true",
                    help="offline negative-space validation: prove the non-seq "
                         "storm trips write_offset at the 5th write, the entropy "
                         "delta stays < 6.5, and rename/canary stay silent "
                         "(no root/BCC needed)")
    args, _ = ap.parse_known_args()
    if args.validate_defense:
        raise SystemExit(validate_defense(args.target))
    _set_comm("writeoffset-locker")
    raise SystemExit(live_main(ap))
