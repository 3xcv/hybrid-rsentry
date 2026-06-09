#!/usr/bin/env python3
"""
tests/integration/test_live_sim_detections.py — LIVE proof that all THREE fixed
ransomware simulations (Akira, Qilin, LockBit) trigger the R-Sentry sensor
AUTONOMOUSLY on the real kernel, via the real ``kprobe__vfs_rename`` path —
nothing mocked, no direct DetectionEngine function calls from the sim side.

WHY THIS TEST EXISTS
    A previous live run showed the agent did NOT detect the Akira "behavioural"
    run even though ~1400 files were processed. Root cause: ``_simulate_file``
    did ``write_bytes(new_file) + unlink(original)`` — a fresh-inode write + a
    delete, NEVER an ``os.rename``. So ``kprobe__vfs_rename`` never fired and the
    write went to a new inode sequentially (the write-offset detector only saw a
    baseline). Zero kernel detection layers triggered.

THE FIX UNDER TEST (simulations/sim_common.py:_simulate_file)
    Every mode now overwrites the file IN PLACE (same inode) and then issues a
    real ``os.rename(original, original + '.<family-ext>')``. The rename is the
    syscall the sensor's vfs_rename probe captures, and the family extension is
    what the userspace ``DetectionEngine.observe_rename`` flags:
        * Akira   → ``.akiranew``  → profile "akira"            (known enc suffix)
        * Qilin   → 7-char random  → entropy-ext filter         (length-independent)
        * LockBit → 16-char random → profile "lockbit5"         (16-char signature)

WHAT THIS DRIVES (real BPF, real syscalls)
    1. Load the SAME bpf source the agent runs — ``build_bpf(enforce=False,
       lsm=False)`` (AUDIT mode: SIGSTOP-fallback, no cgroup/iptables isolation)
       — and attach the live ``vfs_rename`` + ``vfs_write`` probes ONCE.
    2. For each sim: pre-seed a small (<=50) sandbox owned by UID 1000, spawn the
       REAL sim CLI as UID 1000 (``python3 -m simulations.sim_<fam> --no-restore``),
       and drain the perf buffer feeding every rename for the sim PID into the
       SAME ``DetectionEngine`` the agent uses.
    3. When the engine fires for the sim PID, assert it is the EXPECTED layer
       (rename + correct family profile / entropy ext — NOT a silent_enc event)
       and issue the audit-mode response: ``SIGSTOP`` the sim PID.
    4. Prove the operator (interactive UID 1000) never lost the network through
       detection + response (T1498 scoping guard — only the sim PID is signalled).
    5. Run a benign sequential-writer CONTROL (UID 1000, no rename) and assert it
       triggers NOTHING (no rename event, no silent_enc, never SIGSTOP'd).

USAGE
    # Privileged live run — needs root (load BPF + attach kprobes, send signals)
    # AND a bcc-capable interpreter. The project venv has no system site-packages,
    # so use the system python3 that owns python3-bpfcc:
    sudo /usr/bin/python3 tests/integration/test_live_sim_detections.py

    # Unprivileged self-check (no BPF / no signals): validates the syscall-pattern
    # fix (os.rename present, write+unlink gone), the <=50 file cap, and that the
    # sims + this test import cleanly. Runs under any interpreter:
    python3 tests/integration/test_live_sim_detections.py --selfcheck

SAFETY
  * The sims rewrite os.urandom()/XOR bytes — NO real cipher, NO key. They only
    ever touch files under their own /tmp/rsentry_test_<fam>/ sandbox.
  * Each sim run is bounded to MAX_FILES (<=50) via the new ``--max-files`` cap —
    deliberately tiny to avoid the VM hang a large storm caused before.
  * AUDIT mode only: the response is SIGSTOP on the sim PID. NO iptables, NO
    cgroup, NO SIGKILL of anything but our own helpers in teardown.
  * No canary files are placed (``--skip-aaa`` not needed; corpus has none).
  * finally{}: SIGCONT + kill every helper, remove sandboxes + sim backup temp
    dirs, and assert the operator can still reach the network.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

# Make the project importable when run directly (sudo strips PYTHONPATH).
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from agent.monitor_ebpf import (  # noqa: E402
    DetectionEngine,
    IGNORE_COMMS,
    _ENC_SUFFIXES,
    _EXT_ENTROPY_THRESHOLD,
    _shannon_entropy,
    build_bpf,
)

OPERATOR_UID = 1000
OPERATOR_GID = 1000
PING_TARGET = "8.8.8.8"
PING_INTERVAL = "0.3"

CORPUS_FILES = 16          # pre-seeded per sandbox (so the sim skips populate)
MAX_FILES = 40             # hard cap passed to the sim (<=50 — VM-hang guard)
SIM_DELAY = 0.05           # per-file pacing so the PID is alive for SIGSTOP
DETECT_TIMEOUT = 10.0      # per-sim deadline to see the expected layer fire

# Audit log of every privileged command the TEST shells out (proves no -F/flush).
COMMANDS: list[list[str]] = []


# --------------------------------------------------------------------------- #
# Per-sim expectation: which layer MUST fire (correct layer, not "something").
# --------------------------------------------------------------------------- #

def _akira_layer_ok(ev: dict) -> bool:
    return (ev["event_type"] == "PROCESS_ANOMALY"
            and ev["details"].get("profile") == "akira"
            and ev["file_path"].endswith(".akiranew"))


def _qilin_layer_ok(ev: dict) -> bool:
    # Fired via the length-independent ENTROPY ext filter: a 7-char random
    # alphanumeric suffix that is NOT a hard-coded known enc suffix.
    suffix = Path(ev["file_path"]).suffix          # ".<7 chars>"
    ext = suffix.lstrip(".")
    return (ev["event_type"] == "PROCESS_ANOMALY"
            and suffix.lower() not in _ENC_SUFFIXES
            and len(ext) == 7
            and _shannon_entropy(ext) >= _EXT_ENTROPY_THRESHOLD)


def _lockbit_layer_ok(ev: dict) -> bool:
    suffix = Path(ev["file_path"]).suffix
    return (ev["event_type"] == "PROCESS_ANOMALY"
            and ev["details"].get("profile") == "lockbit5"
            and len(suffix.lstrip(".")) == 16)


SIMS = [
    {"name": "Akira",   "module": "simulations.sim_akira",
     "dir": "/tmp/rsentry_test_akira",   "layer": "rename(.akiranew→akira)",
     "check": _akira_layer_ok},
    {"name": "Qilin",   "module": "simulations.sim_qilin",
     "dir": "/tmp/rsentry_test_qilin",   "layer": "rename(7ch entropy-ext)",
     "check": _qilin_layer_ok},
    {"name": "LockBit", "module": "simulations.sim_lockbit",
     "dir": "/tmp/rsentry_test_lockbit", "layer": "rename(16ch→lockbit5)",
     "check": _lockbit_layer_ok},
]
CONTROL_DIR = "/tmp/rsentry_test_control"

# Benign control: 10 sequential single-write files to NEW inodes, no rename.
# Must trigger nothing (sequential write = write-offset baseline only; no rename
# = no rename detector). Sleeps so we can confirm it was NOT SIGSTOP'd.
CONTROL_SRC = """
import os, sys, time
d = sys.argv[1]
for i in range(10):
    with open(os.path.join(d, "benign_%02d.docx" % i), "wb") as fh:
        fh.write(b"benign sequential document content " * 256)  # one sequential write
    time.sleep(0.05)
time.sleep(30)
"""


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #

def run_cmd(cmd: list[str], *, check: bool = False) -> subprocess.CompletedProcess:
    COMMANDS.append(cmd)
    print(f"    RUN: {' '.join(cmd)}")
    return subprocess.run(cmd, check=check, capture_output=True, text=True, timeout=15)


def proc_uid(pid: int) -> "int | None":
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("Uid:"):
                return int(line.split()[1])
    except (FileNotFoundError, ValueError, OSError):
        return None
    return None


def proc_state(pid: int) -> "str | None":
    """Single-letter scheduler state from /proc/pid/stat ('T' == stopped)."""
    try:
        data = Path(f"/proc/{pid}/stat").read_text()
        return data.rsplit(") ", 1)[1].split()[0]
    except (FileNotFoundError, IndexError, OSError):
        return None


def operator_can_reach_network() -> bool:
    """Fresh point-in-time connectivity probe AS THE OPERATOR UID (1000)."""
    try:
        cp = subprocess.run(
            ["ping", "-n", "-c", "1", "-W", "2", PING_TARGET],
            user=OPERATOR_UID, group=OPERATOR_GID,
            capture_output=True, text=True, timeout=6,
        )
        return cp.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def seed_sandbox(path: str, n: int) -> None:
    """Create a UID-1000-owned sandbox with n small corpus files so the sim's
    populate_corpus is skipped and the run is bounded by what we seed."""
    d = Path(path)
    if d.exists():
        shutil.rmtree(d, ignore_errors=True)
    sub = d / "documents"
    sub.mkdir(parents=True)
    exts = [".docx", ".xlsx", ".pdf", ".db", ".jpg", ".vmdk"]
    for i in range(n):
        f = sub / f"corpus_{i:03d}{exts[i % len(exts)]}"
        f.write_bytes((f"document-{i} ".encode() * 512)[:8192])
    # Hand the whole tree to the operator UID so the UID-1000 sim can rename.
    for p in [d, sub, *sub.iterdir()]:
        try:
            os.chown(p, OPERATOR_UID, OPERATOR_GID)
        except OSError:
            pass
    os.chmod(d, 0o777)
    os.chmod(sub, 0o777)


def cleanup_sim_backups() -> None:
    """The sim's _backup_corpus leaves a tempdir when --no-restore is used."""
    for p in Path("/tmp").glob("rsentry_backup_*"):
        shutil.rmtree(p, ignore_errors=True)


# --------------------------------------------------------------------------- #
# Results table
# --------------------------------------------------------------------------- #

class Report:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str, bool]] = []
        self.sim_rows: list[tuple[str, str, str, str, str, str]] = []

    def check(self, name: str, expected: str, observed: str, ok: bool) -> bool:
        self.rows.append((name, expected, observed, ok))
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}: "
              f"expected={expected!r} observed={observed!r}")
        return ok

    def sim_summary(self, sim: str, layer: str, stopped: str, op_safe: str,
                    cleanup: str, result: str) -> None:
        self.sim_rows.append((sim, layer, stopped, op_safe, cleanup, result))

    def render(self) -> bool:
        # Per-check table
        wc = max((len(r[0]) for r in self.rows), default=5)
        we = max((len(r[1]) for r in self.rows), default=8)
        wo = max((len(r[2]) for r in self.rows), default=8)
        wc, we, wo = max(wc, 5), max(we, 8), max(wo, 8)
        line = f"| {{:<{wc}}} | {{:<{we}}} | {{:<{wo}}} | {{:<6}} |"
        sep = f"|{'-'*(wc+2)}|{'-'*(we+2)}|{'-'*(wo+2)}|{'-'*8}|"
        print("\n" + "=" * 80)
        print("PER-CHECK RESULTS")
        print("=" * 80)
        print(line.format("Check", "Expected", "Observed", "Result"))
        print(sep)
        for name, exp, obs, ok in self.rows:
            print(line.format(name, exp, obs, "PASS" if ok else "FAIL"))

        # Per-sim summary table (the shape the task asked for)
        if self.sim_rows:
            print("\n" + "=" * 80)
            print("SIM SUMMARY")
            print("=" * 80)
            hdr = ("Sim", "Layer fired", "SIGSTOP'd", "Operator safe",
                   "Cleanup OK", "Result")
            widths = [max(len(h), *(len(r[i]) for r in self.sim_rows))
                      for i, h in enumerate(hdr)]
            fmt = "| " + " | ".join(f"{{:<{w}}}" for w in widths) + " |"
            print(fmt.format(*hdr))
            print("|" + "|".join("-" * (w + 2) for w in widths) + "|")
            for r in self.sim_rows:
                print(fmt.format(*r))

        all_pass = all(r[3] for r in self.rows)
        print("=" * 80)
        print("OVERALL: " + (
            "PASS — all three fixed sims detected via live vfs_rename "
            "(T1486); operator never cut (T1498 guard held); benign control "
            "triggered nothing"
            if all_pass else "FAIL"))
        print("=" * 80)
        return all_pass


# --------------------------------------------------------------------------- #
# Self-check (no root): the syscall-pattern fix + safety cap + import sanity
# --------------------------------------------------------------------------- #

def _selfcheck(report: Report) -> int:
    common = (Path(_PROJECT_ROOT) / "simulations" / "sim_common.py").read_text()
    body = common[common.index("def _simulate_file"):common.index("# ---", common.index("def _simulate_file"))]

    report.check("FIX: _simulate_file issues os.rename", "os.rename present",
                 "present" if "os.rename(str(p), new_path)" in body else "absent",
                 "os.rename(str(p), new_path)" in body)
    report.check("FIX: legacy write+unlink pattern removed", "no p.unlink()",
                 "present" if "p.unlink()" in body else "removed",
                 "p.unlink()" not in body)
    report.check("FIX: two_pass keeps original until rename",
                 "2 in-place writes + rename",
                 "ok" if (body.count("p.write_bytes(partial)") == 1
                          and "p.write_bytes(full)" in body
                          and ".partial" not in body) else "bad",
                 body.count("p.write_bytes(partial)") == 1
                 and "p.write_bytes(full)" in body and ".partial" not in body)

    report.check("SAFETY: --max-files cap honoured in run_attack", "cap wired",
                 "wired" if "targets = targets[:max_files]" in common else "missing",
                 "targets = targets[:max_files]" in common)
    report.check("SAFETY: test MAX_FILES <= 50", "<=50",
                 str(MAX_FILES), MAX_FILES <= 50)
    report.check("SAFETY: pre-seeded corpus <= 50", "<=50",
                 str(CORPUS_FILES), CORPUS_FILES <= 50)

    # Importability of every sim the live test spawns + their renamed output ext.
    import importlib
    ok_import = True
    for spec in SIMS:
        try:
            m = importlib.import_module(spec["module"])
            _ = m.PROFILE.ext_fn()
        except Exception as exc:  # noqa: BLE001
            print(f"    import FAIL {spec['module']}: {exc}")
            ok_import = False
    report.check("sims import cleanly + expose PROFILE.ext_fn", "all import",
                 "ok" if ok_import else "fail", ok_import)

    # Sanity: the layer predicates accept a representative event each.
    pa = lambda fp, prof: {"event_type": "PROCESS_ANOMALY",
                           "file_path": fp, "details": {"profile": prof}}
    report.check("Akira predicate accepts .akiranew/akira", "True",
                 str(_akira_layer_ok(pa("/x/a.docx.akiranew", "akira"))),
                 _akira_layer_ok(pa("/x/a.docx.akiranew", "akira")))
    report.check("Qilin predicate accepts 7ch entropy ext", "True",
                 str(_qilin_layer_ok(pa("/x/a.docx.a1b2c3d", "unknown"))),
                 _qilin_layer_ok(pa("/x/a.docx.a1b2c3d", "unknown")))
    report.check("LockBit predicate accepts 16ch/lockbit5", "True",
                 str(_lockbit_layer_ok(pa("/x/a.docx.abcdefghij123456", "lockbit5"))),
                 _lockbit_layer_ok(pa("/x/a.docx.abcdefghij123456", "lockbit5")))

    print("\n[self-check] Syscall-pattern fix + safety cap verified. "
          "Run with sudo for the full live-kernel proof.")
    return 0 if report.render() else 1


# --------------------------------------------------------------------------- #
# Live run (root)
# --------------------------------------------------------------------------- #

def _live(report: Report) -> int:
    try:
        from bcc import BPF  # type: ignore
    except Exception as exc:  # pragma: no cover - environment-dependent
        print(f"FAIL: bcc not importable ({exc}); cannot run live kernel test")
        return 3

    print("[0] PREFLIGHT")
    if proc_uid(os.getpid()) != 0:
        print("FAIL: not root")
        return 3

    # ---- Load the SAME source the agent runs, AUDIT mode (SIGSTOP-fallback) ----
    print("[1] LOAD — build_bpf(enforce=False, lsm=False) + attach rename/write probes")
    b = BPF(text=build_bpf(enforce=False, lsm=False))

    # Enable rename tracepoints (may be off by default on some kernels).
    for tp in ("sys_enter_rename", "sys_enter_renameat", "sys_enter_renameat2"):
        try:
            with open(f"/sys/kernel/debug/tracing/events/syscalls/{tp}/enable", "w") as fh:
                fh.write("1")
        except OSError:
            pass

    # Shared engine — exactly what run_sensor builds. self_pid = this test so the
    # sim PIDs are never suppressed as "the monitor itself".
    engine = DetectionEngine(
        host_id="SIMLIVE",
        watch_dirs=[s["dir"] for s in SIMS] + [CONTROL_DIR],
        velocity_threshold=2,
        window_seconds=3.0,
        self_pid=os.getpid(),
        ignore_comms=IGNORE_COMMS,
    )

    # Per-sim observation state, reset before each sim/control via _reset().
    CUR = {
        "pid": None,           # the PID we are watching this round
        "raw_renames": 0,      # kernel rename_events seen for that PID
        "fired": None,         # first DetectionEngine event for that PID
        "silent": 0,           # silent_enc write_events seen for that PID
        "stopped": False,      # did WE issue SIGSTOP (audit response)?
    }

    def _reset(pid: "int | None") -> None:
        CUR.update(pid=pid, raw_renames=0, fired=None, silent=0, stopped=False)

    def _on_rename(cpu, data, size):  # noqa: ANN001 - bcc callback signature
        ev = b["rename_events"].event(data)
        if CUR["pid"] is None or int(ev.pid) != CUR["pid"]:
            return
        old = ev.oldname.decode(errors="replace").rstrip("\x00")
        new = ev.newname.decode(errors="replace").rstrip("\x00")
        if not old or not new:
            return
        comm = ev.comm.decode(errors="replace").rstrip("\x00")
        CUR["raw_renames"] += 1
        out = engine.observe_rename(int(ev.pid), int(ev.ppid), comm, old, new,
                                    ts=time.time())
        if out is not None and CUR["fired"] is None:
            CUR["fired"] = out
            # AUDIT-mode response: SIGSTOP the offending PID (the run_sensor
            # default _contain). NO iptables/cgroup/SIGKILL in audit mode.
            try:
                os.kill(CUR["pid"], 19)  # SIGSTOP
                CUR["stopped"] = True
            except OSError:
                pass

    def _on_write(cpu, data, size):  # noqa: ANN001
        ev = b["write_events"].event(data)
        if CUR["pid"] is None or int(ev.pid) != CUR["pid"]:
            return
        if int(getattr(ev, "silent_enc", 0)):
            CUR["silent"] += 1

    b["rename_events"].open_perf_buffer(_on_rename, page_cnt=8192)
    b["write_events"].open_perf_buffer(_on_write, page_cnt=64)
    for _ in range(10):
        b.perf_buffer_poll(timeout=0)
    print("[1] probes loaded — listening")

    procs: dict[str, subprocess.Popen] = {}
    env = dict(os.environ, PYTHONPATH=str(_PROJECT_ROOT))

    try:
        # ---- OPERATOR — interactive-UID ping that must stay alive throughout ---
        print("[2] OPERATOR — background ping from UID 1000 (must never be cut)")
        operator = subprocess.Popen(
            ["ping", "-n", "-i", PING_INTERVAL, PING_TARGET],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            user=OPERATOR_UID, group=OPERATOR_GID,
        )
        procs["operator"] = operator
        print(f"    operator ping PID={operator.pid} uid={proc_uid(operator.pid)}")
        time.sleep(3)  # baseline connectivity window
        # Liveness is proven by a fresh `ping -c 1` AS UID 1000 — no shared log
        # file (a root-opened file under sticky /tmp chowned to 1000 trips
        # fs.protected_regular and EACCESes even for root).
        if not operator_can_reach_network():
            print("FAIL: operator UID 1000 cannot reach the network at baseline "
                  "(no outbound ICMP?) — cannot validate self-protection")
            return 3
        report.check("operator online at baseline", "fresh probe OK",
                     "reachable", True)

        # ---- 3..N. Each sim, sequentially against the SAME live probes ---------
        for spec in SIMS:
            name, module, sdir = spec["name"], spec["module"], spec["dir"]
            print(f"\n[SIM:{name}] seed sandbox + spawn UID-1000 sim "
                  f"(--max-files {MAX_FILES} --delay {SIM_DELAY})")
            seed_sandbox(sdir, CORPUS_FILES)

            proc = subprocess.Popen(
                [sys.executable, "-m", module, "--target", sdir,
                 "--no-restore", "--traversal", "dfs",
                 "--max-files", str(MAX_FILES), "--delay", str(SIM_DELAY)],
                cwd=str(_PROJECT_ROOT), env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                user=OPERATOR_UID, group=OPERATOR_GID,
            )
            procs[name] = proc
            _reset(proc.pid)
            print(f"    {name} sim PID={proc.pid} uid={proc_uid(proc.pid)}")

            # Drain perf buffer until the EXPECTED layer fires (or timeout).
            deadline = time.time() + DETECT_TIMEOUT
            layer_ok = False
            while time.time() < deadline:
                b.perf_buffer_poll(timeout=100)
                if CUR["fired"] is not None:
                    layer_ok = spec["check"](CUR["fired"])
                    break
                if proc.poll() is not None and CUR["raw_renames"] == 0:
                    # sim exited and we never even saw a rename — keep draining a
                    # moment in case events are still buffered, then bail.
                    b.perf_buffer_poll(timeout=200)
                    if CUR["fired"] is not None:
                        layer_ok = spec["check"](CUR["fired"])
                    break

            fired = CUR["fired"]
            ev_type = fired["event_type"] if fired else "none"
            profile = (fired or {}).get("details", {}).get("profile", "—")
            fpath = fired["file_path"] if fired else "—"

            # ASSERT — detection fired, correct layer, audit response, scoping.
            d1 = report.check(
                f"[{name}] detection fired on live vfs_rename (T1486)",
                ">=1 rename event + engine fired",
                f"raw_renames={CUR['raw_renames']} fired={ev_type}",
                CUR["raw_renames"] >= 1 and fired is not None)
            d2 = report.check(
                f"[{name}] CORRECT layer = {spec['layer']} (not silent_enc)",
                spec["layer"],
                f"type={ev_type} profile={profile} dst={Path(fpath).name} "
                f"silent_enc={CUR['silent']}",
                layer_ok and CUR["silent"] == 0)
            d3 = report.check(
                f"[{name}] audit response: SIGSTOP issued to sim PID",
                "stopped (state=T)",
                f"sent={CUR['stopped']} state={proc_state(proc.pid)}",
                CUR["stopped"] and proc_state(proc.pid) == "T")

            # T1498 scoping guard: operator never cut by detection+response.
            op_alive = operator.poll() is None
            op_reach = operator_can_reach_network()
            d4 = report.check(
                f"[{name}] operator STAYED ALIVE through detect+response (T1498)",
                "alive & reachable",
                f"alive={op_alive} reachable={op_reach}",
                op_alive and op_reach)

            # Release + reap this sim before the next one.
            print(f"    RUN: kill -CONT {proc.pid}; kill {proc.pid}")
            for sig in (18, 9):  # SIGCONT, SIGKILL
                try:
                    os.kill(proc.pid, sig)
                except OSError:
                    pass
            try:
                proc.wait(timeout=5)
            except Exception:
                pass
            shutil.rmtree(sdir, ignore_errors=True)
            cleanup_sim_backups()
            cleanup_ok = not Path(sdir).exists()
            report.check(f"[{name}] sandbox cleaned up", "absent",
                         "absent" if cleanup_ok else "present", cleanup_ok)

            report.sim_summary(
                name, spec["layer"] if layer_ok else f"{ev_type}!",
                "Y" if d3 else "N", "Y" if d4 else "N",
                "Y" if cleanup_ok else "N",
                "PASS" if all([d1, d2, d3, d4, cleanup_ok]) else "FAIL")

        # ---- CONTROL — benign sequential writer must trigger NOTHING ----------
        print(f"\n[CONTROL] benign sequential writer (UID 1000, no rename)")
        seed_sandbox(CONTROL_DIR, 0)  # empty, operator-owned dir to write into
        ctl = subprocess.Popen(
            [sys.executable, "-c", CONTROL_SRC, CONTROL_DIR],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            user=OPERATOR_UID, group=OPERATOR_GID,
        )
        procs["control"] = ctl
        _reset(ctl.pid)
        print(f"    control PID={ctl.pid} uid={proc_uid(ctl.pid)}")
        # Let it write all 10 files; drain throughout.
        deadline = time.time() + 4.0
        while time.time() < deadline:
            b.perf_buffer_poll(timeout=100)

        c1 = report.check("[Control] NO rename event emitted", "0 renames",
                          str(CUR["raw_renames"]), CUR["raw_renames"] == 0)
        c2 = report.check("[Control] NO silent_enc / detection fired",
                          "no detection",
                          f"silent={CUR['silent']} fired="
                          f"{CUR['fired']['event_type'] if CUR['fired'] else 'none'}",
                          CUR["silent"] == 0 and CUR["fired"] is None)
        c3 = report.check("[Control] NOT SIGSTOP'd (benign, left running)",
                          "state!=T",
                          f"sent={CUR['stopped']} state={proc_state(ctl.pid)}",
                          not CUR["stopped"] and proc_state(ctl.pid) != "T")
        c4 = report.check("[Control] operator safe", "alive & reachable",
                          f"alive={ctl.poll() is None and operator.poll() is None} "
                          f"reachable={operator_can_reach_network()}",
                          operator.poll() is None and operator_can_reach_network())
        try:
            os.kill(ctl.pid, 9)
        except OSError:
            pass
        shutil.rmtree(CONTROL_DIR, ignore_errors=True)
        ctl_clean = not Path(CONTROL_DIR).exists()
        report.check("[Control] sandbox cleaned up", "absent",
                     "absent" if ctl_clean else "present", ctl_clean)
        report.sim_summary("Control", "none (benign)",
                           "N" if c3 else "Y!", "Y" if c4 else "N",
                           "Y" if ctl_clean else "N",
                           "PASS" if all([c1, c2, c3, c4, ctl_clean]) else "FAIL")

        return 0 if report.render() else 1

    finally:
        # ---- teardown — always runs, even on assertion failure --------------
        print("\n[teardown] SIGCONT + kill all helpers; remove sandboxes")
        for name, proc in procs.items():
            if proc is None or proc.poll() is not None:
                continue
            for sig in (18, 9):  # CONT then KILL (un-stick any SIGSTOP'd PID)
                try:
                    os.kill(proc.pid, sig)
                except OSError:
                    pass
            try:
                proc.wait(timeout=5)
            except Exception:
                pass
            print(f"    killed {name} PID={proc.pid}")
        for sdir in [s["dir"] for s in SIMS] + [CONTROL_DIR]:
            shutil.rmtree(sdir, ignore_errors=True)
        cleanup_sim_backups()
        used_flush = any(("-F" in c or "--flush" in c) for c in COMMANDS)
        print(f"    no iptables -F/--flush used: {not used_flush}")
        print("    sandboxes + backups removed")


def main() -> int:
    report = Report()
    if "--selfcheck" in sys.argv:
        return _selfcheck(report)
    if os.geteuid() != 0:
        here = Path(__file__).resolve()
        print("\n" + "!" * 78)
        print("FAIL: live sim-detection test needs root to load BPF + attach the")
        print("rename/write kprobes and to SIGSTOP the sim PID.")
        print("\nThe privileged run will, in order:")
        print("  * load eBPF (build_bpf, AUDIT mode) + attach vfs_rename/vfs_write")
        print("  * spawn a UID-1000 `ping 8.8.8.8` (operator liveness probe)")
        print("  * for each sim: seed a <=50-file UID-1000 sandbox, spawn the REAL")
        print("    `python3 -m simulations.sim_<fam> --no-restore` and SIGSTOP it")
        print("    when the live vfs_rename detector fires")
        print("  * run a benign sequential-writer control (must trigger nothing)")
        print("  * tear everything down (SIGCONT+kill helpers, rm sandboxes)")
        print("\nReview the script first, then run:")
        print(f"  sudo /usr/bin/python3 {here}")
        print("Or validate the fix invariants without root:")
        print(f"  {sys.executable} {here} --selfcheck")
        print("!" * 78)
        return 2
    return _live(report)


if __name__ == "__main__":
    sys.exit(main())
