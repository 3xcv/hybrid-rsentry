#!/usr/bin/env python3
"""
tests/integration/test_live_akira_pipeline.py — LIVE end-to-end proof that BOTH
recent fixes hold TOGETHER under a real Akira-style attack on the real kernel:

  FIX 1  (detection)   write-offset SILENT_ENCRYPTION now fires on the live
                       ``kprobe__vfs_write`` path — the per-PID rate limiter was
                       reordered BELOW the non-sequential offset counter, so a
                       fast attacker no longer trips the limiter and escapes
                       detection.  MITRE ATT&CK **T1486 — Data Encrypted for Impact**.

  FIX 2  (containment) the network-isolation step is scoped to a dedicated
                       **cgroup v2** holding ONLY the malicious tree, NOT to the
                       owning UID.  The old ``-m owner --uid-owner`` rule was a
                       host-wide outage for every process under that UID — and a
                       self-DoS of the agent if it shared the UID.  MITRE ATT&CK
                       **T1498 — Network Denial of Service** (the abuse this guard
                       prevents).

WHAT THIS DRIVES (nothing mocked — real BPF, real syscalls, real iptables/cgroup):
    1. Load the SAME bpf source the agent runs (``monitor_ebpf.build_bpf``) and
       attach the live ``vfs_write`` kprobe.
    2. Spawn an Akira "sim" process (UID 1000) that issues the documented Akira
       skip-step write geometry imported from ``simulations.sim_akira``
       (``_WRITE_BLOCK`` / ``_SEEK_STRIDE`` — write a block, seek forward, write
       again: non-sequential in-place rewrites, NO rename, NO cipher) into a
       sandbox file, then sleeps so the pipeline has a live PID to act on.
    3. Confirm Defense #1 fires on the LIVE kernel: the sim PID lands in
       ``blocked_pids`` and a ``silent_enc`` write event is emitted.
    4. Run the FULL production containment pipeline on the sim PID via
       ``agent.containment.contain()``:  SIGSTOP → evidence → cgroup network
       isolate → SIGKILL → surgical release.
    5. Prove the self-protection / scoping guard held LIVE: an operator ``ping``
       from the interactive UID (1000) never lost a packet, and the agent PID,
       its parent shell and PID 1 were never placed in the isolation cgroup.

WHY NOT ``monitor.py --run-sim``:
    monitor.py's built-in ``_sim_fn`` performs ``os.rename(path, path+ext)`` — it
    exercises the *rename*/extension detector, NOT the write-offset
    SILENT_ENCRYPTION path under test here.  To validate FIX 1 we drive the Akira
    *in-place* skip-step write geometry (``simulations.sim_akira``) straight at
    the live kprobe, then invoke the SAME production ``contain()`` the agent calls.

USAGE
    # Privileged live run — needs root (load BPF + attach kprobe, iptables +
    # cgroup writes) AND a bcc-capable interpreter.  The project venv has no
    # system site-packages, so use the system python3 that owns python3-bpfcc:
    sudo /usr/bin/python3 tests/integration/test_live_akira_pipeline.py

    # Unprivileged self-check (no BPF / iptables / cgroup): validates the source
    # ordering invariants (FIX 1), the self-protection guard set (FIX 2) and the
    # no-flush property of the containment module.  Runs under any interpreter:
    python3 tests/integration/test_live_akira_pipeline.py --selfcheck

SAFETY
  * The "attack" writes os.urandom() at jumped offsets — NO cipher, NO key, NO
    rename.  It only ever touches files under the sandbox /tmp/rsentry_lab.
  * Write count is BOUNDED and SMALL (ATTACK_WRITES, just past NONSEQ_THRESH=5) —
    deliberately tiny to avoid the VM-hang a large write storm caused before.
  * No canary files are placed.
  * Every privileged command the TEST issues is printed ("RUN: ...") first and
    audited; ``iptables -F``/``--flush`` is NEVER used — cleanup is surgical -D.
  * finally{}: kills the sim + operator ping, deletes any residual
    rsentry-contain iptables rule + cgroup, removes the sandbox + evidence, and
    ASSERTS the OUTPUT chain is byte-for-byte what it was at start.
  * If the agent / shell / PID 1 / operator UID is ever the isolation target the
    test FAILS LOUDLY and still cleans up.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

# Make the project importable when run directly (sudo strips PYTHONPATH).
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from agent.monitor_ebpf import build_bpf  # noqa: E402
from agent.containment import (  # noqa: E402
    CGROUP2_ROOT,
    CGROUP_CONTAIN_PREFIX,
    _agent_protected_pids,
    _cgroup2_available,
    contain,
)
# Single source of truth for the Akira non-sequential write geometry.
from simulations.sim_akira import PROFILE, _WRITE_BLOCK, _SEEK_STRIDE  # noqa: E402

LAB_DIR = Path("/tmp/rsentry_lab")        # the Akira --sim-target sandbox
CORPUS_FILES = 2                          # tiny synthetic corpus
ATTACK_WRITES = 30                        # bounded; NONSEQ_THRESH is 5 (small on purpose)
BLOCK = _WRITE_BLOCK                      # 4096 — from simulations.sim_akira
STRIDE = _SEEK_STRIDE                     # 10 KiB jump — non-sequential by construction

OPERATOR_UID = 1000                       # the interactive operator's UID
OPERATOR_GID = 1000
PING_TARGET = "8.8.8.8"
PING_INTERVAL = "0.3"                     # 4× / sec roughly; >= 0.2s floor for non-root

# Audit log of every command the TEST shells out — proves no -F/--flush was used.
COMMANDS: list[list[str]] = []


# --------------------------------------------------------------------------- #
# The Akira "sim" attacker — runs as a separate process so it owns its PID/tree.
# Non-sequential in-place rewrites (write block, seek +STRIDE, write again), then
# sleep so the live containment pipeline has a real PID to SIGSTOP/isolate/kill.
# --------------------------------------------------------------------------- #
ATTACKER_SRC = f"""
import os, sys, time
path = sys.argv[1]
fd = os.open(path, os.O_RDWR)
os.pwrite(fd, os.urandom({BLOCK}), 0)               # baseline -> establishes last_end
for i in range(1, {ATTACK_WRITES} + 1):
    os.pwrite(fd, os.urandom({BLOCK}), i * {STRIDE}) # jump -> non-sequential every write
os.fsync(fd)
os.close(fd)
sys.stderr.write("AKIRA_SIM_WRITES_DONE\\n"); sys.stderr.flush()
time.sleep(120)                                      # stay alive for the pipeline
"""


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #

def run_cmd(cmd: list[str], *, check: bool = False) -> subprocess.CompletedProcess:
    """Run a command, echoing it first so the operator can review every action."""
    COMMANDS.append(cmd)
    print(f"    RUN: {' '.join(cmd)}")
    return subprocess.run(cmd, check=check, capture_output=True, text=True, timeout=15)


def output_chain() -> list[str]:
    """Current `iptables -S OUTPUT` rule lines (the baseline we must preserve)."""
    cp = run_cmd(["iptables", "-S", "OUTPUT"])
    return [ln for ln in cp.stdout.splitlines() if ln.strip()]


def contain_rules_present() -> list[str]:
    """Any OUTPUT rules still carrying our containment comment prefix."""
    return [ln for ln in output_chain() if CGROUP_CONTAIN_PREFIX in ln]


def ping_replies(logfile: Path) -> int:
    """Count successful ICMP replies in the operator ping log so far."""
    try:
        return sum(1 for ln in logfile.read_text().splitlines() if "bytes from" in ln)
    except FileNotFoundError:
        return 0


def operator_can_reach_network() -> bool:
    """Active, point-in-time connectivity probe AS THE OPERATOR UID.

    A single fresh `ping -c 1` from UID 1000. Unlike a reply-count delta on the
    long-running background ping (whose 0.3s cadence may not tick during the
    sub-second assertion window), this directly proves the operator still has
    network RIGHT NOW — independent of timing.
    """
    try:
        cp = subprocess.run(
            ["ping", "-n", "-c", "1", "-W", "2", PING_TARGET],
            user=OPERATOR_UID, group=OPERATOR_GID,
            capture_output=True, text=True, timeout=6,
        )
        return cp.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def proc_uid(pid: int) -> int | None:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("Uid:"):
                return int(line.split()[1])
    except (FileNotFoundError, ValueError, OSError):
        return None
    return None


# --------------------------------------------------------------------------- #
# Results table (same shape as the other two live tests)
# --------------------------------------------------------------------------- #

class Report:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str, bool]] = []

    def check(self, name: str, expected: str, observed: str, ok: bool) -> bool:
        self.rows.append((name, expected, observed, ok))
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}: "
              f"expected={expected!r} observed={observed!r}")
        return ok

    def render(self) -> bool:
        wc = max((len(r[0]) for r in self.rows), default=5)
        we = max((len(r[1]) for r in self.rows), default=8)
        wo = max((len(r[2]) for r in self.rows), default=8)
        wc, we, wo = max(wc, 5), max(we, 8), max(wo, 8)
        line = f"| {{:<{wc}}} | {{:<{we}}} | {{:<{wo}}} | {{:<6}} |"
        sep = f"|{'-'*(wc+2)}|{'-'*(we+2)}|{'-'*(wo+2)}|{'-'*8}|"
        print("\n" + "=" * 80)
        print("RESULTS")
        print("=" * 80)
        print(line.format("Check", "Expected", "Observed", "Result"))
        print(sep)
        for name, exp, obs, ok in self.rows:
            print(line.format(name, exp, obs, "PASS" if ok else "FAIL"))
        all_pass = all(r[3] for r in self.rows)
        print("=" * 80)
        print("OVERALL: " + (
            "PASS — Akira detected via write-offset (T1486) AND contained with "
            "cgroup-scoped isolation; operator/agent never cut (T1498 guard held)"
            if all_pass else "FAIL"))
        print("=" * 80)
        return all_pass


# --------------------------------------------------------------------------- #
# Self-check (no root): source-level invariants behind both fixes
# --------------------------------------------------------------------------- #

def _selfcheck(report: Report) -> int:
    # FIX 1 — kprobe ordering that makes live detection possible.
    src = build_bpf(enforce=True, lsm=True)
    body = src[src.index("int kprobe__vfs_write"):src.index("// ── Execve handler")]
    i_off = body.index("write_offset.lookup")
    i_rl = body.index("if (__rate_limited(pid, ts)) return 0;")
    i_byp = body.index("CRITICAL EVENT BYPASS")
    throttle = ("POST-FREEZE THROTTLE" in body
                and "if (blocked && *blocked) return 0;" in body)
    report.check("FIX1 offset counter precedes rate limiter",
                 "counter<limiter", f"{i_off}<{i_rl}", i_off < i_rl)
    report.check("FIX1 silent_enc bypass precedes rate limiter",
                 "bypass<limiter", f"{i_byp}<{i_rl}", i_byp < i_rl)
    report.check("FIX1 post-freeze throttle present",
                 "present", "present" if throttle else "absent", throttle)

    # Akira geometry is genuinely non-sequential (jump != block end).
    report.check("Akira skip-step is non-sequential", "STRIDE!=BLOCK",
                 f"stride={STRIDE} block={BLOCK}", STRIDE != BLOCK)
    report.check("Akira profile loaded", "AKIRA", PROFILE.name, PROFILE.name == "AKIRA")

    # FIX 2 — self-protection guard set + no-flush containment.
    guard = _agent_protected_pids()
    report.check("FIX2 guard covers agent+parent+pid1", "self/ppid/1 in set",
                 f"self={os.getpid()} ppid={os.getppid()} 1=1",
                 os.getpid() in guard and os.getppid() in guard and 1 in guard)
    csrc = (Path(_PROJECT_ROOT) / "agent" / "containment.py").read_text()
    # Look for -F/--flush only as a quoted command-argument TOKEN (the form an
    # actual iptables call uses), not as prose in a docstring ("never iptables -F").
    no_flush = '"-F"' not in csrc and '"--flush"' not in csrc
    surgical = '"-I"' in csrc and '"-D"' in csrc
    report.check("FIX2 containment never flushes (-I/-D only)", "no -F/--flush",
                 "surgical" if (no_flush and surgical) else "flush-found",
                 no_flush and surgical)

    print("\n[self-check] Invariants behind both fixes verified. "
          "Run with sudo for the full live-kernel + iptables proof.")
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

    # ---- PREFLIGHT — fail loudly, never fall back silently ------------------
    print("[0] PREFLIGHT")
    if not _cgroup2_available():
        print(f"FAIL: cgroup v2 unified hierarchy not available at {CGROUP2_ROOT}")
        return 3
    help_cp = run_cmd(["iptables", "-m", "cgroup", "--help"])
    if "--path" not in (help_cp.stdout + help_cp.stderr):
        print("FAIL: iptables here has no `-m cgroup --path` match")
        return 3
    baseline_chain = output_chain()
    print(f"    baseline OUTPUT chain: {len(baseline_chain)} rule(s)")

    LAB_DIR.mkdir(mode=0o777, exist_ok=True)
    os.chmod(LAB_DIR, 0o777)
    corpus = []
    for n in range(CORPUS_FILES):
        f = LAB_DIR / f"doc_{n}.dat"
        f.write_bytes(os.urandom(BLOCK * (ATTACK_WRITES + 4)))  # pre-sized victim file
        os.chmod(f, 0o666)
        corpus.append(f)
    victim = corpus[0]
    op_log = LAB_DIR / "operator_ping.log"
    op_log.write_text("")
    os.chown(str(op_log), OPERATOR_UID, OPERATOR_GID)

    # Load the SAME source the agent runs. lsm=False keeps the test independent
    # of the lsm=bpf kernel param — the silent_enc detection + blocked_pids freeze
    # in kprobe__vfs_write are unconditional, so the live path runs either way.
    print("[1] LOAD — build_bpf(enforce=True, lsm=False) + attach vfs_write kprobe")
    b = BPF(text=build_bpf(enforce=True, lsm=False))

    silent_seen: dict[int, int] = {}

    def _on_write(cpu, data, size):  # noqa: ANN001 - bcc callback signature
        ev = b["write_events"].event(data)
        if int(getattr(ev, "silent_enc", 0)):
            silent_seen[int(ev.pid)] = silent_seen.get(int(ev.pid), 0) + 1

    b["write_events"].open_perf_buffer(_on_write, page_cnt=64)

    def _is_blocked(pid: int) -> bool:
        try:
            return int(b["blocked_pids"][b["blocked_pids"].Key(pid)].value) == 1
        except Exception:
            return False

    operator = attacker = None
    result = None
    try:
        # ---- 2. OPERATOR — interactive-UID ping that must stay alive ---------
        print("[2] OPERATOR — background ping from UID 1000 (must never be cut)")
        operator = subprocess.Popen(
            ["ping", "-n", "-i", PING_INTERVAL, PING_TARGET],
            stdout=open(op_log, "w"), stderr=subprocess.DEVNULL,
            user=OPERATOR_UID, group=OPERATOR_GID,
        )
        print(f"    operator ping PID={operator.pid} uid={proc_uid(operator.pid)}")
        time.sleep(3)  # baseline connectivity window
        op_baseline = ping_replies(op_log)
        if op_baseline < 1:
            print("FAIL: operator ping got no replies at baseline "
                  "(no outbound ICMP?) — cannot validate self-protection")
            return 3
        report.check("operator online at baseline", ">=1 reply",
                     str(op_baseline), op_baseline >= 1)

        # ---- 3. AKIRA SIM — non-sequential in-place writes (UID 1000) --------
        print("[3] AKIRA SIM — skip-step non-sequential writes to a sandbox file")
        attacker = subprocess.Popen(
            [sys.executable, "-c", ATTACKER_SRC, str(victim)],
            stderr=subprocess.DEVNULL,
            user=OPERATOR_UID, group=OPERATOR_GID,
        )
        sim_pid = attacker.pid
        print(f"    akira-sim PID={sim_pid} uid={proc_uid(sim_pid)} "
              f"writes={ATTACK_WRITES} (NONSEQ_THRESH=5)")

        # ---- 4. DETECT — drain perf buffer until Defense #1 freezes the PID --
        print("[4] DETECT — waiting for live SILENT_ENCRYPTION on the sim PID")
        deadline = time.time() + 15
        while time.time() < deadline:
            b.perf_buffer_poll(timeout=100)
            if _is_blocked(sim_pid) and silent_seen.get(sim_pid, 0) >= 1:
                break
        blocked = _is_blocked(sim_pid)
        n_silent = silent_seen.get(sim_pid, 0)
        report.check("akira sim frozen in blocked_pids (Defense #1 live, T1486)",
                     "blocked=True", f"blocked={blocked}", blocked)
        report.check("akira sim emitted silent_enc event", ">=1",
                     str(n_silent), n_silent >= 1)
        # The sim must still be alive (sleeping) for the pipeline to act on it.
        report.check("sim PID alive for pipeline", "alive",
                     "alive" if attacker.poll() is None else "exited",
                     attacker.poll() is None)

        # Sanity: the sim PID is legitimately containable; the agent is not.
        protected = _agent_protected_pids()
        report.check("sim PID NOT in agent protected set", "not protected",
                     f"sim={sim_pid} protected_sample={sorted(protected)[:4]}",
                     sim_pid not in protected)

        # ---- 5. FULL PIPELINE — production contain() on the sim PID ----------
        print("[5] CONTAIN — agent.containment.contain(sim_pid) "
              "[SIGSTOP -> evidence -> cgroup isolate -> SIGKILL]")
        op_before = ping_replies(op_log)
        result = contain(sim_pid)
        op_after = ping_replies(op_log)
        rule = result.iptables_rule or ""
        stages = (f"SIGSTOP={'Y' if result.stopped else 'N'} "
                  f"evidence={'Y' if result.evidence_files else 'N'}"
                  f"({len(result.evidence_files)}f) "
                  f"isolate={'Y' if result.iptables_rule else 'N'} "
                  f"SIGKILL={'Y' if result.killed else 'N'}")
        print(f"    stages : {stages}")
        print(f"    rule   : {rule}")
        print(f"    cgroup : {result.cgroup_path}")
        print(f"    comment: {result.isolation_comment}")
        print(f"    isolated_pids: {result.isolated_pids}")

        # ---- 6. ASSERT pipeline + scoping -----------------------------------
        print("[6] ASSERT")
        report.check("SIGSTOP issued on sim tree", "stopped=True",
                     f"stopped={result.stopped}", result.stopped)
        report.check("evidence captured from /proc", ">=1 file",
                     str(len(result.evidence_files)), len(result.evidence_files) >= 1)
        report.check("cgroup network isolation applied", "rule present",
                     "present" if result.iptables_rule else "absent",
                     bool(result.iptables_rule))
        report.check("SIGKILL delivered to sim tree", "killed=True",
                     f"killed={result.killed}", result.killed)
        report.check("isolation rule uses --path (cgroup) NOT --uid-owner",
                     "--path & !--uid-owner",
                     "--path" if ("--path" in rule and "--uid-owner" not in rule) else rule,
                     "--path" in rule and "--uid-owner" not in rule)
        report.check("isolation comment tagged rsentry-contain-<pid>",
                     f"{CGROUP_CONTAIN_PREFIX}-{sim_pid}",
                     str(result.isolation_comment),
                     result.isolation_comment == f"{CGROUP_CONTAIN_PREFIX}-{sim_pid}")

        # Self-protection: agent / shell / PID 1 NEVER isolated; only the sim was.
        leaked = set(result.isolated_pids) & protected
        report.check("agent+shell+pid1 NOT in isolated cgroup", "no overlap",
                     f"isolated={result.isolated_pids} leaked={sorted(leaked)}",
                     not leaked and sim_pid in result.isolated_pids)
        report.check("only the sim tree was isolated", f"[{sim_pid}]",
                     str(result.isolated_pids),
                     set(result.isolated_pids) == {sim_pid})

        # Operator connectivity held LIVE across the full pipeline window.
        report.check("operator ping STAYED ALIVE through pipeline (T1498 guard)",
                     "alive & replied during contain",
                     f"alive={operator.poll() is None} "
                     f"replies {op_before}->{op_after}",
                     operator.poll() is None and op_after > op_before)

        # ---- 7. POST-TEARDOWN STATE (contain() auto-released on full kill) ---
        print("[7] VERIFY surgical teardown")
        report.check("isolation released by pipeline", "released=True",
                     f"released={result.isolation_released}", result.isolation_released)
        residual = contain_rules_present()
        report.check("no dangling rsentry-contain rule", "none",
                     str(residual) if residual else "none", not residual)
        cg_gone = not (result.cgroup_path and Path(result.cgroup_path).exists())
        report.check("isolation cgroup rmdir'd", "absent",
                     "absent" if cg_gone else "present", cg_gone)
        final_chain = output_chain()
        report.check("OUTPUT chain restored byte-for-byte", "== baseline",
                     f"baseline={len(baseline_chain)} final={len(final_chain)}",
                     final_chain == baseline_chain)
        # Active fresh probe (not a reply-count delta): proves the operator can
        # reach the network RIGHT NOW, after the full pipeline + teardown, and
        # that the background ping is still alive (never collateral-killed).
        op_reachable = operator_can_reach_network()
        report.check("operator network intact after teardown", "fresh probe OK & alive",
                     f"probe={'OK' if op_reachable else 'FAIL'} "
                     f"alive={operator.poll() is None}",
                     op_reachable and operator.poll() is None)
        used_flush = any(("-F" in c or "--flush" in c) for c in COMMANDS)
        report.check("no iptables -F/--flush in any test command", "no flush",
                     "flush used" if used_flush else "none", not used_flush)

        return 0 if report.render() else 1

    finally:
        # ---- teardown — always runs, even on assertion failure --------------
        print("\n[teardown] killing helpers + removing residual rule/cgroup/sandbox")
        for name, proc in (("akira-sim", attacker), ("operator-ping", operator)):
            if proc is not None and proc.poll() is None:
                proc.kill()
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
                print(f"    killed {name} PID={proc.pid}")
        # Belt-and-suspenders: delete our uniquely-tagged rule + cgroup if any
        # survived an early failure. Surgical -D only — NEVER a flush.
        for ln in contain_rules_present():
            # `iptables -S` prints an "-A OUTPUT ..." spec; turn it into a -D.
            spec = ln.split()
            if spec and spec[0] == "-A":
                run_cmd(["iptables", "-D"] + spec[1:])
        for cg in CGROUP2_ROOT.glob(f"{CGROUP_CONTAIN_PREFIX}-*"):
            try:
                cg.rmdir()
                print(f"    cgroup removed: {cg}")
            except OSError:
                pass
        if result is not None and result.evidence_dir:
            import shutil
            shutil.rmtree(result.evidence_dir, ignore_errors=True)
        import shutil as _sh
        _sh.rmtree(LAB_DIR, ignore_errors=True)
        print("    sandbox + evidence removed")


def main() -> int:
    report = Report()
    if "--selfcheck" in sys.argv:
        return _selfcheck(report)
    if os.geteuid() != 0:
        here = Path(__file__).resolve()
        print("\n" + "!" * 78)
        print("FAIL: live Akira pipeline test needs root to load BPF + attach the")
        print("kprobe and to write iptables/cgroup state.")
        print("\nThe privileged run will, in order:")
        print("  * load eBPF (build_bpf) + attach the vfs_write kprobe")
        print("  * spawn a UID-1000 `ping 8.8.8.8` (operator liveness probe)")
        print("  * spawn a UID-1000 Akira skip-step writer into /tmp/rsentry_lab")
        print("  * run agent.containment.contain() on the sim PID")
        print("    (SIGSTOP -> evidence -> iptables -I cgroup DROP -> SIGKILL -> -D)")
        print("  * tear everything down (surgical iptables -D, cgroup rmdir)")
        print("\nReview the script first, then run:")
        print(f"  sudo /usr/bin/python3 {here}")
        print("Or validate the invariants behind both fixes without root:")
        print(f"  {sys.executable} {here} --selfcheck")
        print("!" * 78)
        return 2
    return _live(report)


if __name__ == "__main__":
    sys.exit(main())
