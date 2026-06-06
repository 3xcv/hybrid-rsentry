# Hybrid R-Sentry — Claude Context

You are helping debug or develop **Hybrid R-Sentry**, a ransomware detection system running on Kali Linux.
Read this entire file before doing anything.

---

## What the system is

A multi-process Python + React application with five processes that must all be running simultaneously:

| Process | What it does |
|---|---|
| Docker (Postgres + Redis) | Database and message broker |
| FastAPI backend (`uvicorn`) | REST API + WebSocket server on port 8000 |
| Celery worker | Async tasks: AI analysis, WebSocket push, risk scoring |
| Agent (`agent.monitor`; sensor backend chosen via `--backend`/`SENSOR_BACKEND`, defaults to `ebpf`) | Watchdog that monitors files, detects threats, fires containment |
| React frontend (`npm start`) | Dashboard on port 3000 (Vite dev server) |

---

## Startup sequence

```bash
# One command (recommended):
cd ~/hybrid-rsentry && bash start.sh
# Logs go to /tmp/rsentry-backend.log, /tmp/rsentry-celery.log,
#             /tmp/rsentry-agent.log, /tmp/rsentry-frontend.log

# Or manually (5 terminals):

# Terminal 1
cd ~/hybrid-rsentry && docker compose up -d

# Terminal 2 — source .env first so DATABASE_URL and AI keys reach uvicorn
cd ~/hybrid-rsentry && set -a && source .env && set +a && source venv/bin/activate && uvicorn backend.main:app --reload

# Terminal 3 — source .env first so DATABASE_URL and AI keys reach Celery
cd ~/hybrid-rsentry && set -a && source .env && set +a && PYTHONPATH=. celery -A backend.workers.tasks:celery_app worker --loglevel=info

# Terminal 4 — sudo -E preserves shell-exported overrides (SENSOR_BACKEND, DRY_RUN, etc);
# monitor.py also auto-loads .env via load_dotenv(), so WATCH_PATH loads correctly even without -E.
cd ~/hybrid-rsentry && set -a && source .env && set +a && sudo -E ~/hybrid-rsentry/venv/bin/python -m agent.monitor

# Terminal 5
cd ~/hybrid-rsentry/frontend && npm start
```

---

## Key files

```
backend/main.py                  — FastAPI app, CORS config, lifespan (DB table creation)
backend/models/database.py       — SQLAlchemy async engine; reads DATABASE_URL (required, no default)
backend/models/schemas.py        — All ORM models + Pydantic schemas
backend/routers/events.py        — POST /api/events (agent posts here), alert creation logic
backend/routers/alerts.py        — Alert CRUD, /api/alerts/counts, ACK endpoint, forensic export
backend/routers/hosts.py         — Host inventory, contain/release endpoints, /api/hosts/{id}/risk
backend/routers/ws.py            — WebSocket; subscribes to 3 Redis channels
backend/workers/tasks.py         — All Celery tasks; reads .env directly via _env() — no dotenv
backend/services/ai_analyst.py   — Multi-provider AI: Cerebras → NVIDIA/Groq fallback chain

agent/monitor.py                 — Main watchdog; SENSOR_BACKEND/--backend selects inotify or eBPF (defaults to "ebpf" — system-wide,
                                    not WATCH_PATH-scoped); auto-loads .env via load_dotenv(); _validate_watch_path() exits if
                                    WATCH_PATH inside git repo
agent/monitor_ebpf.py            — eBPF sensor (default backend); 5-syscall behavioral scoring (openat/vfs_write/unlink/rename/execve)
                                    + silent-encryption detection (entropy>=6.5 on in-place rewrites); BPF-LSM inline block
                                    (LSM_PROBE path_rename, -EPERM) when lsm=bpf kernel param active, else SIGSTOP fallback;
                                    velocity burst detection; ransomware family profiling (LockBit5/Akira/ESXi); kernel 6.19+, BCC 0.35 compat
agent/graph.py                   — FilesystemGraph: BFS directory walk + canary placement + cleanup
agent/entropy.py                 — Shannon entropy engine; memory-capped at 5000 files, 65KB partial reads
agent/containment.py             — Tree-aware SIGSTOP → evidence capture → iptables DROP → SIGKILL; PID resolved from /proc;
                                    skips iptables DROP for uid=0/root (would block the agent itself)
agent/adaptive.py                — Markov chain repositioner (inotify backend only — disabled for eBPF, since system-wide
                                    canaries make repositioning unnecessary); _is_safe_target() blocks .git/ and system dirs
agent/lineage.py                 — Process ancestry scorer + dpkg hash verification (416K hashes)
agent/exceptions.py              — Whitelist: browsers, package managers, system paths; smart /tmp filter
agent/client.py                  — HTTP client that posts events to /api/events

simulations/sim_common.py        — Shared simulation engine (Profile, populate_corpus, run_attack, backup/restore)
simulations/sim_akira.py         — Akira intermittent encryption simulation
simulations/sim_qilin.py         — Qilin percent-encryption simulation
simulations/sim_lockbit.py       — LockBit 5.0 two-pass 16-char-ext simulation
tests/test_lockbit.py            — 4-metric evaluation (files<3, latency<500ms, FP=0%, coverage=100%) — ALL TARGETS MET

frontend/src/App.jsx             — Root app; TopBar + StatusBar layout; WebSocket + AI state; passes liveEvent to AlertsPage
frontend/src/index.jsx           — Entry point (.jsx required by Vite production build)
frontend/index.html              — Vite root HTML; IBM Plex Sans/Mono fonts + Font Awesome 6.5.1
frontend/vite.config.js          — Vite config: React plugin + proxy (/api, /ws → localhost:8000) + process.env shim
frontend/postcss.config.js       — Tailwind + autoprefixer config for Vite
frontend/src/index.css           — CSS variable design system (--bg, --panel, --crit, --accent…) + SIEM utility classes

frontend/src/components/TopBar.jsx          — Horizontal nav bar (replaces Sidebar); 6 tabs + alert count badge
frontend/src/components/StatusBar.jsx       — Bottom status bar: agents, EPS, WS status, last refreshed, cluster
frontend/src/components/FacetRail.jsx       — Left filter panel on Alerts page; collapsible field groups from real data
frontend/src/components/MetricsStrip.jsx    — 6 live metrics strip (open/critical/high/hosts/EPS/event types)
frontend/src/components/AlertsHistogram.jsx — Stacked 30-min histogram from /api/events
frontend/src/components/AlertsTable.jsx     — Sortable alerts table with severity dot + risk meter + status
frontend/src/components/DetailFlyout.jsx    — Right flyout on alert click: Summary/Entity/MITRE/Filesystem graph/Raw JSON
frontend/src/components/EventDetailModal.jsx — Modal on TacticalResponseLog event click: same sections as flyout
frontend/src/components/FileSystemGraph.jsx  — D3 v7 Obsidian-style force-directed graph; zoom/drag/tooltip;
                                               highlightPath pulls selected node to center with blue glow
frontend/src/components/FileSystemTree.jsx  — Text tree (Detections page only); highlightPath + compact props added
frontend/src/components/TacticalResponseLog.jsx — Event rows are clickable → opens EventDetailModal
frontend/src/components/AIAnalystPanel.jsx
frontend/src/components/AlertFeed.jsx
frontend/src/components/EventChart.jsx
frontend/src/components/HostRiskPanel.jsx
frontend/src/components/StatsBar.jsx

frontend/src/pages/AlertsPage.jsx     — 3-column SIEM layout: FacetRail + (metrics+histogram+table) + DetailFlyout
frontend/src/pages/Overview.jsx       — Dashboard with StatsBar, EventChart, AlertFeed, TacticalResponseLog, HostRiskPanel
frontend/src/pages/HostsPage.jsx
frontend/src/pages/FilesystemPage.jsx — "Detections" in nav; uses FileSystemTree (full text tree with search)
frontend/src/pages/AIAnalystPage.jsx
frontend/src/pages/ReportsPage.jsx    — PDF forensic export with date/severity filter + host overview table
```

---

## Required .env variables

File lives at `~/hybrid-rsentry/.env` (gitignored — never committed).

```
POSTGRES_PASSWORD=...
DATABASE_URL=postgresql+asyncpg://rsentry:<POSTGRES_PASSWORD>@localhost:5432/rsentry_db
REDIS_URL=redis://localhost:6379/0
SECRET_KEY=...
HOST_ID=ATOMIC
BACKEND_URL=http://localhost:8000
WATCH_PATH=/home/mohammad/Documents
CANARY_COUNT=15
NVIDIA_API_KEY=...           # also readable as AI_API_KEY
NVIDIA_API_KEY_ALERTS=...    # also readable as AI_API_KEY_ALERTS

# Optional — Cerebras becomes primary provider if set (fastest); NVIDIA/Groq used as fallback:
# AI_API_KEY_CEREBRAS=csk-...
```

`DATABASE_URL` is required — no fallback default. Backend raises `RuntimeError` immediately if missing.
`AI_API_KEY_CEREBRAS` is optional — system falls back to NVIDIA/Groq automatically if not set.
Groq keys are also accepted in place of NVIDIA keys — auto-detected by the `gsk_` prefix.

---

## Hard rules — never violate these

1. **WATCH_PATH must be outside ~/hybrid-rsentry.** Canary files corrupt git refs if placed inside the project directory. The agent calls `_validate_watch_path()` at startup and exits immediately if violated. Canaries now use 4 prefixes — `AAA_`/`aaa_`/`ZZZ_`/`zzz_` (agent/graph.py, agent/monitor_ebpf.py) — but `.gitignore` only excludes `AAA_*.txt`/`**/AAA_*.txt`; if WATCH_PATH is ever misconfigured, `aaa_`/`ZZZ_`/`zzz_` canaries can corrupt git refs the same way `AAA_*.txt` did before.
2. **Never run `docker compose down -v`.** The `-v` flag deletes the Postgres data volume. Use `docker compose down` only.
3. **Never edit `.env.example` thinking it is `.env`.** Real secrets are in `.env` (gitignored).
4. **Start the agent with `sudo -E`** after sourcing `.env`. `monitor.py` now auto-loads `.env` via `load_dotenv()` at import (agent/monitor.py:35), so `WATCH_PATH` loads correctly even without `-E` — but `-E` is still needed to preserve shell-exported overrides (`SENSOR_BACKEND`, `DRY_RUN`, etc) that aren't in `.env`.
5. **Always activate the venv before pip commands:** `source venv/bin/activate`
6. **Never run `npm audit fix --force`** on the frontend without checking what it intends to install.
7. **Do not suggest adding authentication middleware** without understanding the full async SQLAlchemy dependency chain — this has broken the app before.
8. **Never merge Dependabot PRs #38 (Vite 8), #42 (Tailwind 4), #43 (react-router-dom 7), #37 (openai 2) without manual review** — all are major breaking versions.

---

## Frontend stack (as of 2026-06-03)

The dashboard was migrated from Create React App to **Vite** (PR #33), upgraded to **React 19** (PR #34), and fully redesigned to a SIEM/Kibana-style layout.

| Package | Version | Note |
|---|---|---|
| react / react-dom | 19.2.0 | |
| vite | 5.x | replaces react-scripts entirely |
| @vitejs/plugin-react | 4.x | |
| tailwindcss | 3.x | configured via postcss.config.js |
| d3 | 7.9.x | force-directed filesystem graph |
| date-fns | 4.x | |
| lucide-react | 1.x | |
| recharts | 2.12.x | React 19 compatible |
| IBM Plex Sans/Mono | Google Fonts | typography for SIEM design |
| Font Awesome | 6.5.1 CDN | icons in TopBar, DetailFlyout, etc. |

`npm run build` produces output in `frontend/dist/` (not `build/`).
`npm start` maps to `vite` (dev server on port 3000 with proxy to backend).
Node.js 22 is used in CI (`deploy-landing.yml`) and Docker (`Dockerfile.frontend`).

**Design system** (CSS variables in `index.css`):
- `--bg: #131519` · `--panel: #191b21` · `--panel-2: #1e2027` · `--border: #2b2e37`
- `--crit: #d8503c` · `--high: #d6873a` · `--med: #c9b13f` · `--low: #5b8fb0`
- `--accent: #4f8cc9` · `--ok: #4e9e7e`

**Navigation mapping** (TopBar tabs → pages):
- Overview → Overview page (dashboard)
- Alerts → AlertsPage (3-column SIEM layout)
- Hosts → HostsPage
- Detections → FilesystemPage
- AI Analyst → AIAnalystPage
- Reports → ReportsPage

---

## Known issues and fixes

**Agent floods alerts from Firefox cache / wrong path**
Cause: `WATCH_PATH` resolving to the wrong directory (e.g. the `/home` default).
Fix: confirm `WATCH_PATH` in `.env` is correct. `monitor.py` now auto-loads `.env` via `load_dotenv()` at import, so this no longer strictly depends on `sudo -E` — but `-E` is still recommended for shell-exported overrides (see startup above).

**Canary files appear in `.git/refs/heads/`** (legacy — now prevented on new installs)
Symptom: git commands error; files named `AAA_*.txt` inside `.git/refs/`.
Fix: `find .git/refs -name "AAA_*" -delete && git pull origin main`
Prevention (already in codebase): `AAA_*.txt` is in `.gitignore`; `_validate_watch_path()` blocks startup if WATCH_PATH is inside a git repo; `_is_safe_target()` blocks Markov repositioner from targeting `.git/`.

**Backend crashes immediately on startup with RuntimeError**
Cause: `DATABASE_URL` is not set — the backend has no fallback default. `database.py` checks it at module import time.
Fix: always use `set -a && source .env && set +a` before starting uvicorn (see startup sequence above).

**Celery crashes on startup or AI analysis fails silently**
Cause: `DATABASE_URL` (needed at import time) and `AI_API_KEY` / `NVIDIA_API_KEY` are not in the shell environment.
Note: `_env()` in `tasks.py` reads the .env file for database/redis/celery config, but `database.py` and `ai_analyst.py` use `os.getenv()` directly.
Fix: always use `set -a && source .env && set +a` before starting Celery (see startup sequence above).

**AI returns 429 rate limit errors**
Cause: rate limit hit on the active provider.
Fix: if persistent, check `AI_API_KEY_CEREBRAS` is set (Cerebras has higher limits); rotate `NVIDIA_API_KEY` and `NVIDIA_API_KEY_ALERTS` in `.env` and restart Celery.

**Alert counts wrong or stale in dashboard**
MetricsStrip and StatsBar use `/api/alerts/counts` endpoint. Risk score updates and WebSocket pushes go through Celery.
Fix: confirm the Celery worker is running.

**Risk score stuck at 0 after clearing alerts**
This is correct behaviour. The score recalculates via Celery on the next incoming event.

**Frontend blank page / `process is not defined` error**
Cause: `AIAnalystPanel.jsx` and `useWebSocket.js` use legacy CRA-era `process.env.REACT_APP_*` syntax.
Fix: already fixed — `vite.config.js` has `define: { 'process.env': {} }` shim. If it recurs, check those two files.

**GitHub Actions deploy-landing.yml — Node.js version**
The workflow uses `node-version: 22` and `node:22-alpine` in the Docker build. Node 22 is LTS until April 2027.

**eBPF sensor fails to load tracepoints**
Cause: kernel < 6.19 or BCC version mismatch.
Fix: confirm `uname -r` ≥ 6.19 and `pip show bcc` is 0.35+. The sensor mixes TRACEPOINT_PROBE (rename/unlink/openat/execve syscalls), `kprobe__vfs_write` (writes), and `LSM_PROBE` (inline canary blocking) — all feeding `BPF_PERF_OUTPUT` (not `BPF_RINGBUF`) for compatibility.

---

## Alert severity logic

| Severity | Trigger | Auto-action |
|---|---|---|
| CRITICAL | Canary file touched or deleted; ransomware extension rename on document; combined score ≥ 70 | Immediate tree-aware: SIGSTOP → evidence → iptables DROP (skipped for uid=0/root — would block the agent itself) → SIGKILL |
| HIGH | Combined score 40–69 (entropy + lineage); new file with ransomware extension | AI analysis queued, alert record created |
| MEDIUM | Entropy spike alone | AI analysis queued, alert record created |
| LOW | Heartbeat / system events | Logged only, no alert record |

AI auto-acknowledges alerts it classifies as Benign or LOW risk.
CRITICAL alerts are auto-acknowledged when CONTAINMENT_COMPLETE fires.

---

## Safe diagnostic commands

```bash
# Confirm all 5 processes are running
docker compose ps
ps aux | grep uvicorn
ps aux | grep celery
ps aux | grep agent.monitor

# Check service logs (when started via start.sh)
tail -30 /tmp/rsentry-backend.log
tail -30 /tmp/rsentry-celery.log
tail -30 /tmp/rsentry-agent.log

# Backend health check
curl http://localhost:8000/health

# One-command pipeline test (sends CANARY_TOUCHED event → triggers CRITICAL + AI analysis)
bash test_event.sh

# Recent events in DB
docker exec -it rsentry_postgres psql -U rsentry -d rsentry_db \
  -c "SELECT event_type, severity, file_path, timestamp FROM events ORDER BY timestamp DESC LIMIT 20;"

# Unacknowledged alert counts
docker exec -it rsentry_postgres psql -U rsentry -d rsentry_db \
  -c "SELECT severity, COUNT(*) FROM alerts WHERE acknowledged=false GROUP BY severity;"

# Clear accumulated test/false-positive alerts (marks resolved, does not delete records)
docker exec -it rsentry_postgres psql -U rsentry -d rsentry_db \
  -c "UPDATE alerts SET acknowledged=true, resolved_at=NOW() WHERE acknowledged=false;"

# Watch Redis for live traffic
redis-cli subscribe rsentry:alerts

# Run LockBit 5.0 simulation (eBPF Phase 3)
cd ~/hybrid-rsentry && source venv/bin/activate && python -m simulations.sim_lockbit

# Run Akira simulation
python -m simulations.sim_akira

# Swagger UI (while uvicorn is running)
# http://localhost:8000/docs
```

---

## Debugging approach

Always ask which terminal the error appeared in before suggesting a fix.
The five processes are independent — an error in Celery does not mean the backend is broken.
