# Session 05 — GitHub Cleanup & Standards

**Date:** 2026-05-22  
**Goal:** Honest audit of the GitHub repo, fix everything that was wrong, bring it up to a clean standard.  
**Commits:** `a37e654`

---

## What was audited

Ran `gh repo view`, `gh api repos/...`, `gh pr list`, `gh issue list`, checked workflows, license, wiki, deployments.

---

## Problems found

### 1. LICENSE file was broken
The file said `MIT License` at the top but also had `All rights reserved.` — these two directly contradict each other. MIT is a permissive license that grants rights to everyone. "All rights reserved" means the opposite (proprietary). The file also had three custom clauses that further broke the MIT definition. GitHub showed the license as **"Other / NOASSERTION"** (unrecognized). Anyone visiting the repo saw no valid license.

### 2. README linked to a wiki that didn't exist
The README had a wiki badge and 7 links to wiki pages: Architecture, Detection Engine, Auto-Containment, AI Threat Analyst, Installation, API Reference, Known Issues. The GitHub wiki was completely empty — all 7 links were 404s.

### 3. Two GitHub Pages deployments (one dead)
Two deployments existed for the `github-pages` environment. The older one (ID `4713762382`, status: `inactive`) had been superseded by the newer one (ID `4713953020`, status: `success`) but was still listed.

### 4. 18 open PRs — repo looked abandoned
The PRs tab was flooded with:
- 1 own revert PR (PR #18) opened by Mohammad but never merged or closed
- 14 Dependabot auto-update PRs — many duplicates (two PRs for the same package at different versions)
- 1 contributor PR (`Feat/detection` by `3xcv`) sitting with no response
- Several major-version bumps (React 19, recharts 3, react-router-dom 7, date-fns 4, Python 3.14) that would break the app if merged without testing

### 5. GitHub Packages — explained
The Packages section on GitHub is a registry for hosting built/compiled versions of software (Docker images, npm packages, pip packages, etc.). The project doesn't use it and doesn't need it yet — it would only matter if CI/CD was set up to build and publish a Docker image automatically.

---

## What was fixed

### Fix 1 — LICENSE corrected to standard MIT
Removed `All rights reserved.` and the three custom clauses. Now uses the exact standard MIT license text. GitHub now recognizes it correctly as MIT.

### Fix 2 — Dead wiki links removed from README
Replaced the 7 dead wiki links with links to the real `docs/context/` files that actually exist in the repo. Also changed the wiki badge to point to `docs/context/README.md`.

### Fix 3 — Old deployment deleted
Deleted the inactive deployment (ID `4713762382`). Only one deployment remains — the active GitHub Pages one at `success` state.

### Fix 4 — 9 PRs closed with explanations

| PR | Title | Reason closed |
|---|---|---|
| #18 | Revert README.md | Own PR, no longer needed — README updated directly |
| #12 | aiohttp 3.13.4 | Duplicate — superseded by #14 (3.13.5) |
| #3 | python-multipart 0.0.28 | Duplicate — superseded by #17 (0.0.27) |
| #13 | react 18 → 19 | Major version, breaking changes — defer until production-ready |
| #11 | react-dom 18 → 19 | Major version, breaking changes — same reason |
| #16 | recharts 2 → 3 | Major version, API changes require testing |
| #15 | react-router-dom 6 → 7 | Major version, breaking changes |
| #10 | date-fns 3 → 4 | Major version, breaking changes |
| #5 | Python 3.11 → 3.14 | 3.14 not yet stable |

---

## What was left open (intentionally)

### 7 safe Dependabot PRs (minor/patch Python updates)
These are all patch or minor version bumps within the same major version — safe to merge when tested on Kali:

| PR | Update |
|---|---|
| #17 | python-multipart 0.0.9 → 0.0.27 |
| #14 | aiohttp 3.11.18 → 3.13.5 |
| #9 | python-dotenv 1.0.1 → 1.2.2 |
| #8 | alembic 1.13.1 → 1.18.4 |
| #7 | sqlalchemy 2.0.30 → 2.0.49 |
| #6 | httpx 0.27.0 → 0.28.1 |
| #4 | numpy ≥2.0.0 → ≥2.4.4 |

To merge: on Kali, merge the PR via GitHub, then `git pull origin main` and `pip install -r requirements.txt`.

### PR #2 — Feat/detection (contributor PR from `3xcv`)
A real contributor forked the repo and opened a PR. Left open — needs review. Either merge it or close it with a reason. Do not leave it sitting without a response — it's rude to contributors and looks bad on the repo.

---

## Repo state after this session

| Item | Status |
|---|---|
| License | ✅ Standard MIT — recognized by GitHub |
| README | ✅ No dead links |
| Deployments | ✅ One active deployment |
| Open PRs | ✅ 8 (7 safe Dependabot + 1 contributor to review) |
| Wiki | ⚠️ Disabled from README — empty, will fill when project is finished |
| CI tests | ⚠️ No test suite — deferred until project is complete |
| GitHub Packages | ⚠️ Not used — not needed until Docker CI/CD is set up |
