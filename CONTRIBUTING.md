# Contributing to Hybrid R-Sentry

Thank you for your interest in contributing. This document explains how to get started.

---

## How to Fork the Project

Forking creates your own copy of the repository on GitHub where you can freely make changes without affecting the original project. Follow these steps exactly.

### Step 1 — Fork on GitHub

1. Go to [https://github.com/Mohhudib/hybrid-rsentry](https://github.com/Mohhudib/hybrid-rsentry)
2. Click the **Fork** button in the top-right corner
3. Under "Owner", select your GitHub account
4. Leave the repository name as `hybrid-rsentry` (or rename it if you prefer)
5. Click **Create fork**

GitHub will create `https://github.com/YOUR_USERNAME/hybrid-rsentry` — this is your fork.

---

### Step 2 — Clone Your Fork Locally

Clone **your fork** (not the original repo) to your local machine:

```bash
git clone https://github.com/YOUR_USERNAME/hybrid-rsentry.git
cd hybrid-rsentry
```

Replace `YOUR_USERNAME` with your GitHub username.

---

### Step 3 — Add the Upstream Remote

Add the original repository as a remote called `upstream` so you can pull in future updates:

```bash
git remote add upstream https://github.com/Mohhudib/hybrid-rsentry.git
```

Verify your remotes are configured correctly:

```bash
git remote -v
```

Expected output:

```
origin    https://github.com/YOUR_USERNAME/hybrid-rsentry.git (fetch)
origin    https://github.com/YOUR_USERNAME/hybrid-rsentry.git (push)
upstream  https://github.com/Mohhudib/hybrid-rsentry.git (fetch)
upstream  https://github.com/Mohhudib/hybrid-rsentry.git (push)
```

---

### Step 4 — Set Up the Project

Run the setup script to install dependencies and configure the environment:

```bash
bash setup.sh
```

Copy the example environment file and fill in your values:

```bash
cp .env.example .env
# Edit .env with your API keys and paths
```

Start the required infrastructure:

```bash
docker compose up -d
```

See the [README](README.md) for the full startup sequence.

---

### Step 5 — Create a Feature Branch

Never work directly on `main` or `develop`. Always create a new branch off `develop`:

```bash
git checkout develop
git pull upstream develop       # sync with the latest upstream changes first
git checkout -b feature/your-feature-name
```

Use descriptive branch names:
- `feature/graph-view` for new features
- `fix/firefox-cache-false-positive` for bug fixes

---

### Step 6 — Make Your Changes

- Keep changes focused — one feature or fix per branch
- If touching `agent/` code, test that it does not generate false positive alerts on a live system
- If adding new environment variables, add them to `.env.example` with a placeholder value
- Update the [Wiki](https://github.com/Mohhudib/hybrid-rsentry/wiki) if you change any behaviour

Commit using the prefix style:

```
feat: add new detection module
fix: resolve false positive on /tmp writes
docs: update API reference
chore: bump asyncpg to 0.31.0
refactor: simplify lineage scorer
```

---

### Step 7 — Push and Open a Pull Request

Push your branch to your fork:

```bash
git push origin feature/your-feature-name
```

Then on GitHub:

1. Go to your fork at `https://github.com/YOUR_USERNAME/hybrid-rsentry`
2. Click **Compare & pull request** (GitHub shows this automatically after a push)
3. Set the base repository to `Mohhudib/hybrid-rsentry` and the base branch to **`develop`**
4. Fill in the PR title and description fully
5. Click **Create pull request**

PRs that introduce new false positives will not be merged.

---

## Keeping Your Fork in Sync

Before starting any new work, sync your fork with the latest upstream changes:

```bash
git checkout develop
git fetch upstream
git merge upstream/develop
git push origin develop
```

This keeps your fork up to date and avoids merge conflicts later.

---

## Branch Strategy

| Branch | Purpose |
|---|---|
| `main` | Stable releases only |
| `develop` | Active development — base all PRs here |
| `feature/your-feature` | New features |
| `fix/your-fix` | Bug fixes |

Always branch off `develop`, never `main`.

---

## Reporting Bugs

Use the [Bug Report](https://github.com/Mohhudib/hybrid-rsentry/issues/new?template=bug_report.md) issue template.

## Suggesting Features

Use the [Feature Request](https://github.com/Mohhudib/hybrid-rsentry/issues/new?template=feature_request.md) issue template.

---

## Contact

For questions or security vulnerabilities: **mohammadhudib960@gmail.com**
