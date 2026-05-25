# Known Code Issues

All issues found during CI setup on 2026-05-25 have been fixed.

| Category | Count | Status | Fixed in |
|----------|-------|--------|---------|
| F401 - Unused imports | 23 | Fixed | commits f2ae876...f5782e7 |
| F841 - Unused variables | 2 | Fixed | commits 8e1235e, 2416602 |
| E712 - SQLAlchemy == False | 4 | Annotated with noqa: E712 | commit db9ad4e |
| ESLint - unused useRef | 1 | Fixed | commit 6f0c77a |

CI now runs with no ignores. Any new issues will fail the build.
