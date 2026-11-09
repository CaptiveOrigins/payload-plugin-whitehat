# First-public-push audit

Run 2026-11-09 by the Web Platform session, before the repo goes public (per ~/Code/CLAUDE.md). Visibility is changed by the owner, not by this audit.

| Check | Result |
| --- | --- |
| Commit authors (all history) | Only the noreply address (11632652+mgilardi@users.noreply.github.com), 2 commits |
| Secrets in history (Stripe, AWS, GitHub, Slack, Resend keys, private keys, database URLs with passwords, hard-coded passwords) | None found (the test fixture value "s3cret" is made up) |
| Email addresses in tracked files | None other than noreply |
| Server addresses, IPs, private hosts | None (a public site name may appear as an example) |
| Build output, dependencies, env files committed | None (dist/, node_modules/, .env are ignored) |
| Private terms (`scripts/leak-check.sh` locally, with ~/.leak-private-terms) | Passed |
| Leak check in CI | Yes, first step of `.github/workflows/ci.yml` |
| LICENSE | MIT, Copyright (c) 2026 Captive Origins |
| README status line says what has and hasn't been tested | Yes |
| Findings about a real site | None in this repo |

Result: clean. Ready for the owner's visibility change.
