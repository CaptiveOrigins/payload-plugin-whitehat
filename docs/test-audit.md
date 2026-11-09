# Test audit

Kept by this repo's owning session, per `~/Code/CLAUDE.md`, "Test self-audits". Newest first.

## 2026-11-09: first audit (0.1.0)

| Promise | Tests (`test/access.test.ts`) |
| --- | --- |
| Catches a private related record's id in a public read (regression) | "catches the private-parent read leak…" |
| Catches a refusal that reveals what it protects (regression) | "catches the loop answer in a refusal…" |
| Fails writes that should be refused | "fails a write that should have been refused" |
| Never reports an unchecked path as passed | "never reports something it couldn’t check…" |
| Ranks failures by severity; plain report with reproduction steps | "puts failures first, worst first…" |
| Untrusted credentials: a gate that trusts a cookie's presence is caught (regression: the maintenance gate, medium); a verifying gate passes; a forged role cookie revealing data is high; forged tokens look real; failures are "not checked" | `test/credentials.test.ts` |

- Gaps skipped: `payloadReadPaths` against a real Payload (it only calls the Local API with the viewer's access; covered when a site runs it in its own tests).
- Planned checks in `CHECKLIST.md` get tests as they're automated.
