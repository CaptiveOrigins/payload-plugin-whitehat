# Test audit

Kept by this repo's owning session, per `~/Code/CLAUDE.md`, "Test self-audits". Newest first.

## 2026-11-11: only an exact `true` from `access`

Suite: 36 tests before, 38 after (`npx vitest run`; `alerts.test.ts` on real Payload 3.92 and in-memory MongoDB with made-up alerts and users).

- **The change.** `hasAccess` in `src/alerts.ts`: signed in, and `access(req)` answered exactly `true`; a throw or rejection is `false`. The alerts collection's read and update and the retest endpoint use it, so the site's answer never reaches Payload as access.
- **Tests.** "refuses reads, snoozes and retests with 403 for anything but true…": `1`, `'yes'`, `{}`, a query-shaped object, a throw and a rejection each get 403 on find, findByID, a snooze and the retest endpoint, no suite runs and the alert is unchanged. "lets an exact true read every alert, and refuses someone not signed in even then".
- **Mutation checks.** 5, each a Python string replace restored byte for byte (SHA-256 checked); all 5 fail the suite: truthy passing; errors rethrown; the sign-in check dropped; the old pass-through in the collection's access; the old truthy check in the retest endpoint.
- **Skipped.** No default to test: `access` is required and there's no fallback, so the "member of a second auth collection under the default" case doesn't apply; the site's own rule decides who that is. The "Retest selected" button only calls the endpoint and has no access decision of its own.

## 2026-11-10: 0.2.0

28 tests: `access.test.ts` (5), `credentials.test.ts` (4), `checks.test.ts` (10), `alerts.test.ts` (9, real Payload 3.92 and in-memory MongoDB).

| Promise | Test |
| --- | --- |
| Headers, cookie flags, CORS, open redirects, GraphQL introspection, admin indexing: pass and fail cases | checks: one test each |
| A check whose request fails is "not checked", never passed | checks: "a check whose request fails…" |
| Secrets in bundles and scripts in user text are found without copying them | checks: "client secrets…", "user-written content…" |
| SVG and unrestricted uploads flagged | checks: "uploads…" |
| One alert per finding; updated on re-run; resolved on pass; plain passes not stored | alerts: "opens one alert per finding…" |
| A throwing suite is recorded "not checked" | alerts: "a suite that throws…" |
| Critical alerts reported once | alerts: "tells someone about a new critical alert once…" |
| Bulk snooze over a selection holds through later runs; reason, future end and 90-day limit enforced | alerts: "bulk snooze" (2) |
| No access, no alerts; edits change only the snooze | alerts: "people without access…" |
| Retest runs only the selected alerts' suites; endpoint refuses without access or a selection | alerts: "retest a selection" (2) |

Checked outside the tests: the admin list, Retest selected (with its result kept across the reload) and a bulk snooze sent the way bulk Edit sends it, in a real Payload admin on a local copy of a site with made-up findings. This also found that Payload hid the snooze refusals ("Something went wrong"); they now show the reason. axe on the list found issues only in Payload's own list markup.

Gaps: dependency advisories (planned); GraphQL depth and complexity (planned); the admin's bulk Edit drawer was opened but driven by the request, not by clicks.

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
