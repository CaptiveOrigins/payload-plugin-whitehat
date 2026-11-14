# Decisions

Dated decisions for this repo, newest last.

- 2026-11-09: created from the ops starter kit, area `plugins`.
- 2026-11-09: built at the owner's decision (a brief in ops). MIT; private until the first-public-push audit with the leak check in CI, then public (owner said yes). Never published to npm by a session. Findings about a real site never go in this repo. The engine takes read and write functions from the site, so it is testable without a database.
- 2026-11-10 (0.2.0): **alerts live in the site's database**, in a `whitehat-alerts` collection the plugin adds, never in this repo. Kept by fingerprint (check, role, path); passes resolve, and a finding that never failed isn't stored.
- 2026-11-10: **bulk snooze uses Payload's own bulk Edit** rather than a custom screen (the owner's "select several to snooze in bulk", brief 2026-11-09). An end date within 90 days and a reason are required; a person can change only the snooze. **Retest selected** runs only the suites behind the selection.
- 2026-11-10: **checklist checks take plain answers** (`Ask` returns status, headers, body) or config, so they're testable without a server, and the same code runs read-only against a live site when the owner allows.
- 2026-11-11 (access sweep): only an exact `true` from `access` lets someone see, snooze or retest alerts; any other answer, an error included, is a 403, and the answer is never passed to Payload as access. `access` stays required, with no default.
- 2026-11-13: moved to the ExtantApe GitHub organization and the `@extantape` npm scope at the same version. EXTANT APE owns its reusable tools and licenses them to the platform. The earlier package name is deprecated with a pointer here, and GitHub redirects the old repository address.
