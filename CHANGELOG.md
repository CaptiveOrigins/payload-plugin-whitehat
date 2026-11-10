# Changelog

## 0.2.1 (not released yet; 0.2.0 wasn't published, so they go out together)

From a security review of 0.2.0. Whitehat's rule is that a check it couldn't make is "not checked", never "passed"; these places broke it.

- **Only a real refusal passes a forbidden write.** Any error used to count as refused, so an allowed write that failed validation (a probe missing a field) passed. Now 401 or 403 pass by default, a write can describe its proper refusal with `refusal`, and anything else is not checked. A refusal that gives something away still fails.
- **The credential check says when it can't see.** If a signed-out visitor already gets a 2xx and the target gives no `secretMarkers`, a bypass would look the same, so each forgery is not checked instead of passed.
- **Alerts for things that are gone resolve.** When a suite runs in full, its open alerts it no longer reports are resolved ("no longer found"), such as a cleaned record or a rebuilt bundle. A suite that reports nothing resolves nothing and is itself not checked. `scanUserContent` always reports a summary, so a clean scan isn't empty. `recordFindings` resolves this way only with `complete: true`.
- **Not checked, not passed:** a canary with no read paths, a canary every viewer may see, an answer that can't be turned into text, and a redirect whose Location can't be read.
- **`allowWriteProbes`** (default off). Suites that try writes are declared `{ run, writes: true }`; the plugin won't start with one while it's off, and `runSuite` records such a suite as not checked without running it.

Tested: 36 tests (8 new; 7 of them fail without these changes, and the eighth checks that partial uploads leave alerts alone, which already held). Not yet run against a real site's suites.

## 0.2.0 (not released yet)

- **Alerts in the site's database.** The `whitehat` plugin adds a `whitehat-alerts` collection.
  - Findings are kept by fingerprint (check, role, path): a re-run updates an alert rather than adding one, and an alert resolves when its check passes.
  - A suite that fails to run is recorded as "not checked", never as passed.
  - New critical alerts call `onCritical` once.
- **Snooze several at once** with the admin's own bulk Edit. An end date within 90 days and a reason are required, and the snooze holds through later runs until it ends. People can change only the snooze, never what was found, and refusals say why.
- **Retest selected** re-runs only the checks behind the selected alerts (button above the list, or `POST /api/whitehat/retest`).
- **Nine checklist checks:**
  - `checkHeaders`, `checkCookies`, `checkCors`, `checkOpenRedirects`;
  - `checkGraphql` (introspection in production), `checkAdminExposure` (noindex);
  - `checkClientSecrets`, `checkUploads`;
  - `scanUserContent` (scripts in user-written text). The secrets and content scans never copy the matching text.

## 0.1.0

- The access check (canaries and forbidden writes, `payloadReadPaths`), and the untrusted-credentials check (forged session cookies and headers; first regression: a maintenance gate that trusted a cookie's presence). Severity-ranked findings; "not checked" never counts as passed.
