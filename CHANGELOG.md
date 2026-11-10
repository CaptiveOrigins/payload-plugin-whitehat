# Changelog

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
