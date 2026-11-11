# payload-plugin-whitehat

Whitehat for Payload: finds security holes in a Payload site, its database, code and UI, with severity-ranked alerts and a checklist that grows with every incident.

**Status:** early (0.2.1, private, not on npm). 36 tests.
- **The access check** works; its tests include the two real leaks it was written to catch (a private related record's id in a public read, and a refusal that answered a question it shouldn't).
- **Checklist checks:** nine are automated, each tested against made-up responses (`CHECKLIST.md` says which).
- **Alerts:** the collection, bulk snooze and Retest selected were tried in a real Payload admin on a local copy of a site, with made-up findings. Saving a snooze, retesting and the refusal messages worked.
- **Not tried yet:** running against a real site's own suites; dependency advisories (still planned).

## What it does

- **Access check.** You declare *canaries*: records only some roles may see, each carrying a unique marker. Whitehat signs in as every role you give it and looks for the marker on every read path: list and by-id reads at depths 0 to 2 (`payloadReadPaths`), plus any REST or GraphQL paths you add through your route handlers. You also declare *forbidden writes*: things a role must not be able to do. It tries each one, and fails it if it's allowed, or if the refusal's message says something it mustn't. Only a real refusal passes: HTTP 401 or 403 by default, or what you describe with `refusal` (a pattern or a function) when the site refuses another way. Any other error, such as a validation error from a probe missing a field, is **not checked**, because an allowed write that failed for another reason looks the same.
- **Untrusted credentials.** `runCredentialCheck` asks each page, endpoint, action or gate you list as a signed-out visitor, then again with forged credentials (fake, expired, malformed and foreign session cookies; forged role, tenant or preview cookies you name; forged `x-forwarded-*` and Vercel bypass headers). A forgery that gets more than the signed-out request is a finding: high if data or an action is behind it, medium for a courtesy gate. Where a signed-out visitor already gets a 2xx (a sign-in page served as 200), a bypass looks the same, so give `secretMarkers` (text only someone let through would see); without them that target is **not checked**.
- **Findings** are ranked critical, high, medium, low or info, and each says how it was found and how to reproduce it. A check that can't run is reported as **not checked**, never as passed.
- **Checklist checks** (`checkHeaders`, `checkCookies`, `checkCors`, `checkOpenRedirects`, `checkGraphql`, `checkAdminExposure`, `checkClientSecrets`, `checkUploads`, `scanUserContent`): each takes plain answers or config, so it runs the same against dev, test or (read-only) a live site.
  - The secrets and content scans name the pattern and the record, never the matching text.
- **Alerts in the site's own database** (the `whitehat` plugin, `whitehat-alerts`).
  - Findings are recorded by fingerprint, so a re-run updates an alert rather than adding one; an alert resolves when its check passes, or when its suite runs in full and no longer reports it (a cleaned record). A suite that reports nothing at all resolves nothing. Name client bundles without their content hash, so a rebuilt bundle keeps its fingerprint.
  - **Snooze several at once** with the admin's own bulk Edit: an end date (at most 90 days) and a reason are required, and the snooze holds through later runs until it ends. People can only change the snooze, never what was found.
  - **Retest selected** re-runs only the checks behind the selected alerts.
  - New critical alerts call `onCritical` once, so the site can tell the owner.
  - Nobody sees alerts without the site's `access`.
- **It only finds.** It never fixes anything, changes data or settings, or touches anything outside the site you run it against.

Run it against a throwaway or test database. Never point write probes at a live site. A suite that tries writes is declared as `{ run, writes: true }`, and the plugin refuses to start with one unless `allowWriteProbes: true`, which belongs only on a throwaway test copy: **Retest selected** runs suites inside the site.

## On its own, and with others

**On its own:** the checks are plain functions that take your site's read and write functions, so they run with no other plugin. The `whitehat` plugin adds the alerts collection and needs your `access`.

**Works with:** nothing is wired to another Captive Origins plugin. It tests whatever access rules the site has, including ones other plugins add. Hats' design plans a Whitehat canary for it: an admin wearing Member must not read admin-only records.

**Family:** It's part of the **Defense** family (a working draft): plugins designed to sit together to find and stop abuse. The other member, Guardrails (rate limits), isn't built yet.

## Use

```ts
import { formatReport, payloadReadPaths, runAccessCheck } from '@captiveorigins/payload-plugin-whitehat'

const findings = await runAccessCheck({
  viewers: [{ role: 'signed-out', user: null }, { role: 'member', user: member }, { role: 'staff', user: admin }],
  canaries: [
    {
      id: 'private-note',
      title: 'A private note is readable by others',
      marker: privateNote.id,
      visibleTo: ['staff'],
      paths: payloadReadPaths(payload, { collection: 'notes', ids: [privateNote.id], where: { site: { equals: site.id } } }),
    },
  ],
  writes: [{ id: 'edit-others', title: 'A member edits someone else’s note', role: 'member', attempt: (v) => payload.update({ collection: 'notes', id: othersNote.id, data: { text: 'x' }, overrideAccess: false, user: v.user as never }) }],
})
console.log(formatReport(findings))
```

## Commands

```bash
npm test          # Vitest
npm run typecheck
npm run build     # dist/
```

Releasing: see `RELEASING.md`.

## License

MIT
