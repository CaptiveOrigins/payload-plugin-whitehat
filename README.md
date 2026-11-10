# payload-plugin-whitehat

Whitehat for Payload: finds security holes in a Payload site, its database, code and UI, with severity-ranked alerts and a checklist that grows with every incident.

**Status:** early (0.2.0, private, not on npm).
- **The access check** works; its tests include the two real leaks it was written to catch (a private related record's id in a public read, and a refusal that answered a question it shouldn't).
- **Checklist checks:** nine are automated, each tested against made-up responses (`CHECKLIST.md` says which).
- **Alerts:** the collection, bulk snooze and Retest selected were tried in a real Payload admin on a local copy of a site, with made-up findings. Saving a snooze, retesting and the refusal messages worked.
- **Not tried yet:** running against a real site's own suites; dependency advisories (still planned).

## What it does

- **Access check.** You declare *canaries*: records only some roles may see, each carrying a unique marker. Whitehat signs in as every role you give it and looks for the marker on every read path: list and by-id reads at depths 0 to 2 (`payloadReadPaths`), plus any REST or GraphQL paths you add through your route handlers. You also declare *forbidden writes*: things a role must not be able to do. It tries each one, and fails it if it's allowed, or if the refusal's message says something it mustn't.
- **Untrusted credentials.** `runCredentialCheck` asks each page, endpoint, action or gate you list as a signed-out visitor, then again with forged credentials (fake, expired, malformed and foreign session cookies; forged role, tenant or preview cookies you name; forged `x-forwarded-*` and Vercel bypass headers). A forgery that gets more than the signed-out request is a finding: high if data or an action is behind it, medium for a courtesy gate.
- **Findings** are ranked critical, high, medium, low or info, and each says how it was found and how to reproduce it. A check that can't run is reported as **not checked**, never as passed.
- **Checklist checks** (`checkHeaders`, `checkCookies`, `checkCors`, `checkOpenRedirects`, `checkGraphql`, `checkAdminExposure`, `checkClientSecrets`, `checkUploads`, `scanUserContent`): each takes plain answers or config, so it runs the same against dev, test or (read-only) a live site.
  - The secrets and content scans name the pattern and the record, never the matching text.
- **Alerts in the site's own database** (the `whitehat` plugin, `whitehat-alerts`).
  - Findings are recorded by fingerprint, so a re-run updates an alert rather than adding one; an alert resolves when its check passes.
  - **Snooze several at once** with the admin's own bulk Edit: an end date (at most 90 days) and a reason are required, and the snooze holds through later runs until it ends. People can only change the snooze, never what was found.
  - **Retest selected** re-runs only the checks behind the selected alerts.
  - New critical alerts call `onCritical` once, so the site can tell the owner.
  - Nobody sees alerts without the site's `access`.
- **It only finds.** It never fixes anything, changes data or settings, or touches anything outside the site you run it against.

Run it against a throwaway or test database. Never point write probes at a live site.

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
