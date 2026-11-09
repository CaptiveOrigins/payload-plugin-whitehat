# payload-plugin-whitehat

Whitehat for Payload: finds security holes in a Payload site, its database, code and UI, with severity-ranked alerts and a checklist that grows with every incident.

**Status:** early (0.1.0, private, not on npm). The access check works, and its tests include the two real leaks it was written to catch (a private related record's id in a public read, and a refusal that answered a question it shouldn't). It hasn't been run against a real site from this package yet; the rest of `CHECKLIST.md` is planned.

## What it does

- **Access check.** You declare *canaries*: records only some roles may see, each carrying a unique marker. Whitehat signs in as every role you give it and looks for the marker on every read path: list and by-id reads at depths 0 to 2 (`payloadReadPaths`), plus any REST or GraphQL paths you add through your route handlers. You also declare *forbidden writes*: things a role must not be able to do. It tries each one, and fails it if it's allowed, or if the refusal's message says something it mustn't.
- **Findings** are ranked critical, high, medium, low or info, and each says how it was found and how to reproduce it. A check that can't run is reported as **not checked**, never as passed.
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
