# Whitehat checklist

What Whitehat looks for. Every incident or new advisory adds a row, reviewed in a pull request; that's how it learns. "Automated" means `runAccessCheck` or a helper does it today; "planned" means it's listed so it isn't forgotten, and is done by hand until then.

Default severities: critical (data or accounts at risk now), high (private data reachable), medium (weakens a defence), low (hygiene), info (worth knowing).

| Id | Check | Default severity | Status |
| --- | --- | --- | --- |
| access-read | Canaries: records only some roles may see never appear on any read path (list, by id, depth 0–2, REST, GraphQL) for other roles | high | automated |
| access-write | Forbidden writes are refused, and refusals don't reveal what they protect | high | automated |
| private-relations | A related record the reader can't see doesn't leak its id or fields through the record that refers to it (regression, 2026-11-09) | high | automated (canary) |
| refusal-oracle | A refusal's message doesn't answer a question about records the person can't see (regression, 2026-11-09) | high | automated (write probe) |
| trusted-api-writes | REST, GraphQL and admin writes run the same checks as the Local API with access on (regression, 2026-11-09) | high | automated (write probe) |
| headers | Security headers: CSP, framing, nosniff, referrer, permissions, HSTS | medium | planned |
| cookies | Session cookies are Secure, HttpOnly and SameSite | high | planned |
| cors | CORS and CSRF origins are a short, explicit list | medium | planned |
| rate-limits | Sign-in, password reset and public forms are rate-limited | medium | planned |
| uploads | Upload types and sizes are limited; SVGs can't run scripts | high | planned |
| ssrf | Fields that take a URL can't make the server fetch private addresses | high | planned |
| stored-xss | User-written text can't carry scripts or event handlers into pages | high | planned |
| guessable-ids | Records reachable by guessing ids in URLs are only ones meant to be public | medium | planned |
| open-redirect | Redirect parameters only go to the site's own pages | medium | planned |
| graphql-limits | GraphQL depth and complexity are capped; introspection off in production | medium | planned |
| admin-exposure | The admin isn't indexable and refuses people without an admin role | medium | planned |
| client-secrets | No secret or server-only value reaches a client bundle | critical | planned |
| dependencies | Dependencies have no known advisories (grouped; snoozable with a reason and an end date) | low–critical | planned |
