import type { Finding, Severity } from './index.js'

/**
 * Checklist checks that need only a request and its answer, or a piece of config. Each takes plain data, so
 * it's testable without a server and runs the same against dev, test or (read-only) a live site. Every one
 * returns findings, and a check that couldn't run is "not-checked", never "pass".
 */
export type Answer = { status: number; headers: Record<string, string | string[] | undefined>; body?: string }
export type Ask = (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string }) => Promise<Answer>

const header = (a: Answer, name: string): string | undefined => {
  const v = a.headers[name.toLowerCase()] ?? a.headers[name]
  return Array.isArray(v) ? v.join(', ') : v
}
const all = (a: Answer, name: string): string[] => {
  const v = a.headers[name.toLowerCase()] ?? a.headers[name]
  return v === undefined ? [] : Array.isArray(v) ? v : [v]
}
const f = (check: string, title: string, severity: Severity, ok: boolean, path: string, how: string, reproduce?: string): Finding => ({ check, title, severity, status: ok ? 'pass' : 'fail', role: 'signed-out', path, how, reproduce: ok ? undefined : reproduce })
const unchecked = (check: string, title: string, severity: Severity, path: string, error: unknown): Finding => ({ check, title, severity, status: 'not-checked', role: 'signed-out', path, how: `Couldn't run: ${(error as Error)?.message ?? String(error)}`.slice(0, 300) })

async function attempt(check: string, title: string, severity: Severity, path: string, run: () => Promise<Finding[]>): Promise<Finding[]> {
  try {
    return await run()
  } catch (error) {
    return [unchecked(check, title, severity, path, error)]
  }
}

/** Security headers on a page: CSP, framing, nosniff, referrer, permissions, and HSTS on https. */
export function checkHeaders(ask: Ask, url: string): Promise<Finding[]> {
  return attempt('headers', 'Security headers', 'medium', url, async () => {
    const a = await ask(url)
    const csp = header(a, 'content-security-policy') ?? ''
    const wants: [string, boolean, string][] = [
      ['framing', Boolean(header(a, 'x-frame-options')) || /frame-ancestors/i.test(csp), 'X-Frame-Options or CSP frame-ancestors'],
      ['nosniff', /nosniff/i.test(header(a, 'x-content-type-options') ?? ''), 'X-Content-Type-Options: nosniff'],
      ['referrer', Boolean(header(a, 'referrer-policy')), 'Referrer-Policy'],
      ['permissions', Boolean(header(a, 'permissions-policy')), 'Permissions-Policy'],
      ['csp', Boolean(csp), 'Content-Security-Policy'],
      ...(url.startsWith('https:') ? ([['hsts', /max-age=\d+/i.test(header(a, 'strict-transport-security') ?? ''), 'Strict-Transport-Security']] as [string, boolean, string][]) : []),
    ]
    return wants.map(([id, ok, name]) => f(`headers-${id}`, `Security header: ${name}`, id === 'csp' ? 'low' : 'medium', ok, url, ok ? `${name} is set.` : `${name} is missing.`, `curl -sI ${url} | grep -i '${name.split(' ')[0]}'`))
  })
}

/** The session cookie set at sign-in is Secure (on https), HttpOnly and SameSite. */
export function checkCookies(signIn: () => Promise<Answer>, o: { cookie?: string; https?: boolean } = {}): Promise<Finding[]> {
  const name = o.cookie ?? 'payload-token'
  return attempt('cookies', 'Session cookie flags', 'high', 'sign-in', async () => {
    const set = all(await signIn(), 'set-cookie').find((c) => c.trim().startsWith(`${name}=`))
    if (!set) return [unchecked('cookies', 'Session cookie flags', 'high', 'sign-in', new Error(`no ${name} cookie was set at sign-in`))]
    const flags = set.split(';').map((s) => s.trim().toLowerCase())
    const has = (k: string) => flags.some((x) => x === k || x.startsWith(`${k}=`))
    const out = [
      f('cookies-httponly', 'Session cookie is HttpOnly', 'high', has('httponly'), 'sign-in', has('httponly') ? 'HttpOnly is set.' : 'HttpOnly is missing: page scripts can read the session.'),
      f('cookies-samesite', 'Session cookie is SameSite', 'medium', has('samesite') && !flags.includes('samesite=none'), 'sign-in', has('samesite') ? `SameSite is ${flags.find((x) => x.startsWith('samesite'))?.split('=')[1]}.` : 'SameSite is missing.'),
    ]
    if (o.https !== false) out.push(f('cookies-secure', 'Session cookie is Secure', 'high', has('secure'), 'sign-in', has('secure') ? 'Secure is set.' : 'Secure is missing: the session can travel over plain http.'))
    return out
  })
}

/** CORS: an unknown origin is never echoed back as allowed, and never with credentials. */
export function checkCors(ask: Ask, url: string, evil = 'https://whitehat-probe.example.invalid'): Promise<Finding[]> {
  return attempt('cors', 'CORS', 'medium', url, async () => {
    const a = await ask(url, { headers: { origin: evil } })
    const allow = header(a, 'access-control-allow-origin') ?? ''
    const creds = /true/i.test(header(a, 'access-control-allow-credentials') ?? '')
    const echoed = allow === evil || (allow === '*' && creds)
    return [f('cors', 'CORS only allows the site’s own origins', creds && echoed ? 'high' : 'medium', !echoed, url, echoed ? `An unknown origin was allowed (${allow}${creds ? ', with credentials' : ''}).` : 'An unknown origin wasn’t allowed.', `curl -sI -H 'Origin: ${evil}' ${url}`)]
  })
}

/** Open redirects: each URL carries a parameter pointing elsewhere; the answer must not send the visitor there. */
export function checkOpenRedirects(ask: Ask, urls: string[], ownHosts: string[]): Promise<Finding[]> {
  return Promise.all(
    urls.map((url) =>
      attempt('open-redirect', 'Open redirect', 'medium', url, async () => {
        const a = await ask(url)
        const loc = header(a, 'location')
        let external = false
        if (loc && a.status >= 300 && a.status < 400) {
          try {
            const host = new URL(loc, url).host
            external = !ownHosts.includes(host)
          } catch {
            external = false
          }
        }
        return [f('open-redirect', 'Redirects stay on the site', 'medium', !external, url, external ? `It redirected to ${loc}.` : 'It didn’t redirect off the site.', `curl -sI '${url}'`)]
      }),
    ),
  ).then((x) => x.flat())
}

/** GraphQL: introspection answers only outside production. */
export function checkGraphql(ask: Ask, url: string, production: boolean): Promise<Finding[]> {
  return attempt('graphql-limits', 'GraphQL introspection', 'medium', url, async () => {
    const a = await ask(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ query: '{ __schema { queryType { name } } }' }) })
    const open = a.status === 200 && /"__schema"\s*:\s*\{/.test(a.body ?? '')
    if (!production) return [{ check: 'graphql-limits', title: 'GraphQL introspection', severity: 'info', status: 'pass', role: 'signed-out', path: url, how: open ? 'Introspection answers (fine outside production).' : 'Introspection is off.' }]
    return [f('graphql-limits', 'GraphQL introspection is off in production', 'medium', !open, url, open ? 'Introspection answered: anyone can read the whole schema.' : 'Introspection is refused.', `curl -s -X POST -H 'content-type: application/json' -d '{"query":"{ __schema { queryType { name } } }"}' ${url}`)]
  })
}

/** The admin isn't indexed by search engines. */
export function checkAdminExposure(ask: Ask, url: string): Promise<Finding[]> {
  return attempt('admin-exposure', 'Admin exposure', 'medium', url, async () => {
    const a = await ask(url)
    const noindex = /noindex/i.test(header(a, 'x-robots-tag') ?? '') || /<meta[^>]+name=["']robots["'][^>]+noindex/i.test(a.body ?? '')
    return [f('admin-exposure', 'The admin asks search engines not to index it', 'low', noindex, url, noindex ? 'noindex is set.' : 'Neither an X-Robots-Tag nor a robots meta tag says noindex.')]
  })
}

/** Secrets in client bundles: patterns of real keys in the JavaScript a browser downloads. Never prints a match. */
export const SECRET_PATTERNS: { name: string; re: RegExp }[] = [
  { name: 'Stripe secret key', re: /\bsk_(live|test)_[A-Za-z0-9]{10,}/ },
  { name: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}/ },
  { name: 'AWS access key', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'GitHub token', re: /\bgh[pousr]_[A-Za-z0-9]{30,}/ },
  { name: 'Private key', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { name: 'Database URL with a password', re: /mongodb(\+srv)?:\/\/[^\s"'/:@]+:[^\s"'@]+@/ },
  { name: 'Resend API key', re: /\bre_[A-Za-z0-9]{20,}/ },
]
export function checkClientSecrets(bundles: { name: string; text: string }[]): Finding[] {
  const out: Finding[] = []
  for (const b of bundles) {
    const hits = SECRET_PATTERNS.filter((p) => p.re.test(b.text)).map((p) => p.name)
    out.push(f('client-secrets', 'No secrets in client bundles', 'critical', hits.length === 0, b.name, hits.length ? `Looks like it contains: ${hits.join(', ')}. (The value isn't copied here.)` : 'No secret patterns found.'))
  }
  return out
}

/** Upload collections: SVGs (which can carry scripts) and unrestricted types are flagged. Reads the Payload config. */
export function checkUploads(collections: { slug: string; upload?: unknown }[]): Finding[] {
  const out: Finding[] = []
  for (const c of collections) {
    if (!c.upload) continue
    const mimes = (typeof c.upload === 'object' && (c.upload as { mimeTypes?: string[] }).mimeTypes) || null
    if (!mimes) out.push(f('uploads', 'Upload types are limited', 'medium', false, c.slug, 'Any file type can be uploaded: no mimeTypes list.'))
    else {
      const svg = mimes.some((m) => /svg|image\/\*|\*\/\*/i.test(m))
      out.push(f('uploads', 'SVG uploads can’t carry scripts', 'high', !svg, c.slug, svg ? `It accepts ${mimes.filter((m) => /svg|\*/.test(m)).join(', ')}; SVGs can carry scripts unless they're sanitised.` : 'No SVGs accepted.'))
    }
  }
  return out
}

/**
 * User-written text: script tags, event handlers, javascript: and data:text/html links, and SVG scripts.
 * Records the record, the field and the pattern, never a copy of the text (owner 2026-11-09).
 */
export const CONTENT_PATTERNS: { name: string; re: RegExp }[] = [
  { name: 'script tag', re: /<\s*script\b/i },
  { name: 'event handler attribute', re: /<[^>]+\son[a-z]+\s*=/i },
  { name: 'javascript: URL', re: /(^|["'=\s(])\s*javascript:/i },
  { name: 'data:text/html link', re: /data:text\/html/i },
  { name: 'iframe', re: /<\s*iframe\b/i },
  { name: 'SVG with script', re: /<\s*svg\b[^>]*>[\s\S]*<\s*script\b/i },
]
export function scanUserContent(items: { collection: string; id: string; field: string; value: unknown }[]): Finding[] {
  const out: Finding[] = []
  for (const it of items) {
    const text = typeof it.value === 'string' ? it.value : JSON.stringify(it.value ?? '')
    for (const p of CONTENT_PATTERNS) {
      if (p.re.test(text)) {
        out.push({ check: 'stored-xss', title: 'User-written text carries a script', severity: 'high', status: 'fail', role: 'content', path: `${it.collection}/${it.id} · ${it.field}`, how: `Matched "${p.name}". (The text isn't copied here.)`, reproduce: `Open ${it.collection} ${it.id} in the admin and look at the field "${it.field}".` })
      }
    }
  }
  return out
}
