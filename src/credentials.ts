import { createHmac, randomBytes } from 'node:crypto'

import type { Finding, Severity } from './index.js'

/**
 * Untrusted credentials (owner 2026-11-09): code that lets a request through because a cookie or header is
 * *present*, without verifying it. Every target is asked once as a plain signed-out visitor, then again with
 * each forged credential; if a forgery gets more than the signed-out request did (a better status, or text the
 * signed-out response never shows), that's a finding. The first regression: a maintenance gate that let anyone
 * with any `payload-token` cookie past the "back soon" page.
 */
export type TargetResponse = { status: number; body: string }

export type CredentialTarget = {
  id: string
  title: string
  /** Make the request with these extra headers (a `cookie` header carries forged cookies). */
  request: (headers: Record<string, string>) => Promise<TargetResponse>
  /** What's behind it: data or an action (high when bypassed), or only a courtesy gate such as a maintenance page (medium). */
  protects: 'data' | 'action' | 'courtesy'
  /** Text that must never appear for a signed-out visitor (e.g. a private record's id). */
  secretMarkers?: string[]
}

export type Forgery = { name: string; headers: Record<string, string> }

const b64 = (v: unknown) => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url')

/** A token shaped like a real JWT, signed with a key the site has never seen. */
function foreignJwt(claims: Record<string, unknown>) {
  const head = b64({ alg: 'HS256', typ: 'JWT' })
  const body = b64(claims)
  const sig = createHmac('sha256', randomBytes(32)).update(`${head}.${body}`).digest('base64url')
  return `${head}.${body}.${sig}`
}

/**
 * The forged credentials every target gets. `sessionCookie` is the auth cookie's name (Payload's default
 * `payload-token`); `extraCookies` are any other cookies the site's code might trust (role, tenant, preview).
 */
export function forgedCredentials(o: { sessionCookie?: string; extraCookies?: Record<string, string> } = {}): Forgery[] {
  const name = o.sessionCookie ?? 'payload-token'
  const now = Math.floor(Date.now() / 1000)
  const sessions: [string, string][] = [
    ['a made-up session cookie', 'x'],
    ['a malformed session cookie', 'not.a.jwt'],
    ['an expired session token', foreignJwt({ id: 'whitehat-expired', collection: 'users', email: 'probe@example.invalid', iat: now - 7200, exp: now - 3600 })],
    ['a session token signed by someone else', foreignJwt({ id: 'whitehat-foreign', collection: 'users', email: 'probe@example.invalid', iat: now, exp: now + 3600 })],
  ]
  return [
    ...sessions.map(([label, value]) => ({ name: label, headers: { cookie: `${name}=${value}` } })),
    { name: 'a forged x-forwarded-host', headers: { 'x-forwarded-host': 'admin.example.invalid' } },
    { name: 'a forged x-forwarded-for', headers: { 'x-forwarded-for': '127.0.0.1' } },
    { name: 'a made-up Vercel protection bypass', headers: { 'x-vercel-protection-bypass': randomBytes(16).toString('hex') } },
    ...Object.entries(o.extraCookies ?? {}).map(([k, v]) => ({ name: `a forged ${k} cookie`, headers: { cookie: `${k}=${v}` } })),
  ]
}

const better = (forged: number, baseline: number) => {
  const ok = (s: number) => s >= 200 && s < 300
  return ok(forged) && !ok(baseline)
}

/** Runs every forgery against every target and reports any that got more than a signed-out visitor. */
export async function runCredentialCheck(input: { targets: CredentialTarget[]; forgeries?: Forgery[] }): Promise<Finding[]> {
  const forgeries = input.forgeries ?? forgedCredentials()
  const findings: Finding[] = []
  for (const t of input.targets) {
    const severity: Severity = t.protects === 'courtesy' ? 'medium' : 'high'
    let baseline: TargetResponse
    try {
      baseline = await t.request({})
    } catch (error) {
      findings.push({ check: t.id, title: t.title, status: 'not-checked', severity, role: 'signed-out', how: `The signed-out request failed, so there was nothing to compare with: ${(error as Error).message}`.slice(0, 300) })
      continue
    }
    for (const f of forgeries) {
      let res: TargetResponse
      try {
        res = await t.request(f.headers)
      } catch (error) {
        findings.push({ check: t.id, title: t.title, status: 'not-checked', severity, role: 'forged', path: f.name, how: `The request with ${f.name} failed: ${(error as Error).message}`.slice(0, 300) })
        continue
      }
      const leaked = (t.secretMarkers ?? []).find((m) => res.body.includes(m) && !baseline.body.includes(m))
      const passed = better(res.status, baseline.status)
      const fail = Boolean(leaked || passed)
      findings.push({
        check: t.id,
        title: t.title,
        status: fail ? 'fail' : 'pass',
        severity,
        role: 'forged',
        path: f.name,
        how: fail
          ? `With ${f.name}, the request got ${leaked ? 'text a signed-out visitor never sees' : `HTTP ${res.status} instead of ${baseline.status}`}: something trusts that credential without verifying it.`
          : `With ${f.name}, nothing more than a signed-out visitor gets (HTTP ${res.status}).`,
        reproduce: fail ? `Send the request with ${JSON.stringify(f.headers)} and compare with a plain signed-out request.` : undefined,
      })
    }
  }
  return findings
}
