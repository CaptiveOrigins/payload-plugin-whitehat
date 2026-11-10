/**
 * Whitehat for Payload: finds security holes in a Payload site. Its core is an access check run as every
 * role: canaries (records only some roles may see, carrying a unique marker) are looked for on every read
 * path, and forbidden writes are attempted. Anything allowed that the site's rules refuse is a finding.
 *
 * It only finds; it never fixes. A check that can't run is reported "not-checked", never "pass".
 */
export { payloadReadPaths, type PayloadReadOptions } from './payload.js'
export { formatReport } from './report.js'
export { forgedCredentials, runCredentialCheck, type CredentialTarget, type Forgery, type TargetResponse } from './credentials.js'
export { checkAdminExposure, checkClientSecrets, checkCookies, checkCors, checkGraphql, checkHeaders, checkOpenRedirects, checkUploads, scanUserContent, CONTENT_PATTERNS, SECRET_PATTERNS, type Answer, type Ask } from './checks.js'
export { fingerprint, recordFindings, retest, runSuite, whitehat, type Suite, type WhitehatOptions } from './alerts.js'

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

/** Someone the site is probed as: a role name and the user record (null when signed out). */
export type Viewer = { role: string; user: unknown | null }

/** One way to read data, e.g. "REST GET /api/animals/:id?depth=1". Returns anything that serialises to JSON. */
export type ReadPath = { name: string; read: (viewer: Viewer) => Promise<unknown> }

/**
 * A record only some roles may see. Its `marker` (a unique string planted in it, e.g. its id) must never
 * appear on any read path for any other role.
 */
export type Canary = {
  id: string
  title: string
  marker: string
  visibleTo: string[]
  paths: ReadPath[]
  severity?: Severity
  /** Plain steps to see the leak for yourself. */
  reproduce?: string
}

/**
 * Something a role must not be able to do. `attempt` performs it as the viewer and resolves if it was
 * allowed; a refusal throws. `leaks`, if given, also fails the check when the refusal's message says
 * something it mustn't (e.g. that a private record exists).
 */
export type ForbiddenWrite = {
  id: string
  title: string
  role: string
  attempt: (viewer: Viewer) => Promise<unknown>
  leaks?: RegExp
  severity?: Severity
  reproduce?: string
}

export type Finding = {
  check: string
  title: string
  status: 'fail' | 'pass' | 'not-checked'
  severity: Severity
  role: string
  path?: string
  /** How it was found, in plain words. */
  how: string
  reproduce?: string
}

const text = (v: unknown) => {
  try {
    return typeof v === 'string' ? v : JSON.stringify(v) ?? ''
  } catch {
    return String(v)
  }
}

/** Runs every canary on every read path as every viewer, and every forbidden write. */
export async function runAccessCheck(input: { viewers: Viewer[]; canaries?: Canary[]; writes?: ForbiddenWrite[] }): Promise<Finding[]> {
  const findings: Finding[] = []
  for (const c of input.canaries ?? []) {
    if (!c.marker || c.marker.length < 6) {
      findings.push({ check: c.id, title: c.title, status: 'not-checked', severity: c.severity ?? 'high', role: '*', how: 'The canary’s marker is missing or too short to search for reliably.' })
      continue
    }
    for (const viewer of input.viewers) {
      if (c.visibleTo.includes(viewer.role)) continue
      for (const path of c.paths) {
        let body: unknown
        try {
          body = await path.read(viewer)
        } catch (error) {
          findings.push({ check: c.id, title: c.title, status: 'not-checked', severity: c.severity ?? 'high', role: viewer.role, path: path.name, how: `The read failed, so it couldn't be checked: ${(error as Error).message}`.slice(0, 300) })
          continue
        }
        const leaked = text(body).includes(c.marker)
        findings.push({
          check: c.id,
          title: c.title,
          status: leaked ? 'fail' : 'pass',
          severity: c.severity ?? 'high',
          role: viewer.role,
          path: path.name,
          how: leaked ? `As ${viewer.role}, ${path.name} returned the canary's marker, which this role must never see.` : `As ${viewer.role}, ${path.name} didn't return the marker.`,
          reproduce: leaked ? c.reproduce : undefined,
        })
      }
    }
  }
  for (const w of input.writes ?? []) {
    const viewer = input.viewers.find((v) => v.role === w.role)
    if (!viewer) {
      findings.push({ check: w.id, title: w.title, status: 'not-checked', severity: w.severity ?? 'high', role: w.role, how: `No viewer for role "${w.role}", so it couldn't be tried.` })
      continue
    }
    try {
      await w.attempt(viewer)
      findings.push({ check: w.id, title: w.title, status: 'fail', severity: w.severity ?? 'high', role: w.role, how: `As ${w.role}, this was allowed; the site's rules say it must be refused.`, reproduce: w.reproduce })
    } catch (error) {
      const said = text((error as { data?: unknown }).data ?? '') + ' ' + text((error as Error).message ?? '')
      const leak = w.leaks?.test(said)
      findings.push({
        check: w.id,
        title: w.title,
        status: leak ? 'fail' : 'pass',
        severity: w.severity ?? 'high',
        role: w.role,
        how: leak ? `As ${w.role}, it was refused, but the refusal said something it mustn't (matched ${w.leaks}).` : `As ${w.role}, it was refused without saying anything it mustn't.`,
        reproduce: leak ? w.reproduce : undefined,
      })
    }
  }
  const rank = (s: Severity) => SEVERITIES.indexOf(s)
  const order = { fail: 0, 'not-checked': 1, pass: 2 } as const
  return findings.sort((a, b) => order[a.status] - order[b.status] || rank(a.severity) - rank(b.severity) || a.check.localeCompare(b.check))
}
