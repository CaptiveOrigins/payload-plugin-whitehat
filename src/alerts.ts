import { APIError, type Access, type CollectionConfig, type Config, type Endpoint, type Payload, type PayloadRequest, type Plugin } from 'payload'

import type { Finding } from './index.js'

/**
 * Whitehat's alerts in the site's own database (never in this repo): one alert per finding, kept by a
 * fingerprint (check, role, path), so a re-run updates it instead of adding another.
 *
 * - Fail or not-checked: open, unless it's snoozed and the snooze hasn't ended.
 * - Pass: resolved. A finding that never failed isn't stored.
 * - Snooze several at once with the admin's own bulk Edit: select them, set "Snoozed until" and a reason.
 * - Retest a selection: the "Retest selected" button, or POST /api/whitehat/retest { ids }. Only the suites
 *   behind the selected alerts run, and their results update every alert they touch.
 */
export type Suite = () => Promise<Finding[]>
/** A suite that writes (forbidden-write probes). Refused unless `allowWriteProbes` is on. */
export type WriteSuite = { run: Suite; writes: true }

export type WhitehatOptions = {
  /**
   * The site's checks, by name. Retesting an alert runs the suite that found it. Declare a suite that tries writes
   * as `{ run, writes: true }`: those only run where `allowWriteProbes` is on.
   */
  suites: Record<string, Suite | WriteSuite>
  /**
   * Allow suites that write. Default false, and the plugin refuses to start with a write suite while it's off.
   * Turn it on only where the database is a throwaway test copy: "Retest selected" runs suites inside the site.
   */
  allowWriteProbes?: boolean
  /** Who may see alerts, snooze them and retest. Required: nobody gets in by default. */
  access: (req: PayloadRequest) => boolean | Promise<boolean>
  /** Called with alerts that just opened at critical severity (for example, to tell the owner). */
  onCritical?: (alerts: { id: string; title: string; check: string; how: string }[], req: { payload: Payload }) => Promise<void> | void
  slug?: string
  adminGroup?: string
  /** Longest a snooze may run, in days. Default 90. */
  maxSnoozeDays?: number
}

export const fingerprint = (f: Pick<Finding, 'check' | 'role' | 'path'>) => [f.check, f.role, f.path ?? ''].join(' | ')

const writes = (s: Suite | WriteSuite | undefined): s is WriteSuite => Boolean(s && typeof s === 'object' && s.writes)
const runOf = (s: Suite | WriteSuite) => (writes(s) ? s.run : s)

const DAY = 86_400_000

/** Why a snooze can't be saved, or null: an end in the future within the limit, and a reason. */
function snoozeProblem(until: unknown, reason: unknown, max: number): string | null {
  if (!until) return null
  const t = new Date(String(until)).getTime()
  if (Number.isNaN(t) || t <= Date.now()) return 'Snooze until a date in the future.'
  if (t > Date.now() + max * DAY) return `A snooze can run for at most ${max} days.`
  if (!String(reason ?? '').trim()) return 'Say why it can wait: a snooze needs a reason.'
  return null
}

function alertsCollection(o: WhitehatOptions): CollectionConfig {
  const allowed: Access = async ({ req }) => Boolean(req.user) && (await o.access(req))
  const max = o.maxSnoozeDays ?? 90
  return {
    slug: o.slug ?? 'whitehat-alerts',
    labels: { singular: 'Security alert', plural: 'Security alerts' },
    admin: {
      useAsTitle: 'title',
      group: o.adminGroup,
      defaultColumns: ['title', 'severity', 'status', 'snoozedUntil', 'lastSeen'],
      description: 'Found by Whitehat. To snooze several, select them and use Edit: set "Snoozed until" and a reason. To check again, select them and press Retest selected.',
      components: { beforeListTable: ['@captiveorigins/payload-plugin-whitehat/client#RetestSelected'] },
    },
    access: { read: allowed, update: allowed, create: () => false, delete: () => false },
    fields: [
      { name: 'title', type: 'text', required: true, admin: { readOnly: true } },
      { name: 'severity', type: 'select', required: true, options: ['critical', 'high', 'medium', 'low', 'info'], index: true, admin: { readOnly: true } },
      { name: 'status', type: 'select', required: true, defaultValue: 'open', options: ['open', 'snoozed', 'resolved'], index: true, admin: { readOnly: true, description: 'Set by Whitehat and by snoozing.' } },
      {
        type: 'row',
        fields: [
          {
            name: 'snoozedUntil',
            type: 'date',
            validate: (value: unknown) => snoozeProblem(value, 'x', max) ?? true,
            admin: { width: '40%', description: `Up to ${max} days. Leave empty to un-snooze.` },
          },
          {
            name: 'snoozeReason',
            type: 'text',
            validate: (value: unknown, { siblingData }: { siblingData?: Record<string, unknown> }) => (siblingData?.snoozedUntil && !String(value ?? '').trim() ? 'Say why it can wait: a snooze needs a reason.' : true),
            admin: { width: '60%', description: 'Why it can wait. Required to snooze.' },
          },
        ],
      },
      { name: 'how', label: 'How it was found', type: 'textarea', admin: { readOnly: true } },
      { name: 'reproduce', label: 'To reproduce', type: 'textarea', admin: { readOnly: true } },
      { name: 'check', type: 'text', required: true, index: true, admin: { readOnly: true, position: 'sidebar' } },
      { name: 'role', type: 'text', admin: { readOnly: true, position: 'sidebar' } },
      { name: 'path', type: 'text', admin: { readOnly: true, position: 'sidebar' } },
      { name: 'suite', type: 'text', required: true, admin: { readOnly: true, position: 'sidebar' } },
      { name: 'fingerprint', type: 'text', required: true, unique: true, index: true, admin: { hidden: true } },
      { name: 'lastResult', type: 'select', options: ['fail', 'not-checked', 'pass'], admin: { readOnly: true, position: 'sidebar' } },
      { name: 'firstSeen', type: 'date', admin: { readOnly: true, position: 'sidebar' } },
      { name: 'lastSeen', type: 'date', admin: { readOnly: true, position: 'sidebar' } },
      { name: 'snoozedBy', type: 'text', admin: { readOnly: true, position: 'sidebar' } },
    ],
    hooks: {
      beforeChange: [
        ({ data, originalDoc, req, context }) => {
          if ((context as { whitehat?: boolean })?.whitehat) return data
          // A person editing: only the snooze can change, and a snooze needs a reason and an end within the limit.
          const until = data.snoozedUntil ? new Date(String(data.snoozedUntil)) : null
          if (until) {
            // Shown to the person (bulk Edit validates only the fields it was given, so this is the backstop).
            const problem = snoozeProblem(data.snoozedUntil, data.snoozeReason, max)
            if (problem) throw new APIError(problem, 400, null, true)
            const who = (req.user as { email?: string } | null)?.email ?? 'someone'
            return { ...originalDoc, snoozedUntil: until.toISOString(), snoozeReason: String(data.snoozeReason).trim().slice(0, 500), snoozedBy: who, status: originalDoc?.status === 'resolved' ? 'resolved' : 'snoozed' }
          }
          return { ...originalDoc, snoozedUntil: null, snoozeReason: null, snoozedBy: null, status: originalDoc?.status === 'resolved' ? 'resolved' : 'open' }
        },
      ],
    },
  }
}

/** Records one suite's findings: updates alerts by fingerprint, opens new ones, resolves ones that now pass. */
/**
 * `complete`: these are everything the suite found on a full run, so its open alerts that aren't among them are
 * resolved ("no longer found"). Leave it off for findings from elsewhere (a partial CI upload, say).
 */
export async function recordFindings(payload: Payload, o: WhitehatOptions, suite: string, findings: Finding[], req?: PayloadRequest, { complete = false }: { complete?: boolean } = {}): Promise<{ opened: number; updated: number; resolved: number; critical: { id: string; title: string; check: string; how: string }[] }> {
  const slug = (o.slug ?? 'whitehat-alerts') as never
  const now = new Date()
  const ctx = { whitehat: true }
  let opened = 0
  let updated = 0
  let resolved = 0
  const critical: { id: string; title: string; check: string; how: string }[] = []
  for (const fnd of findings) {
    const fp = fingerprint(fnd)
    const existing = (await payload.find({ collection: slug, where: { fingerprint: { equals: fp } }, limit: 1, depth: 0, overrideAccess: true })).docs[0] as Record<string, unknown> | undefined
    if (fnd.status === 'pass') {
      if (existing && existing.status !== 'resolved') {
        await payload.update({ collection: slug, id: String(existing.id), data: { status: 'resolved', lastResult: 'pass', lastSeen: now.toISOString(), how: fnd.how, snoozedUntil: null, snoozeReason: null } as never, overrideAccess: true, context: ctx, req })
        resolved++
      }
      continue
    }
    const snoozed = existing?.snoozedUntil && new Date(String(existing.snoozedUntil)).getTime() > now.getTime()
    const data = { title: fnd.title, severity: fnd.severity, check: fnd.check, role: fnd.role, path: fnd.path ?? null, how: fnd.how, reproduce: fnd.reproduce ?? null, suite, lastResult: fnd.status, lastSeen: now.toISOString(), status: snoozed ? 'snoozed' : 'open' }
    if (existing) {
      await payload.update({ collection: slug, id: String(existing.id), data: { ...data, ...(snoozed ? {} : { snoozedUntil: null, snoozeReason: null }) } as never, overrideAccess: true, context: ctx, req })
      updated++
      if (fnd.severity === 'critical' && !snoozed && existing.status !== 'open') critical.push({ id: String(existing.id), title: fnd.title, check: fnd.check, how: fnd.how })
    } else {
      const doc = await payload.create({ collection: slug, data: { ...data, fingerprint: fp, firstSeen: now.toISOString() } as never, overrideAccess: true, context: ctx, req })
      opened++
      if (fnd.severity === 'critical') critical.push({ id: String(doc.id), title: fnd.title, check: fnd.check, how: fnd.how })
    }
  }
  if (complete && findings.length) {
    // A fixed record, a rebuilt bundle, a removed canary: the suite ran in full and didn't report it, so it's gone.
    const seen = new Set(findings.map(fingerprint))
    const { docs } = await payload.find({ collection: slug, where: { and: [{ suite: { equals: suite } }, { status: { not_equals: 'resolved' } }] }, limit: 0, pagination: false, depth: 0, overrideAccess: true })
    for (const d of docs as unknown as { id: string; fingerprint: string }[]) {
      if (seen.has(d.fingerprint)) continue
      await payload.update({ collection: slug, id: String(d.id), data: { status: 'resolved', lastResult: 'pass', lastSeen: now.toISOString(), how: 'No longer found: the suite ran in full and didn’t report it.', snoozedUntil: null, snoozeReason: null } as never, overrideAccess: true, context: ctx, req })
      resolved++
    }
  }
  if (critical.length && o.onCritical) await o.onCritical(critical, { payload })
  return { opened, updated, resolved, critical }
}

/** Runs one suite and records it. A suite that throws is recorded as "not-checked", never as passed. */
export async function runSuite(payload: Payload, o: WhitehatOptions, name: string, req?: PayloadRequest) {
  const suite = o.suites[name]
  if (!suite) throw new Error(`No Whitehat suite called "${name}".`)
  const notChecked = (how: string): Finding[] => [{ check: `suite:${name}`, title: `Suite "${name}" couldn't run`, severity: 'high', status: 'not-checked', role: '*', how: how.slice(0, 300) }]
  if (writes(suite) && !o.allowWriteProbes) return { suite: name, ...(await recordFindings(payload, o, name, notChecked('It tries writes, and write probes are off here (allowWriteProbes). Run it against a throwaway test database.'), req)) }
  let findings: Finding[]
  let complete = false
  try {
    findings = await runOf(suite)()
    complete = findings.length > 0
    // A suite that reports nothing confirmed nothing: its open alerts stay as they are.
    if (!findings.length) findings = notChecked('It finished without reporting anything, so nothing could be confirmed.')
  } catch (error) {
    findings = notChecked(`It failed before finishing: ${(error as Error).message}`)
  }
  return { suite: name, ...(await recordFindings(payload, o, name, findings, req, { complete })) }
}

/** Retests a selection: runs each suite behind the selected alerts once, then reports where each alert stands. */
export async function retest(payload: Payload, o: WhitehatOptions, ids: string[], req?: PayloadRequest) {
  const slug = (o.slug ?? 'whitehat-alerts') as never
  const { docs } = await payload.find({ collection: slug, where: { id: { in: ids.slice(0, 200) } }, limit: 200, depth: 0, overrideAccess: true })
  const suites = [...new Set((docs as unknown as { suite: string }[]).map((d) => d.suite))]
  const runs = []
  for (const s of suites) runs.push(o.suites[s] ? await runSuite(payload, o, s, req) : { suite: s, missing: true })
  const after = (await payload.find({ collection: slug, where: { id: { in: ids.slice(0, 200) } }, limit: 200, depth: 0, overrideAccess: true })).docs as unknown as { id: string; status: string; lastResult: string }[]
  return { runs, alerts: after.map((a) => ({ id: String(a.id), status: a.status, lastResult: a.lastResult })) }
}

/** The plugin: the alerts collection and the retest endpoint. The checks themselves are the site's suites. */
export const whitehat =
  (o: WhitehatOptions): Plugin =>
  (config: Config): Config => {
    const writers = Object.entries(o.suites).filter(([, s]) => writes(s)).map(([n]) => n)
    if (writers.length && !o.allowWriteProbes)
      throw new Error(`whitehat: ${writers.map((n) => `"${n}"`).join(', ')} tries writes, and allowWriteProbes is off. Turn it on only where the database is a throwaway test copy.`)
    const endpoint: Endpoint = {
      path: '/whitehat/retest',
      method: 'post',
      handler: async (req) => {
        if (!req.user || !(await o.access(req))) return Response.json({ errors: [{ message: 'Not allowed.' }] }, { status: 403 })
        const body = (await req.json?.().catch(() => null)) as { ids?: unknown } | null
        const ids = Array.isArray(body?.ids) ? body!.ids.map(String).filter((s) => /^[A-Za-z0-9_-]{1,64}$/.test(s)) : []
        if (!ids.length) return Response.json({ errors: [{ message: 'Choose at least one alert.' }] }, { status: 400 })
        return Response.json(await retest(req.payload, o, ids, req))
      },
    }
    return { ...config, collections: [...(config.collections ?? []), alertsCollection(o)], endpoints: [...(config.endpoints ?? []), endpoint] }
  }
