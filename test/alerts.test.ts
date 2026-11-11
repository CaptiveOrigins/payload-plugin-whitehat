import { mongooseAdapter } from '@payloadcms/db-mongodb'
import { MongoMemoryReplSet } from 'mongodb-memory-server'
import { buildConfig, getPayload, type Payload } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { fingerprint, recordFindings, retest, runSuite, scanUserContent, whitehat, type Finding, type WhitehatOptions } from '../src/index.js'

/** A made-up site with one admin and one member; suites return whatever the test sets. */
let payload: Payload
let mongo: MongoMemoryReplSet
let admin: Record<string, unknown>
let member: Record<string, unknown>
const results: Record<string, Finding[] | Error> = {}
const told: string[] = []
const suite = (name: string) => async () => {
  const r = results[name]
  if (r instanceof Error) throw r
  return r ?? []
}
const opts: WhitehatOptions = {
  suites: { access: suite('access'), headers: suite('headers'), content: suite('content') },
  access: (req) => (req.user as { role?: string } | null)?.role === 'admin',
  onCritical: (alerts) => void told.push(...alerts.map((a) => a.check)),
}
const fail = (check: string, severity: Finding['severity'] = 'high', status: Finding['status'] = 'fail'): Finding => ({ check, title: check, severity, status, role: 'member', path: 'GET /api/x', how: 'made up' })
const pass = (check: string): Finding => ({ ...fail(check), status: 'pass' })
const alerts = async () => (await payload.find({ collection: 'whitehat-alerts' as never, limit: 100, depth: 0, overrideAccess: true, sort: 'check' })).docs as unknown as Record<string, unknown>[]

beforeAll(async () => {
  mongo = await MongoMemoryReplSet.create({ replSet: { count: 1, storageEngine: 'wiredTiger' } })
  payload = await getPayload({
    config: await buildConfig({
      secret: 'test-secret-not-for-production',
      telemetry: false,
      typescript: { autoGenerate: false },
      db: mongooseAdapter({ url: mongo.getUri('whitehat'), ensureIndexes: true }),
      collections: [{ slug: 'users', auth: true, fields: [{ name: 'role', type: 'text' }] }],
      plugins: [whitehat(opts)],
    }),
  })
  admin = { ...(await payload.create({ collection: 'users', data: { email: 'admin@example.invalid', password: 'correct-horse-battery', role: 'admin' } as never })), collection: 'users' }
  member = { ...(await payload.create({ collection: 'users', data: { email: 'member@example.invalid', password: 'correct-horse-battery', role: 'member' } as never })), collection: 'users' }
}, 120_000)

afterAll(async () => {
  await payload?.destroy()
  await mongo?.stop()
})

describe('alerts', () => {
  it('opens one alert per finding, updates it on the next run, resolves it when it passes, and never stores a plain pass', async () => {
    results.access = [fail('private-parent'), fail('loop-answer', 'medium'), pass('never-failed')]
    expect(await runSuite(payload, opts, 'access')).toMatchObject({ opened: 2, updated: 0, resolved: 0 })
    expect((await runSuite(payload, opts, 'access')).updated).toBe(2)
    results.access = [pass('private-parent'), fail('loop-answer', 'medium')]
    expect((await runSuite(payload, opts, 'access')).resolved).toBe(1)
    const a = await alerts()
    expect(a.map((x) => [x.check, x.status])).toEqual([['loop-answer', 'open'], ['private-parent', 'resolved']])
    expect(a.find((x) => x.check === 'never-failed')).toBeUndefined()
    expect(a[0]!.fingerprint).toBe(fingerprint(fail('loop-answer')))
  })

  it('a suite that throws is recorded as not checked, never as passed', async () => {
    results.headers = new Error('site unreachable')
    await runSuite(payload, opts, 'headers')
    expect((await alerts()).find((x) => x.check === 'suite:headers')).toMatchObject({ status: 'open', lastResult: 'not-checked' })
  })

  it('tells someone about a new critical alert once, not on every run', async () => {
    told.length = 0
    results.headers = [fail('client-secrets', 'critical')]
    await runSuite(payload, opts, 'headers')
    await runSuite(payload, opts, 'headers')
    expect(told).toEqual(['client-secrets'])
  })
})

describe('bulk snooze', () => {
  it('snoozes several at once with a reason and an end date, and keeps them snoozed through later runs until it ends', async () => {
    results.access = [fail('a1'), fail('a2'), fail('a3', 'low')]
    await runSuite(payload, opts, 'access')
    const until = new Date(Date.now() + 7 * 86_400_000).toISOString()
    // The admin's bulk Edit: one update over the selection.
    await payload.update({ collection: 'whitehat-alerts' as never, where: { check: { in: ['a1', 'a2'] } }, data: { snoozedUntil: until, snoozeReason: 'Waiting on the upstream fix' } as never, user: admin as never, overrideAccess: false })
    await runSuite(payload, opts, 'access')
    const by = Object.fromEntries((await alerts()).map((x) => [x.check, x]))
    expect([by.a1!.status, by.a2!.status, by.a3!.status]).toEqual(['snoozed', 'snoozed', 'open'])
    expect(by.a1).toMatchObject({ snoozeReason: 'Waiting on the upstream fix', snoozedBy: 'admin@example.invalid' })
  })

  it('refuses a snooze without a reason, in the past, or longer than the limit', async () => {
    const one = String((await alerts()).find((x) => x.check === 'a3')!.id)
    const snooze = (data: object) => payload.update({ collection: 'whitehat-alerts' as never, id: one, data: data as never, user: admin as never, overrideAccess: false })
    await expect(snooze({ snoozedUntil: new Date(Date.now() + 86_400_000).toISOString() })).rejects.toThrow(/reason/)
    await expect(snooze({ snoozedUntil: new Date(Date.now() - 86_400_000).toISOString(), snoozeReason: 'x' })).rejects.toThrow(/future/)
    await expect(snooze({ snoozedUntil: new Date(Date.now() + 200 * 86_400_000).toISOString(), snoozeReason: 'x' })).rejects.toThrow(/at most 90/)
  })

  it('people without access can neither see nor snooze alerts, and nobody can rewrite what was found', async () => {
    await expect(payload.find({ collection: 'whitehat-alerts' as never, user: member as never, overrideAccess: false })).rejects.toThrow(/not allowed/)
    const one = String((await alerts())[0]!.id)
    await expect(payload.update({ collection: 'whitehat-alerts' as never, id: one, data: { snoozedUntil: new Date(Date.now() + 86_400_000).toISOString(), snoozeReason: 'x' } as never, user: member as never, overrideAccess: false })).rejects.toThrow()
    // An admin edit can only touch the snooze: a changed severity or status is ignored.
    await payload.update({ collection: 'whitehat-alerts' as never, id: one, data: { severity: 'info', status: 'resolved', how: 'edited' } as never, user: admin as never, overrideAccess: false })
    const after = (await alerts()).find((x) => String(x.id) === one)!
    expect(after.how).toBe('made up')
    expect(after.severity).not.toBe('info')
  })
})

describe('retest a selection', () => {
  it('runs only the suites behind the selected alerts, and reports where each now stands', async () => {
    const calls: string[] = []
    const counted: WhitehatOptions = { ...opts, suites: { access: async () => (calls.push('access'), [pass('a1'), fail('a2'), fail('a3', 'low')]), headers: async () => (calls.push('headers'), []) } }
    const sel = (await alerts()).filter((x) => ['a1', 'a2'].includes(String(x.check))).map((x) => String(x.id))
    const out = await retest(payload, counted, sel)
    expect(calls).toEqual(['access'])
    expect(out.alerts.map((a) => a.status).sort()).toEqual(['resolved', 'snoozed'])
  })

  it('the endpoint refuses people without access and empty selections', async () => {
    const ep = payload.config.endpoints.find((e) => e.path === '/whitehat/retest')!
    const call = (user: unknown, body: unknown) => ep.handler({ user, payload, json: async () => body } as never) as Promise<Response>
    expect((await call(member, { ids: ['x'] })).status).toBe(403)
    expect((await call(null, { ids: ['x'] })).status).toBe(403)
    expect((await call(admin, { ids: [] })).status).toBe(400)
    expect((await call(admin, { ids: [String((await alerts())[0]!.id)] })).status).toBe(200)
  })
})

describe('only an exact yes from access (2026-11-11)', () => {
  // Each a no: truthy values, objects (one shaped like a query, which must not become the read filter), and errors.
  const noes: [string, () => unknown][] = [
    ['1', () => 1],
    ["'yes'", () => 'yes'],
    ['{}', () => ({})],
    ['a query-shaped object', () => ({ severity: { equals: 'low' } })],
    ['a thrown error', () => {
      throw new Error('directory down')
    }],
    ['a rejected promise', async () => {
      throw new Error('directory down')
    }],
  ]
  /** Runs `body` with the site's `access` answering `answer`, then puts the site's rule back. */
  const answering = async (answer: () => unknown, body: () => Promise<void>) => {
    const before = opts.access
    opts.access = answer as never
    try {
      await body()
    } finally {
      opts.access = before
    }
  }
  const status = (p: Promise<unknown>) => p.then(() => 200, (e: { status?: number }) => e.status ?? 500)
  const ep = () => payload.config.endpoints.find((e) => e.path === '/whitehat/retest')!
  const call = (user: unknown, body: unknown) => ep().handler({ user, payload, json: async () => body } as never) as Promise<Response>

  it('refuses reads, snoozes and retests with 403 for anything but true, never a 500, and changes nothing', async () => {
    const one = (await alerts()).find((x) => x.status === 'open')!
    const id = String(one.id)
    let ran = 0
    const before = opts.suites[String(one.suite)]
    opts.suites[String(one.suite)] = async () => (ran++, [])
    try {
      for (const [label, answer] of noes)
        await answering(answer, async () => {
          expect(await status(payload.find({ collection: 'whitehat-alerts' as never, user: admin as never, overrideAccess: false })), label).toBe(403)
          expect(await status(payload.findByID({ collection: 'whitehat-alerts' as never, id, user: admin as never, overrideAccess: false })), label).toBe(403)
          const snooze = { snoozedUntil: new Date(Date.now() + 86_400_000).toISOString(), snoozeReason: 'not now' }
          expect(await status(payload.update({ collection: 'whitehat-alerts' as never, id, data: snooze as never, user: admin as never, overrideAccess: false })), label).toBe(403)
          expect((await call(admin, { ids: [id] })).status, label).toBe(403)
        })
    } finally {
      opts.suites[String(one.suite)] = before!
    }
    expect(ran).toBe(0)
    const after = (await alerts()).find((x) => String(x.id) === id)!
    expect(after).toMatchObject({ status: one.status, snoozedUntil: one.snoozedUntil ?? null })
  })

  it('lets an exact true read every alert, and refuses someone not signed in even then', async () => {
    await answering(() => true, async () => {
      const all = (await payload.find({ collection: 'whitehat-alerts' as never, user: admin as never, overrideAccess: false, limit: 100 })).totalDocs
      expect(all).toBe((await alerts()).length)
      expect(await status(payload.find({ collection: 'whitehat-alerts' as never, overrideAccess: false }))).toBe(403)
      expect((await call(null, { ids: ['x'] })).status).toBe(403)
    })
  })
})

describe('resolving what’s gone', () => {
  it('resolves an alert a full run no longer reports (a fixed record), but not after a run that reported nothing', async () => {
    const bad = { collection: 'posts', id: 'p1', field: 'body', value: '<script>x()</script>' }
    results.content = scanUserContent([bad, { collection: 'posts', id: 'p2', field: 'body', value: 'fine' }])
    await runSuite(payload, opts, 'content')
    const open = async () => (await alerts()).filter((x) => x.suite === 'content' && x.status === 'open').map((x) => x.check)
    expect(await open()).toEqual(['stored-xss'])
    // A suite that reports nothing confirmed nothing: the alert stays, and the empty run is itself not checked.
    results.content = []
    await runSuite(payload, opts, 'content')
    expect(await open()).toEqual(expect.arrayContaining(['stored-xss', 'suite:content']))
    // The record is cleaned: a full run without it resolves it (and the not-checked one too).
    results.content = scanUserContent([{ ...bad, value: 'cleaned' }])
    const r = await runSuite(payload, opts, 'content')
    expect(r.resolved).toBe(2)
    expect(await open()).toEqual([])
  })

  it('leaves alerts alone when findings come from elsewhere (not a full run)', async () => {
    await recordFindings(payload, opts, 'ci-partial', [fail('one'), fail('two')])
    await recordFindings(payload, opts, 'ci-partial', [fail('one')])
    expect((await alerts()).filter((x) => x.suite === 'ci-partial' && x.status === 'open')).toHaveLength(2)
  })
})

describe('write probes', () => {
  it('refuses to start with a write suite unless allowWriteProbes is on', () => {
    const writer = { run: async () => [], writes: true as const }
    expect(() => whitehat({ ...opts, suites: { probe: writer } })({ collections: [] } as never)).toThrow(/allowWriteProbes/)
    expect(() => whitehat({ ...opts, suites: { probe: writer }, allowWriteProbes: true })({ collections: [] } as never)).not.toThrow()
  })

  it('records a write suite as not checked where write probes are off, without running it', async () => {
    let ran = false
    const o = { ...opts, suites: { probe: { run: async () => ((ran = true), [fail('w')]), writes: true as const } } }
    await runSuite(payload, o, 'probe')
    expect(ran).toBe(false)
    expect((await alerts()).find((x) => x.check === 'suite:probe')).toMatchObject({ lastResult: 'not-checked' })
  })
})

describe('recording directly', () => {
  it('records findings from any source, for example a CI run', async () => {
    const r = await recordFindings(payload, opts, 'ci', [fail('ci-only', 'medium')])
    expect(r.opened).toBe(1)
  })
})
