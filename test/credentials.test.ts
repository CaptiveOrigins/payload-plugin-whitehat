import { describe, expect, it } from 'vitest'

import { forgedCredentials, runCredentialCheck, type CredentialTarget } from '../src/index.js'

/** A maintenance gate, the way it was on 2026-11-09: anyone with any `payload-token` cookie got through. */
const presenceGate = (verify: boolean): CredentialTarget => ({
  id: 'maintenance-gate-bypass',
  title: 'The maintenance page can be skipped with any session cookie',
  protects: 'courtesy',
  request: async (headers) => {
    const token = /payload-token=([^;]+)/.exec(headers.cookie ?? '')?.[1]
    const valid = token === 'a-real-verified-session'
    const through = verify ? valid : Boolean(token)
    return through ? { status: 200, body: '<h1>Home</h1>' } : { status: 503, body: '<h1>Back soon</h1>' }
  },
})

describe('untrusted credentials', () => {
  it('catches the maintenance gate trusting a cookie by its presence (medium: a courtesy gate)', async () => {
    const found = (await runCredentialCheck({ targets: [presenceGate(false)] })).filter((f) => f.status === 'fail')
    expect(found.map((f) => f.path)).toEqual(['a made-up session cookie', 'a malformed session cookie', 'an expired session token', 'a session token signed by someone else'])
    expect(found.every((f) => f.severity === 'medium')).toBe(true)
    expect(found[0]!.how).toMatch(/HTTP 200 instead of 503/)
  })

  it('passes a gate that verifies the session', async () => {
    const all = await runCredentialCheck({ targets: [presenceGate(true)] })
    expect(all.every((f) => f.status === 'pass')).toBe(true)
  })

  it('rates a bypass of data or an action high, and catches private text leaking', async () => {
    const leaky: CredentialTarget = {
      id: 'role-cookie',
      title: 'An admin list trusts a role cookie',
      protects: 'data',
      secretMarkers: ['secret-record-7f3a'],
      request: async (h) => (/(^|; )role=admin/.test(h.cookie ?? '') ? { status: 200, body: 'secret-record-7f3a' } : { status: 200, body: 'nothing here' }),
    }
    const found = (await runCredentialCheck({ targets: [leaky], forgeries: forgedCredentials({ extraCookies: { role: 'admin' } }) })).filter((f) => f.status === 'fail')
    expect(found).toHaveLength(1)
    expect(found[0]).toMatchObject({ severity: 'high', path: 'a forged role cookie' })
  })

  it('can’t see a bypass when signed-out visitors already get a 200, so says “not checked” unless given text to look for', async () => {
    // A sign-in page served as 200; a forged role cookie gets the admin list, also as 200.
    const page = (markers?: string[]): CredentialTarget => ({
      id: 'admin-list',
      title: 'The admin list',
      protects: 'data',
      ...(markers ? { secretMarkers: markers } : {}),
      request: async (h) => (/(^|; )role=admin/.test(h.cookie ?? '') ? { status: 200, body: 'record-9c1e' } : { status: 200, body: '<form>Sign in</form>' }),
    })
    const forgeries = forgedCredentials({ extraCookies: { role: 'admin' } })
    const blind = await runCredentialCheck({ targets: [page()], forgeries })
    expect(blind.every((f) => f.status === 'not-checked')).toBe(true)
    expect(blind[0]!.how).toMatch(/secretMarkers/)
    const seen = await runCredentialCheck({ targets: [page(['record-9c1e'])], forgeries })
    expect(seen.filter((f) => f.status === 'fail').map((f) => f.path)).toEqual(['a forged role cookie'])
  })

  it('makes forged tokens that look real but aren’t, and never reports a failed request as safe', async () => {
    const tokens = forgedCredentials().map((f) => /payload-token=([^;]+)/.exec(f.headers.cookie ?? '')?.[1]).filter(Boolean) as string[]
    expect(tokens.filter((t) => t.split('.').length === 3 && t.length > 40)).toHaveLength(2)
    const broken: CredentialTarget = { id: 'down', title: 'Down', protects: 'data', request: async () => Promise.reject(new Error('timeout')) }
    expect((await runCredentialCheck({ targets: [broken] }))[0]).toMatchObject({ status: 'not-checked' })
  })
})
