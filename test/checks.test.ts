import { describe, expect, it } from 'vitest'

import { checkAdminExposure, checkClientSecrets, checkCookies, checkCors, checkGraphql, checkHeaders, checkOpenRedirects, checkUploads, scanUserContent, type Answer, type Ask } from '../src/index.js'

/** A made-up site: answers are chosen per test; nothing leaves the process. */
const site = (answer: (url: string, init?: Parameters<Ask>[1]) => Partial<Answer>): Ask => async (url, init) => ({ status: 200, headers: {}, body: '', ...answer(url, init) })
const statuses = (fs: { check: string; status: string }[]) => Object.fromEntries(fs.map((f) => [f.check, f.status]))

describe('checklist checks', () => {
  it('headers: passes a well-dressed page and names each missing header', async () => {
    const good = site(() => ({ headers: { 'content-security-policy': "default-src 'self'; frame-ancestors 'none'", 'x-content-type-options': 'nosniff', 'referrer-policy': 'strict-origin', 'permissions-policy': 'camera=()', 'strict-transport-security': 'max-age=63072000' } }))
    expect((await checkHeaders(good, 'https://site.example/')).every((f) => f.status === 'pass')).toBe(true)
    const bare = await checkHeaders(site(() => ({})), 'https://site.example/')
    expect(statuses(bare)).toMatchObject({ 'headers-framing': 'fail', 'headers-nosniff': 'fail', 'headers-hsts': 'fail', 'headers-csp': 'fail' })
    expect(bare.find((f) => f.check === 'headers-csp')!.severity).toBe('low')
  })

  it('cookies: flags a session cookie without HttpOnly or Secure, and reports a missing cookie as not checked', async () => {
    const bad = await checkCookies(async () => ({ status: 200, headers: { 'set-cookie': ['payload-token=abc; Path=/; SameSite=Lax'] } }))
    expect(statuses(bad)).toEqual({ 'cookies-httponly': 'fail', 'cookies-samesite': 'pass', 'cookies-secure': 'fail' })
    const good = await checkCookies(async () => ({ status: 200, headers: { 'set-cookie': 'payload-token=abc; Path=/; HttpOnly; Secure; SameSite=Lax' } }))
    expect(good.every((f) => f.status === 'pass')).toBe(true)
    expect((await checkCookies(async () => ({ status: 401, headers: {} })))[0]!.status).toBe('not-checked')
  })

  it('CORS: an echoed unknown origin fails, high with credentials', async () => {
    const echo = site((_, init) => ({ headers: { 'access-control-allow-origin': init?.headers?.origin, 'access-control-allow-credentials': 'true' } }))
    const [f] = await checkCors(echo, 'https://site.example/api/users')
    expect(f).toMatchObject({ status: 'fail', severity: 'high' })
    expect((await checkCors(site(() => ({ headers: { 'access-control-allow-origin': 'https://site.example' } })), 'https://site.example/api'))[0]!.status).toBe('pass')
  })

  it('open redirects: off-site Location fails, on-site passes', async () => {
    const r = site((url) => ({ status: 302, headers: { location: url.includes('next=') ? decodeURIComponent(url.split('next=')[1]!) : '/home' } }))
    const out = await checkOpenRedirects(r, ['https://site.example/login?next=https%3A%2F%2Fevil.example.invalid', 'https://site.example/login?next=%2Faccount'], ['site.example'])
    expect(out.map((f) => f.status)).toEqual(['fail', 'pass'])
  })

  it('GraphQL: introspection fails in production, is only noted elsewhere', async () => {
    const open = site(() => ({ body: '{"data":{"__schema":{"queryType":{"name":"Query"}}}}' }))
    expect((await checkGraphql(open, 'https://site.example/api/graphql', true))[0]!.status).toBe('fail')
    expect((await checkGraphql(open, 'http://localhost/api/graphql', false))[0]).toMatchObject({ status: 'pass', severity: 'info' })
    expect((await checkGraphql(site(() => ({ status: 400, body: '{"errors":[]}' })), 'https://site.example/api/graphql', true))[0]!.status).toBe('pass')
  })

  it('admin exposure: wants noindex, by header or meta tag', async () => {
    expect((await checkAdminExposure(site(() => ({ headers: { 'x-robots-tag': 'noindex, nofollow' } })), 'https://site.example/admin'))[0]!.status).toBe('pass')
    expect((await checkAdminExposure(site(() => ({ body: '<meta name="robots" content="noindex">' })), 'https://site.example/admin'))[0]!.status).toBe('pass')
    expect((await checkAdminExposure(site(() => ({})), 'https://site.example/admin'))[0]!.status).toBe('fail')
  })

  it('a check whose request fails is not checked, never passed', async () => {
    const down: Ask = async () => {
      throw new Error('connection refused')
    }
    for (const out of [await checkHeaders(down, 'https://x.example/'), await checkCors(down, 'https://x.example/'), await checkAdminExposure(down, 'https://x.example/admin')]) expect(out.map((f) => f.status)).toEqual(['not-checked'])
  })

  it('client secrets: finds key shapes without copying them', () => {
    const fake = ['sk', 'live', 'X'.repeat(24)].join('_')
    const out = checkClientSecrets([{ name: 'main.js', text: `var k="${fake}"` }, { name: 'clean.js', text: 'console.log(1)' }])
    expect(out.map((f) => f.status)).toEqual(['fail', 'pass'])
    expect(out[0]!.severity).toBe('critical')
    expect(JSON.stringify(out)).not.toContain(fake)
  })

  it('uploads: flags SVG and unrestricted uploads, passes a tight list', () => {
    const out = checkUploads([
      { slug: 'media', upload: { mimeTypes: ['image/png', 'image/svg+xml'] } },
      { slug: 'files', upload: true },
      { slug: 'photos', upload: { mimeTypes: ['image/jpeg', 'image/png'] } },
      { slug: 'posts' },
    ])
    expect(out.map((f) => [f.path, f.status])).toEqual([['media', 'fail'], ['files', 'fail'], ['photos', 'pass']])
  })

  it('user-written content: flags script, handlers, javascript: and data:text/html, never copies the text', () => {
    const items = [
      { collection: 'posts', id: '1', field: 'body', value: 'Hello <script>steal()</script>' },
      { collection: 'animals', id: '2', field: 'notes', value: '<img src=x onerror="steal()">' },
      { collection: 'links', id: '3', field: 'url', value: 'javascript:alert(1)' },
      { collection: 'links', id: '4', field: 'url', value: 'data:text/html;base64,PHNjcmlwdD4=' },
      { collection: 'posts', id: '5', field: 'body', value: 'A care sheet about javascript-free feeding schedules and onions.' },
    ]
    const out = scanUserContent(items)
    expect(out.map((f) => f.path)).toEqual(['posts/1 · body', 'animals/2 · notes', 'links/3 · url', 'links/4 · url'])
    expect(JSON.stringify(out)).not.toContain('steal()')
  })
})
