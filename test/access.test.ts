import { describe, expect, it } from 'vitest'

import { formatReport, runAccessCheck, type Canary, type ForbiddenWrite, type Viewer } from '../src/index.js'

const viewers: Viewer[] = [
  { role: 'signed-out', user: null },
  { role: 'keeper-a', user: { id: 'a' } },
  { role: 'keeper-b', user: { id: 'b' } },
  { role: 'staff', user: { id: 's' } },
]
const PRIVATE_PARENT = 'p0000000000000000000000a'

/**
 * Regression 1 (2026-11-09, a real leak found in a site using a pedigree plugin): reading a public animal
 * returned its private parent's id to anyone, signed out included.
 */
const readLeak = (fixed: boolean): Canary => ({
  id: 'private-parent-id-in-public-read',
  title: 'A private parent’s id appears in a public animal’s read',
  marker: PRIVATE_PARENT,
  visibleTo: ['keeper-b', 'staff'],
  severity: 'high',
  reproduce: 'Signed out, GET the public child animal at depth 0 and look in parentage.parents.',
  paths: [
    { name: 'REST GET /api/animals/child?depth=0', read: async () => ({ id: 'child', parentage: { parents: [{ individual: fixed ? null : PRIVATE_PARENT, role: 'mother', hidden: fixed }] } }) },
    { name: 'GraphQL Animal(child)', read: async () => ({ data: { Animal: { parentage: { parents: [{ individual: fixed ? null : { id: PRIVATE_PARENT } }] } } } }) },
  ],
})

/**
 * Regression 2 (same day): proposing a private animal as a parent was refused, but the refusal said it would
 * make a loop, which told the keeper that the private animal exists and descends from theirs.
 */
const loopLeak = (fixed: boolean): ForbiddenWrite => ({
  id: 'private-parent-loop-answer',
  title: 'Proposing a private animal as a parent reveals whether it descends from yours',
  role: 'keeper-a',
  leaks: /descend|loop/i,
  severity: 'high',
  reproduce: 'As keeper A, PATCH your animal with parentage.parents = [the private animal]; read the error.',
  attempt: async () => {
    throw Object.assign(new Error('The following field is invalid: parentage.parents'), {
      data: { errors: [{ message: fixed ? 'A parent does not exist or you cannot access it.' : 'This parent already descends from the individual; the pedigree would loop.' }] },
    })
  },
})

describe('access check', () => {
  it('catches the private-parent read leak, and passes once it’s fixed', async () => {
    const leaky = await runAccessCheck({ viewers, canaries: [readLeak(false)] })
    expect(leaky.filter((f) => f.status === 'fail').map((f) => `${f.role} ${f.path}`).sort()).toEqual([
      'keeper-a GraphQL Animal(child)',
      'keeper-a REST GET /api/animals/child?depth=0',
      'signed-out GraphQL Animal(child)',
      'signed-out REST GET /api/animals/child?depth=0',
    ])
    const fixed = await runAccessCheck({ viewers, canaries: [readLeak(true)] })
    expect(fixed.every((f) => f.status === 'pass')).toBe(true)
    // Roles allowed to see it aren't probed.
    expect(fixed.some((f) => f.role === 'staff' || f.role === 'keeper-b')).toBe(false)
  })

  it('catches the loop answer in a refusal, and passes once the refusal says nothing', async () => {
    expect((await runAccessCheck({ viewers, writes: [loopLeak(false)] }))[0]).toMatchObject({ status: 'fail', severity: 'high', role: 'keeper-a' })
    expect((await runAccessCheck({ viewers, writes: [loopLeak(true)] }))[0]).toMatchObject({ status: 'pass' })
  })

  it('fails a write that should have been refused', async () => {
    const [f] = await runAccessCheck({ viewers, writes: [{ id: 'w', title: 'Keeper edits another keeper’s animal', role: 'keeper-a', attempt: async () => ({ ok: true }) }] })
    expect(f).toMatchObject({ status: 'fail' })
  })

  it('never reports something it couldn’t check as passed', async () => {
    const broken: Canary = { id: 'c', title: 'Broken path', marker: 'marker-123456', visibleTo: [], paths: [{ name: 'GET /x', read: async () => Promise.reject(new Error('timeout')) }] }
    const findings = await runAccessCheck({ viewers, canaries: [broken, { ...broken, id: 'short', marker: 'x' }], writes: [{ id: 'nobody', title: 'No viewer', role: 'ghost', attempt: async () => null }] })
    expect(findings.every((f) => f.status === 'not-checked')).toBe(true)
    expect(findings.find((f) => f.check === 'c')!.how).toMatch(/timeout/)
  })

  it('puts failures first, worst first, and reports plainly', async () => {
    const findings = await runAccessCheck({
      viewers,
      canaries: [{ ...readLeak(false), id: 'low', severity: 'low' }, readLeak(false)],
      writes: [{ id: 'crit', title: 'Critical', role: 'signed-out', severity: 'critical', attempt: async () => null }],
    })
    expect(findings[0]!.severity).toBe('critical')
    expect(findings.findIndex((f) => f.severity === 'low')).toBeGreaterThan(findings.findIndex((f) => f.check === 'private-parent-id-in-public-read'))
    const report = formatReport(findings)
    expect(report).toMatch(/^Whitehat: \d+ found, 0 not checked, \d+ passed\./)
    expect(report).toContain('[CRITICAL] Critical (crit) as signed-out')
    expect(report).toContain('To reproduce: Signed out, GET the public child animal')
  })
})
