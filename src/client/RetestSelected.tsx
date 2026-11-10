'use client'

import { useConfig, useSelection } from '@payloadcms/ui'
import { useRouter } from 'next/navigation.js'
import { useEffect, useState } from 'react'

const KEY = 'whitehat-retest-result'

/**
 * Above the Security alerts list: "Retest selected" runs again only the checks behind the selected alerts,
 * then reloads the list. Snoozing several at once uses the admin's own Edit on a selection.
 */
export function RetestSelected() {
  const { config } = useConfig()
  const { selectedIDs, count } = useSelection()
  const router = useRouter()
  const [busy, setBusy] = useState(false)
  const [said, setSaid] = useState('')
  // The list reloads after a retest, which remounts this button: keep the result across that, and announce it.
  useEffect(() => {
    try {
      const kept = sessionStorage.getItem(KEY)
      if (kept) {
        sessionStorage.removeItem(KEY)
        setSaid(kept)
      }
    } catch {
      // Storage may be off: the list itself still shows the new statuses.
    }
  }, [])

  async function retest() {
    setBusy(true)
    setSaid('')
    try {
      const res = await fetch(`${config.serverURL ?? ''}${config.routes.api}/whitehat/retest`, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ids: selectedIDs }) })
      const out = (await res.json()) as { alerts?: { status: string }[]; errors?: { message: string }[] }
      if (!res.ok) setSaid(out.errors?.[0]?.message ?? 'That didn’t work.')
      else {
        const by = (out.alerts ?? []).reduce<Record<string, number>>((c, a) => ({ ...c, [a.status]: (c[a.status] ?? 0) + 1 }), {})
        const msg = `Checked again: ${Object.entries(by).map(([s, n]) => `${n} ${s}`).join(', ') || 'nothing changed'}.`
        setSaid(msg)
        try {
          sessionStorage.setItem(KEY, msg)
        } catch {
          // ignore
        }
        router.refresh()
      }
    } catch {
      setSaid('Couldn’t reach the site. Nothing was changed.')
    }
    setBusy(false)
  }

  return (
    <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap', margin: '0 0 var(--base, 20px)' }}>
      <button type="button" className="btn btn--style-secondary btn--size-small" style={{ margin: 0 }} disabled={busy || count === 0} onClick={() => void retest()}>
        {busy ? 'Checking…' : count ? `Retest selected (${count})` : 'Retest selected'}
      </button>
      <span role="status" aria-live="polite" style={{ color: 'var(--theme-elevation-650)' }}>
        {said || (count ? '' : 'Select alerts to check them again, or to snooze them with Edit.')}
      </span>
    </div>
  )
}
