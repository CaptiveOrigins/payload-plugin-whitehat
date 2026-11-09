import type { Finding } from './index.js'

/** A plain report: failures first by severity, then what couldn't be checked, then a count of passes. */
export function formatReport(findings: Finding[]): string {
  const fails = findings.filter((f) => f.status === 'fail')
  const unchecked = findings.filter((f) => f.status === 'not-checked')
  const passes = findings.filter((f) => f.status === 'pass').length
  const line = (f: Finding) => `- [${f.severity.toUpperCase()}] ${f.title} (${f.check}) as ${f.role}${f.path ? `, ${f.path}` : ''}\n  ${f.how}${f.reproduce ? `\n  To reproduce: ${f.reproduce}` : ''}`
  return [
    `Whitehat: ${fails.length} found, ${unchecked.length} not checked, ${passes} passed.`,
    ...(fails.length ? ['', 'Found:', ...fails.map(line)] : []),
    ...(unchecked.length ? ['', 'Not checked (treat as unknown, not safe):', ...unchecked.map(line)] : []),
  ].join('\n')
}
