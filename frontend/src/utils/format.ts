export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  const u = ['KB', 'MB', 'GB']
  let i = -1
  do { n /= 1024; i++ } while (n >= 1024 && i < u.length - 1)
  return `${n.toFixed(n >= 100 ? 0 : n >= 10 ? 1 : 2)} ${u[i]}`
}

export function formatMs(ms: number): string {
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)} s`
  if (ms >= 10) return `${ms.toFixed(1)} ms`
  return `${ms.toFixed(2)} ms`
}

export function timeAgo(iso: string): string {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000)
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.floor(s / 60)} min ago`
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`
  return new Date(iso).toLocaleDateString()
}

export const fullDate = (iso: string) => new Date(iso).toLocaleString()

export function shortFp(fp: string): string {
  return `${fp.slice(0, 8)}…${fp.slice(-6)}`
}

export function prettyFp(fp: string): string {
  return fp.slice(0, 32).replace(/(.{4})(?=.)/g, '$1 ')
}

export function passwordIssues(pw: string): string[] {
  const out: string[] = []
  if (pw.length < 10) out.push('At least 10 characters')
  if (!/[a-z]/.test(pw)) out.push('A lower-case letter')
  if (!/[A-Z]/.test(pw)) out.push('An upper-case letter')
  if (!/\d/.test(pw)) out.push('A digit')
  return out
}

export function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export const EVENT_LABELS: Record<string, string> = {
  USER_REGISTERED: 'Account created', LOGIN_SUCCESS: 'Signed in', LOGIN_FAILED: 'Failed sign-in attempt', LOGOUT: 'Signed out',
  KEYS_GENERATED: 'Post-quantum keys generated', FILE_UPLOADED: 'File uploaded', FILE_ENCRYPTED: 'File encrypted',
  FILE_SHARED: 'File shared', FILE_RECEIVED: 'File received', SIGNATURE_VERIFIED: 'Signature verified',
  SIGNATURE_INVALID: 'Invalid signature detected', INTEGRITY_CHECK_FAILED: 'Integrity check failed',
  FILE_DECRYPTED: 'File decrypted', FILE_DOWNLOADED: 'File downloaded', BENCHMARK_RUN: 'Benchmark executed',
}
