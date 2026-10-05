import type {
  AuditEvent, Benchmark, Dashboard, DecryptOut, KeyInfo, Peer, PublicKeys, SecurityInfo, Share, TokenOut,
  UploadOut, User, VerifyOut,
} from '../types'

const BASE = (import.meta.env.VITE_API_URL as string | undefined) ?? 'http://localhost:8000'
const TOKEN_KEY = 'pqshare.token'

export const tokenStore = {
  get: () => sessionStorage.getItem(TOKEN_KEY),
  set: (t: string) => sessionStorage.setItem(TOKEN_KEY, t),
  clear: () => sessionStorage.removeItem(TOKEN_KEY),
}

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) { super(message); this.status = status }
}

let onUnauthorized: () => void = () => {}
export const setUnauthorizedHandler = (fn: () => void) => { onUnauthorized = fn }

function messageFrom(body: unknown, fallback: string): string {
  const d = (body as { detail?: unknown } | null)?.detail
  if (typeof d === 'string') return d
  if (Array.isArray(d) && d[0]?.msg) return String(d[0].msg).replace(/^Value error, /, '')
  return fallback
}

async function raw(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers)
  const t = tokenStore.get()
  if (t) headers.set('Authorization', `Bearer ${t}`)
  let res: Response
  try {
    res = await fetch(BASE + path, { ...init, headers })
  } catch {
    throw new ApiError(0, 'Cannot reach the server. Is the backend running on ' + BASE + '?')
  }
  if (!res.ok) {
    let body: unknown = null
    try { body = await res.json() } catch { /* not json */ }
    if (res.status === 401 && t && !path.startsWith('/auth/login')) onUnauthorized()
    throw new ApiError(res.status, messageFrom(body, `Request failed (${res.status}).`))
  }
  return res
}

async function json<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await raw(path, init)
  return res.status === 204 ? (undefined as T) : ((await res.json()) as T)
}

const post = <T>(path: string, body?: unknown) =>
  json<T>(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) })

export const api = {
  register: (username: string, email: string, password: string) => post<TokenOut>('/auth/register', { username, email, password }),
  login: (username: string, password: string) => post<TokenOut>('/auth/login', { username, password }),
  logout: () => post<void>('/auth/logout'),
  me: () => json<User>('/auth/me'),
  dashboard: () => json<Dashboard>('/dashboard'),
  audit: (limit = 50) => json<AuditEvent[]>(`/audit?limit=${limit}`),
  peers: () => json<Peer[]>('/users'),
  keys: () => json<KeyInfo[]>('/keys'),
  publicKeys: () => json<PublicKeys>('/keys/public'),
  sent: () => json<Share[]>('/files/sent'),
  received: () => json<Share[]>('/files/received'),
  packageInfo: (id: number) => json<Record<string, string | number>>(`/files/${id}/package`),
  upload: (receiverId: number, file: File) => {
    const fd = new FormData()
    fd.append('receiver_id', String(receiverId))
    fd.append('file', file)
    return json<UploadOut>('/files/upload', { method: 'POST', body: fd })
  },
  verify: (id: number) => post<VerifyOut>(`/files/${id}/verify`),
  decrypt: (id: number) => post<DecryptOut>(`/files/${id}/decrypt`),
  forward: (id: number, receiverId: number) => post<UploadOut>(`/files/${id}/share`, { receiver_id: receiverId }),
  download: async (id: number) => {
    const res = await raw(`/files/${id}/download`)
    const cd = res.headers.get('Content-Disposition') ?? ''
    const m = /filename\*=UTF-8''([^;]+)/i.exec(cd)
    return { blob: await res.blob(), filename: m ? decodeURIComponent(m[1]) : 'download.bin' }
  },
  securityInfo: () => json<SecurityInfo>('/security/info'),
  benchmarks: () => json<Benchmark[]>('/benchmarks'),
  runBenchmark: (sizes_mb: number[], iterations: number) => post<Benchmark>('/benchmarks/run', { sizes_mb, iterations }),
}
