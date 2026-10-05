import { useState, type FormEvent } from 'react'
import { Link, Navigate, useNavigate } from 'react-router-dom'
import { Atom, Fingerprint, Lock, ShieldCheck } from 'lucide-react'
import { useAuth } from '../context/AuthContext'
import { useToast } from '../context/ToastContext'
import { Logo } from '../components/Layout'
import { Spinner } from '../components/ui'
import { api } from '../services/api'
import { passwordIssues } from '../utils/format'

export default function AuthPage({ mode }: { mode: 'login' | 'register' }) {
  const { user, signIn } = useAuth()
  const nav = useNavigate()
  const toast = useToast()
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const reg = mode === 'register'

  if (user) return <Navigate to="/" replace />
  const issues = reg ? passwordIssues(password) : []

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      const t = reg ? await api.register(username, email, password) : await api.login(username, password)
      signIn(t)
      if (reg) toast.push('success', 'Account created. Your ML-KEM and ML-DSA key pairs were generated.')
      nav('/')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed.')
    } finally { setBusy(false) }
  }

  const demo = (u: string) => { setUsername(u); setPassword('Demo-Passw0rd!') }

  return (
    <div className="relative grid min-h-full lg:grid-cols-2">
      <section className="relative hidden overflow-hidden border-r border-line bg-bg2/60 p-12 lg:flex lg:flex-col lg:justify-between">
        <div className="grid-bg absolute inset-0" />
        <div className="absolute -left-24 top-1/3 h-80 w-80 rounded-full bg-cy/10 blur-3xl" />
        <div className="absolute -right-10 bottom-10 h-72 w-72 rounded-full bg-em/10 blur-3xl" />
        <div className="relative"><Logo size="lg" /></div>
        <div className="relative max-w-lg animate-fade-up">
          <h2 className="font-display text-5xl font-semibold leading-[1.05] tracking-tight">
            Share files today.<br /><span className="bg-gradient-to-r from-cy to-em bg-clip-text text-transparent">Safe from tomorrow's quantum computers.</span>
          </h2>
          <p className="mt-5 text-mute">A hybrid design: lattice-based <b className="text-ink">ML-KEM-768</b> establishes keys, <b className="text-ink">AES-256-GCM</b> protects the data and <b className="text-ink">ML-DSA-65</b> proves who sent it.</p>
          <ul className="mt-8 space-y-3 text-sm">
            {[[Atom, 'NIST FIPS 203 / 204 post-quantum standards'], [Lock, 'Authenticated encryption, tamper detection built in'], [Fingerprint, 'Sender signatures on every package']].map(([I, t], i) => {
              const Icon = I as typeof Atom
              return <li key={i} className="flex items-center gap-3 text-mute"><span className="grid h-8 w-8 place-items-center rounded-lg border border-line2 bg-panel text-cy"><Icon className="h-4 w-4" /></span>{t as string}</li>
            })}
          </ul>
        </div>
        <p className="relative text-xs text-dim">Academic cryptography project · not independently audited</p>
      </section>

      <section className="grid place-items-center p-6">
        <div className="w-full max-w-md animate-fade-up">
          <div className="mb-8 lg:hidden"><Logo /></div>
          <h1 className="font-display text-3xl font-semibold">{reg ? 'Create your account' : 'Welcome back'}</h1>
          <p className="mt-1.5 text-sm text-mute">{reg ? 'Post-quantum key pairs are generated for you automatically.' : 'Sign in to your secure workspace.'}</p>

          <form onSubmit={submit} className="mt-8 space-y-4" noValidate>
            <div>
              <label className="label" htmlFor="username">{reg ? 'Username' : 'Username or email'}</label>
              <input id="username" className="input" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required minLength={3} placeholder="alice" />
            </div>
            {reg && (
              <div>
                <label className="label" htmlFor="email">Email</label>
                <input id="email" type="email" className="input" autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} required placeholder="alice@example.com" />
              </div>
            )}
            <div>
              <label className="label" htmlFor="password">Password</label>
              <input id="password" type="password" className="input" autoComplete={reg ? 'new-password' : 'current-password'} value={password} onChange={(e) => setPassword(e.target.value)} required placeholder="••••••••••" />
              {reg && password && (
                <ul className="mt-2 flex flex-wrap gap-1.5">
                  {['At least 10 characters', 'A lower-case letter', 'An upper-case letter', 'A digit'].map((r) => (
                    <li key={r} className={`rounded-md border px-2 py-0.5 text-[11px] ${issues.includes(r) ? 'border-line2 text-dim' : 'border-em/30 bg-em/10 text-em'}`}>{r}</li>
                  ))}
                </ul>
              )}
            </div>
            {error && <p role="alert" className="rounded-xl border border-bad/30 bg-bad/10 px-3.5 py-2.5 text-sm text-bad">{error}</p>}
            <button id="auth-submit" className="btn-primary w-full !py-3" disabled={busy || !username || !password || (reg && (!email || issues.length > 0))}>
              {busy ? <Spinner /> : <ShieldCheck className="h-4 w-4" />} {reg ? 'Create account' : 'Sign in'}
            </button>
          </form>

          <p className="mt-6 text-center text-sm text-mute">
            {reg ? 'Already registered?' : 'New here?'}{' '}
            <Link className="font-medium text-cy hover:underline" to={reg ? '/login' : '/register'}>{reg ? 'Sign in' : 'Create an account'}</Link>
          </p>

          {!reg && (
            <div className="mt-8 rounded-xl border border-line bg-panel/60 p-4">
              <p className="text-xs font-semibold uppercase tracking-wider text-dim">Demo accounts</p>
              <div className="mt-2 flex gap-2">
                {['alice', 'bob', 'carol'].map((u) => <button key={u} type="button" className="btn-ghost !px-3 !py-1.5 text-xs" onClick={() => demo(u)}>{u}</button>)}
              </div>
              <p className="mt-2 text-xs text-dim">Click to fill credentials (password <span className="mono text-mute">Demo-Passw0rd!</span>). Development only.</p>
            </div>
          )}
        </div>
      </section>
    </div>
  )
}
