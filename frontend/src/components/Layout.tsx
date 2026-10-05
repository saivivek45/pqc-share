import { useEffect, useRef, useState } from 'react'
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import {
  Activity, Bell, FileDown, FileUp, Gauge, KeyRound, LayoutDashboard, LogOut, Menu, Scale, Send, Settings as Cog,
  ShieldCheck, ShieldHalf, X,
} from 'lucide-react'
import { useAuth } from '../context/AuthContext'
import { api } from '../services/api'
import type { AuditEvent } from '../types'
import { EVENT_LABELS, timeAgo } from '../utils/format'

export function Logo({ size = 'md' }: { size?: 'md' | 'lg' }) {
  const s = size === 'lg' ? 'h-12 w-12' : 'h-9 w-9'
  return (
    <div className="flex items-center gap-3">
      <div className={`${s} grid shrink-0 place-items-center rounded-xl border border-cy/30 bg-bg2`} style={{ boxShadow: '0 0 24px -6px rgb(34 211 238 / .6)' }}>
        <ShieldCheck className={size === 'lg' ? 'h-7 w-7' : 'h-5 w-5'} style={{ stroke: 'url(#lg)' }} />
        <svg width="0" height="0"><defs><linearGradient id="lg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stopColor="#22d3ee" /><stop offset="1" stopColor="#34d399" /></linearGradient></defs></svg>
      </div>
      <div className="leading-tight">
        <p className={`font-display font-semibold tracking-tight ${size === 'lg' ? 'text-2xl' : 'text-lg'}`}>PQC<span className="text-cy">-Share</span></p>
        <p className="text-[10px] uppercase tracking-[.18em] text-dim">Post-quantum secure</p>
      </div>
    </div>
  )
}

const NAV = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/share', label: 'Share a file', icon: FileUp },
  { to: '/received', label: 'Received', icon: FileDown },
  { to: '/sent', label: 'Sent', icon: Send },
  { to: '/keys', label: 'My keys', icon: KeyRound },
  { to: '/security', label: 'Security center', icon: ShieldHalf },
  { to: '/benchmarks', label: 'Benchmarks', icon: Gauge },
  { to: '/comparison', label: 'RSA vs ML-KEM', icon: Scale },
  { to: '/threat-model', label: 'Threat model', icon: Activity },
  { to: '/settings', label: 'Activity & settings', icon: Cog },
]

function Notifications() {
  const [open, setOpen] = useState(false)
  const [items, setItems] = useState<AuditEvent[]>([])
  const ref = useRef<HTMLDivElement>(null)
  const { pathname } = useLocation()

  useEffect(() => { api.audit(8).then(setItems).catch(() => {}) }, [pathname, open])
  useEffect(() => {
    const h = (e: MouseEvent) => { if (!ref.current?.contains(e.target as Node)) setOpen(false) }
    document.addEventListener('mousedown', h)
    return () => document.removeEventListener('mousedown', h)
  }, [])

  const bad = (e: string) => e.includes('FAILED') || e.includes('INVALID')
  return (
    <div ref={ref} className="relative">
      <button onClick={() => setOpen((o) => !o)} aria-label="Notifications" className="btn-ghost relative !p-2.5">
        <Bell className="h-4 w-4" />
        {items.some((i) => bad(i.event)) && <span className="absolute right-1.5 top-1.5 h-2 w-2 rounded-full bg-bad" />}
      </button>
      {open && (
        <div className="card absolute right-0 top-12 z-40 w-80 animate-fade-up border-line2 bg-panel p-2 shadow-2xl">
          <p className="px-3 pb-2 pt-1.5 text-xs font-semibold uppercase tracking-wider text-dim">Recent security events</p>
          {items.length === 0 && <p className="px-3 py-6 text-center text-sm text-mute">Nothing yet.</p>}
          {items.map((i) => (
            <div key={i.id} className="rounded-lg px-3 py-2 hover:bg-panel2">
              <p className={`text-sm ${bad(i.event) ? 'text-bad' : 'text-ink'}`}>{EVENT_LABELS[i.event] ?? i.event}</p>
              <p className="text-xs text-dim">{timeAgo(i.created_at)}{i.detail ? ` · ${i.detail.slice(0, 40)}` : ''}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default function Layout() {
  const { user, signOut } = useAuth()
  const nav = useNavigate()
  const [mobile, setMobile] = useState(false)
  const { pathname } = useLocation()
  useEffect(() => setMobile(false), [pathname])

  const sidebar = (
    <nav className="flex h-full flex-col gap-1 p-4" aria-label="Main">
      <div className="mb-6 px-2 pt-2"><Logo /></div>
      {NAV.map(({ to, label, icon: Icon, end }) => (
        <NavLink key={to} to={to} end={end}
          className={({ isActive }) => `group flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition ${isActive ? 'bg-cy/10 text-cy shadow-[inset_2px_0_0_var(--color-cy)]' : 'text-mute hover:bg-panel2 hover:text-ink'}`}>
          <Icon className="h-[18px] w-[18px]" /> {label}
        </NavLink>
      ))}
      <div className="mt-auto rounded-xl border border-line bg-bg2/60 p-3 text-xs text-dim">
        <p className="mb-1 flex items-center gap-1.5 font-medium text-em"><span className="h-2 w-2 animate-pulse-ring rounded-full bg-em" /> Quantum-resistant</p>
        ML-KEM-768 · ML-DSA-65 · AES-256-GCM
      </div>
    </nav>
  )

  return (
    <div className="flex min-h-full">
      <aside className="sticky top-0 hidden h-screen w-64 shrink-0 border-r border-line bg-bg2/70 backdrop-blur lg:block">{sidebar}</aside>
      {mobile && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <div className="absolute inset-0 bg-black/70" onClick={() => setMobile(false)} />
          <aside className="relative h-full w-72 border-r border-line bg-bg2">{sidebar}</aside>
        </div>
      )}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex items-center justify-between border-b border-line bg-bg/80 px-4 py-3 backdrop-blur-md sm:px-8">
          <button className="btn-ghost !p-2.5 lg:hidden" onClick={() => setMobile((m) => !m)} aria-label="Menu">{mobile ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}</button>
          <div className="hidden text-sm text-mute lg:block">Welcome back, <span className="font-medium text-ink">{user?.username}</span></div>
          <div className="flex items-center gap-3">
            <Notifications />
            <div className="flex items-center gap-2.5 rounded-xl border border-line bg-panel/70 py-1.5 pl-1.5 pr-3">
              <div className="grid h-8 w-8 place-items-center rounded-lg bg-gradient-to-br from-cy to-em font-display text-sm font-bold text-bg">{user?.username[0]?.toUpperCase()}</div>
              <span className="hidden text-sm font-medium sm:inline">{user?.username}</span>
            </div>
            <button className="btn-ghost !p-2.5" aria-label="Sign out" title="Sign out" onClick={async () => { await signOut(); nav('/login') }}><LogOut className="h-4 w-4" /></button>
          </div>
        </header>
        <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-8 sm:px-8"><Outlet /></main>
      </div>
    </div>
  )
}
