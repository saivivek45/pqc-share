import { useState, type ReactNode } from 'react'
import { AlertTriangle, Check, Copy, Loader2, RefreshCw, ShieldAlert, ShieldCheck, Lock, FileCheck2, FileX2 } from 'lucide-react'
import type { ShareStatus } from '../types'
import { shortFp } from '../utils/format'

export function PageHeader({ title, subtitle, children }: { title: string; subtitle?: string; children?: ReactNode }) {
  return (
    <div className="mb-8 flex flex-wrap items-end justify-between gap-4 animate-fade-up">
      <div>
        <h1 className="font-display text-3xl font-semibold tracking-tight text-ink">{title}</h1>
        {subtitle && <p className="mt-1.5 max-w-2xl text-sm text-mute">{subtitle}</p>}
      </div>
      {children}
    </div>
  )
}

export function Spinner({ className = 'h-4 w-4' }: { className?: string }) {
  return <Loader2 className={`${className} animate-spin`} aria-label="Loading" />
}

export function Skeleton({ className = '' }: { className?: string }) {
  return <div className={`skeleton ${className}`} />
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="card flex flex-col items-center gap-3 border-bad/30 p-10 text-center">
      <AlertTriangle className="h-8 w-8 text-bad" />
      <p className="max-w-md text-sm text-mute">{message}</p>
      {onRetry && <button className="btn-ghost" onClick={onRetry}><RefreshCw className="h-4 w-4" /> Retry</button>}
    </div>
  )
}

export function EmptyState({ icon, title, hint, action }: { icon: ReactNode; title: string; hint?: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-3 px-6 py-14 text-center">
      <div className="grid h-14 w-14 place-items-center rounded-2xl border border-line2 bg-panel2 text-cy">{icon}</div>
      <p className="font-display text-lg text-ink">{title}</p>
      {hint && <p className="max-w-sm text-sm text-mute">{hint}</p>}
      {action}
    </div>
  )
}

const STATUS: Record<ShareStatus, { label: string; cls: string; Icon: typeof Lock }> = {
  ENCRYPTED: { label: 'Encrypted', cls: 'border-cy/30 bg-cy/10 text-cy', Icon: Lock },
  VERIFIED: { label: 'Signature verified', cls: 'border-vio/30 bg-vio/10 text-vio', Icon: ShieldCheck },
  DECRYPTED: { label: 'Decrypted', cls: 'border-em/30 bg-em/10 text-em', Icon: FileCheck2 },
  INTEGRITY_FAILED: { label: 'Integrity failed', cls: 'border-bad/40 bg-bad/10 text-bad', Icon: FileX2 },
}

export function StatusBadge({ status }: { status: ShareStatus }) {
  const s = STATUS[status]
  return (
    <span className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2.5 py-1 text-xs font-medium ${s.cls}`}>
      <s.Icon className="h-3.5 w-3.5" /> {s.label}
    </span>
  )
}

export function Pill({ children, tone = 'cy' }: { children: ReactNode; tone?: 'cy' | 'em' | 'vio' | 'warn' | 'mute' }) {
  const t = {
    cy: 'border-cy/30 bg-cy/10 text-cy', em: 'border-em/30 bg-em/10 text-em', vio: 'border-vio/30 bg-vio/10 text-vio',
    warn: 'border-warn/30 bg-warn/10 text-warn', mute: 'border-line2 bg-panel2 text-mute',
  }[tone]
  return <span className={`mono inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] ${t}`}>{children}</span>
}

export function Fingerprint({ value, full = false }: { value: string; full?: boolean }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      type="button"
      title="Copy fingerprint"
      onClick={() => { void navigator.clipboard?.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1400) }}
      className="mono group inline-flex items-center gap-1.5 rounded-md border border-line bg-bg2 px-2 py-1 text-[11px] text-mute transition hover:border-cy/40 hover:text-ink"
    >
      <span className={full ? 'break-all text-left' : ''}>{full ? value : shortFp(value)}</span>
      {copied ? <Check className="h-3 w-3 shrink-0 text-em" /> : <Copy className="h-3 w-3 shrink-0 opacity-50 group-hover:opacity-100" />}
    </button>
  )
}

export function StatCard({ label, value, icon, tone = 'cy', hint }: { label: string; value: ReactNode; icon: ReactNode; tone?: 'cy' | 'em' | 'bad' | 'vio'; hint?: string }) {
  const c = { cy: 'text-cy bg-cy/10', em: 'text-em bg-em/10', bad: 'text-bad bg-bad/10', vio: 'text-vio bg-vio/10' }[tone]
  return (
    <div className="card card-hover p-5 animate-fade-up">
      <div className="flex items-start justify-between">
        <p className="text-xs font-medium uppercase tracking-wider text-mute">{label}</p>
        <div className={`grid h-9 w-9 place-items-center rounded-xl ${c}`}>{icon}</div>
      </div>
      <p className="mt-3 font-display text-4xl font-semibold tabular-nums">{value}</p>
      {hint && <p className="mt-1 text-xs text-dim">{hint}</p>}
    </div>
  )
}

export function Modal({ open, onClose, title, children }: { open: boolean; onClose: () => void; title: string; children: ReactNode }) {
  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 grid place-items-center p-4" role="dialog" aria-modal="true" aria-label={title}>
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div className="card relative w-full max-w-lg animate-fade-up border-line2 bg-panel p-6">
        <h2 className="font-display text-xl font-semibold">{title}</h2>
        <div className="mt-4">{children}</div>
      </div>
    </div>
  )
}

export function Callout({ tone, title, children }: { tone: 'good' | 'bad' | 'info'; title: string; children?: ReactNode }) {
  const c = { good: 'border-em/30 bg-em/5 text-em', bad: 'border-bad/40 bg-bad/5 text-bad', info: 'border-cy/30 bg-cy/5 text-cy' }[tone]
  const Icon = tone === 'bad' ? ShieldAlert : tone === 'good' ? ShieldCheck : AlertTriangle
  return (
    <div role={tone === 'bad' ? 'alert' : 'status'} className={`flex gap-3 rounded-xl border p-4 ${c}`}>
      <Icon className="mt-0.5 h-5 w-5 shrink-0" />
      <div className="text-sm">
        <p className="font-semibold">{title}</p>
        {children && <div className="mt-1 text-mute">{children}</div>}
      </div>
    </div>
  )
}
