import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react'
import { AlertTriangle, CheckCircle2, Info, X } from 'lucide-react'

type Kind = 'success' | 'error' | 'info'
interface T { id: number; kind: Kind; text: string }
interface ToastCtx { push: (kind: Kind, text: string) => void }
const Ctx = createContext<ToastCtx | null>(null)
let seq = 0

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<T[]>([])
  const remove = useCallback((id: number) => setItems((s) => s.filter((i) => i.id !== id)), [])
  const push = useCallback((kind: Kind, text: string) => {
    const id = ++seq
    setItems((s) => [...s.slice(-3), { id, kind, text }])
    setTimeout(() => remove(id), kind === 'error' ? 7000 : 4500)
  }, [remove])
  const value = useMemo(() => ({ push }), [push])

  const icon = { success: CheckCircle2, error: AlertTriangle, info: Info }
  const color = { success: 'text-em', error: 'text-bad', info: 'text-cy' }
  return (
    <Ctx.Provider value={value}>
      {children}
      <div className="pointer-events-none fixed bottom-5 right-5 z-[100] flex w-[22rem] max-w-[calc(100vw-2rem)] flex-col gap-2" aria-live="polite">
        {items.map((t) => {
          const Icon = icon[t.kind]
          return (
            <div key={t.id} role="status" className="pointer-events-auto card flex animate-fade-up items-start gap-3 border-line2 bg-panel2 p-3.5 shadow-2xl">
              <Icon className={`mt-0.5 h-5 w-5 shrink-0 ${color[t.kind]}`} />
              <p className="flex-1 text-sm leading-snug text-ink">{t.text}</p>
              <button onClick={() => remove(t.id)} aria-label="Dismiss" className="text-dim hover:text-ink"><X className="h-4 w-4" /></button>
            </div>
          )
        })}
      </div>
    </Ctx.Provider>
  )
}

export function useToast(): ToastCtx {
  const c = useContext(Ctx)
  if (!c) throw new Error('useToast outside provider')
  return c
}
