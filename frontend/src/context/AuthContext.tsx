import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { api, setUnauthorizedHandler, tokenStore } from '../services/api'
import type { TokenOut, User } from '../types'

interface AuthCtx {
  user: User | null
  loading: boolean
  signIn: (t: TokenOut) => void
  signOut: () => Promise<void>
}
const Ctx = createContext<AuthCtx | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(!!tokenStore.get())

  useEffect(() => {
    setUnauthorizedHandler(() => { tokenStore.clear(); setUser(null) })
    if (!tokenStore.get()) return
    api.me().then(setUser).catch(() => tokenStore.clear()).finally(() => setLoading(false))
  }, [])

  const signIn = useCallback((t: TokenOut) => { tokenStore.set(t.access_token); setUser(t.user) }, [])
  const signOut = useCallback(async () => {
    try { await api.logout() } catch { /* token may already be invalid */ }
    tokenStore.clear()
    setUser(null)
  }, [])

  const value = useMemo(() => ({ user, loading, signIn, signOut }), [user, loading, signIn, signOut])
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useAuth(): AuthCtx {
  const c = useContext(Ctx)
  if (!c) throw new Error('useAuth outside provider')
  return c
}
