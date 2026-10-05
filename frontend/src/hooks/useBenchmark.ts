import { useCallback, useState } from 'react'
import { api } from '../services/api'
import type { Benchmark } from '../types'
import { useAsync } from './useAsync'

export function useBenchmark() {
  const hist = useAsync(api.benchmarks)
  const [running, setRunning] = useState(false)
  const [runError, setRunError] = useState<string | null>(null)
  const latest: Benchmark | null = hist.data?.[0] ?? null

  const run = useCallback(async (sizes: number[], iterations: number) => {
    setRunning(true); setRunError(null)
    try {
      const b = await api.runBenchmark(sizes, iterations)
      hist.setData((d) => [b, ...(d ?? [])])
    } catch (e) { setRunError(e instanceof Error ? e.message : 'Benchmark failed.') }
    finally { setRunning(false) }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return { latest, loading: hist.loading, error: hist.error, running, runError, run, reload: hist.reload }
}
