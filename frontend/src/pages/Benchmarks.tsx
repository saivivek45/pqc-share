import { useState } from 'react'
import { Cpu, Play } from 'lucide-react'
import { Bar, BarChart, CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Callout, EmptyState, ErrorState, PageHeader, Skeleton, Spinner } from '../components/ui'
import { useBenchmark } from '../hooks/useBenchmark'
import { formatBytes, formatMs, fullDate } from '../utils/format'
import type { Stat } from '../types'

export const chartTooltip = { contentStyle: { background: '#0e182c', border: '1px solid #243455', borderRadius: 12, fontSize: 12 }, labelStyle: { color: '#e6edf8' }, cursor: { fill: 'rgb(34 211 238 / .06)' } }
export const axis = { stroke: '#5b6b88', fontSize: 11, tickLine: false, axisLine: { stroke: '#1a2740' } } as const

export function BenchControls({ running, onRun, defaultSizes = '1, 5, 10' }: { running: boolean; onRun: (s: number[], n: number) => void; defaultSizes?: string }) {
  const [sizes, setSizes] = useState(defaultSizes)
  const [iters, setIters] = useState(5)
  const parsed = sizes.split(',').map((s) => parseFloat(s.trim())).filter((n) => n > 0 && n <= 50).slice(0, 6)
  return (
    <div className="flex flex-wrap items-end gap-3">
      <div><label className="label" htmlFor="sizes">File sizes (MB)</label><input id="sizes" className="input !w-36" value={sizes} onChange={(e) => setSizes(e.target.value)} disabled={running} /></div>
      <div><label className="label" htmlFor="iters">Iterations</label><input id="iters" type="number" min={1} max={50} className="input !w-24" value={iters} onChange={(e) => setIters(Math.max(1, Math.min(50, +e.target.value || 1)))} disabled={running} /></div>
      <button id="run-benchmark" className="btn-primary" disabled={running || !parsed.length} onClick={() => onRun(parsed, iters)}>
        {running ? <><Spinner /> Measuring…</> : <><Play className="h-4 w-4" /> Run benchmark</>}
      </button>
    </div>
  )
}

const row = (label: string, s: Stat) => (
  <tr key={label} className="transition hover:bg-panel2/50">
    <td className="td font-medium">{label}</td><td className="td mono text-cy">{formatMs(s.mean_ms)}</td>
    <td className="td mono text-mute">{formatMs(s.min_ms)}</td><td className="td mono text-mute">{formatMs(s.max_ms)}</td><td className="td mono text-dim">± {formatMs(s.stdev_ms)}</td>
  </tr>
)

export default function Benchmarks() {
  const b = useBenchmark()
  const r = b.latest?.results
  return (
    <>
      <PageHeader title="Benchmarks" subtitle="Live measurements of the real cryptographic operations on this machine. Nothing is precomputed.">
        <BenchControls running={b.running} onRun={(s, n) => void b.run(s, n)} />
      </PageHeader>
      {b.runError && <div className="mb-5"><Callout tone="bad" title="Benchmark failed">{b.runError}</Callout></div>}
      {b.error ? <ErrorState message={b.error} onRetry={() => void b.reload()} /> : b.loading ? <Skeleton className="h-80" /> : !r ? (
        <div className="card"><EmptyState icon={<Cpu className="h-6 w-6" />} title="No benchmark has been run yet" hint="Press “Run benchmark” to measure key generation, encapsulation, signing and full-file throughput." /></div>
      ) : (
        <div className="space-y-6 animate-fade-up">
          <p className="text-xs text-dim">Run {fullDate(b.latest!.created_at)} · {b.latest!.parameters.iterations} iterations · Python {r.environment.python} · {r.environment.cpu_count} CPUs · {r.environment.platform}</p>

          <section className="card overflow-hidden">
            <div className="border-b border-line px-5 py-4"><h2 className="font-display text-lg font-semibold">Primitive operations</h2><p className="text-xs text-dim">{r.primitives.kem_algorithm} and {r.primitives.signature_algorithm}</p></div>
            <div className="overflow-x-auto"><table className="w-full">
              <thead><tr className="border-b border-line"><th className="th">Operation</th><th className="th">Mean</th><th className="th">Min</th><th className="th">Max</th><th className="th">Std dev</th></tr></thead>
              <tbody className="divide-y divide-line">
                {row('ML-KEM key generation', r.primitives.kem_keygen)}{row('ML-KEM encapsulation', r.primitives.kem_encapsulate)}{row('ML-KEM decapsulation', r.primitives.kem_decapsulate)}
                {row('ML-DSA key generation', r.primitives.sig_keygen)}{row('ML-DSA signing', r.primitives.sig_sign)}{row('ML-DSA verification', r.primitives.sig_verify)}
              </tbody></table></div>
          </section>

          <div className="grid gap-6 lg:grid-cols-2">
            <section className="card p-5">
              <h2 className="font-display text-lg font-semibold">End-to-end time by file size</h2>
              <p className="mb-4 text-xs text-dim">Full package encrypt (KEM + AES-GCM + sign) vs verify + decrypt</p>
              <div className="h-64"><ResponsiveContainer>
                <BarChart data={r.pipeline.map((p) => ({ size: `${p.size_mb} MB`, Encrypt: +p.total_encrypt.mean_ms.toFixed(2), Decrypt: +p.total_decrypt.mean_ms.toFixed(2) }))}>
                  <CartesianGrid stroke="#1a2740" vertical={false} /><XAxis dataKey="size" {...axis} /><YAxis {...axis} unit=" ms" width={70} />
                  <Tooltip {...chartTooltip} /><Legend wrapperStyle={{ fontSize: 12 }} />
                  <Bar dataKey="Encrypt" fill="#22d3ee" radius={[6, 6, 0, 0]} /><Bar dataKey="Decrypt" fill="#34d399" radius={[6, 6, 0, 0]} />
                </BarChart></ResponsiveContainer></div>
            </section>
            <section className="card p-5">
              <h2 className="font-display text-lg font-semibold">Throughput (MB/s)</h2>
              <p className="mb-4 text-xs text-dim">AES-256-GCM alone vs whole pipeline: the PQ overhead is a constant, not per-byte</p>
              <div className="h-64"><ResponsiveContainer>
                <LineChart data={r.pipeline.map((p) => ({ size: `${p.size_mb} MB`, 'AES-GCM encrypt': +p.aes_encrypt.throughput_mb_s.toFixed(0), 'Full pipeline encrypt': +p.total_encrypt.throughput_mb_s.toFixed(0), 'Full pipeline decrypt': +p.total_decrypt.throughput_mb_s.toFixed(0) }))}>
                  <CartesianGrid stroke="#1a2740" vertical={false} /><XAxis dataKey="size" {...axis} /><YAxis {...axis} width={55} />
                  <Tooltip {...chartTooltip} /><Legend wrapperStyle={{ fontSize: 12 }} />
                  <Line dataKey="AES-GCM encrypt" stroke="#a78bfa" strokeWidth={2} dot={{ r: 3 }} /><Line dataKey="Full pipeline encrypt" stroke="#22d3ee" strokeWidth={2} dot={{ r: 3 }} /><Line dataKey="Full pipeline decrypt" stroke="#34d399" strokeWidth={2} dot={{ r: 3 }} />
                </LineChart></ResponsiveContainer></div>
            </section>
          </div>

          <section className="card overflow-hidden">
            <div className="border-b border-line px-5 py-4"><h2 className="font-display text-lg font-semibold">Key, signature and package sizes</h2></div>
            <div className="grid gap-px bg-line sm:grid-cols-3">
              {Object.entries(r.primitives.sizes_bytes).map(([k, v]) => (
                <div key={k} className="bg-panel p-4"><p className="text-[11px] uppercase tracking-wider text-dim">{k.replace(/_/g, ' ')}</p><p className="mono mt-1 text-lg text-ink">{v.toLocaleString()} <span className="text-xs text-dim">bytes</span></p></div>
              ))}
              {r.pipeline[0] && <div className="bg-panel p-4"><p className="text-[11px] uppercase tracking-wider text-dim">package overhead / file</p><p className="mono mt-1 text-lg text-ink">{formatBytes(r.pipeline[0].package_overhead_bytes)}</p></div>}
            </div>
          </section>
        </div>
      )}
    </>
  )
}
