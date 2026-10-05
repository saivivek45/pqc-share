import { Scale } from 'lucide-react'
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Callout, EmptyState, ErrorState, PageHeader, Skeleton } from '../components/ui'
import { useBenchmark } from '../hooks/useBenchmark'
import { formatMs } from '../utils/format'
import { axis, BenchControls, chartTooltip } from './Benchmarks'

export default function Comparison() {
  const b = useBenchmark()
  const c = b.latest?.results.comparison
  const rows = c ? [
    ['Key generation', c.rsa.keygen_ms, c.post_quantum.keygen_ms],
    ['Encrypt / encapsulate', c.rsa.encrypt_ms, c.post_quantum.encrypt_ms],
    ['Decrypt / decapsulate', c.rsa.decrypt_ms, c.post_quantum.decrypt_ms],
  ] as const : []
  const sizeRows = c ? [['Public key', c.rsa.public_key_bytes, c.post_quantum.public_key_bytes], ['Private key', c.rsa.private_key_bytes, c.post_quantum.private_key_bytes], ['Ciphertext', c.rsa.ciphertext_bytes, c.post_quantum.ciphertext_bytes]] as const : []

  return (
    <>
      <PageHeader title="RSA-2048 vs ML-KEM-768" subtitle="Classical and post-quantum key establishment measured side by side. Experimental results from this machine.">
        <BenchControls running={b.running} onRun={(s, n) => void b.run(s, n)} defaultSizes="1" />
      </PageHeader>
      {b.runError && <div className="mb-5"><Callout tone="bad" title="Benchmark failed">{b.runError}</Callout></div>}
      {b.error ? <ErrorState message={b.error} onRetry={() => void b.reload()} /> : b.loading ? <Skeleton className="h-80" /> : !c ? (
        <div className="card"><EmptyState icon={<Scale className="h-6 w-6" />} title="No comparison data yet" hint="Run a benchmark to measure RSA-2048 (OAEP) against ML-KEM-768 live." /></div>
      ) : (
        <div className="space-y-6 animate-fade-up">
          <section className="card p-5">
            <h2 className="font-display text-lg font-semibold">Operation time (lower is better)</h2>
            <p className="mb-4 text-xs text-dim">Mean over {c.iterations} iterations · logarithmic scale · {c.rsa.algorithm} vs {c.post_quantum.algorithm}</p>
            <div className="h-72"><ResponsiveContainer>
              <BarChart data={rows.map(([op, rsa, pq]) => ({ op, 'RSA-2048': +rsa.mean_ms.toFixed(3), 'ML-KEM-768': +pq.mean_ms.toFixed(3) }))}>
                <CartesianGrid stroke="#1a2740" vertical={false} /><XAxis dataKey="op" {...axis} /><YAxis {...axis} scale="log" domain={[0.01, 'auto']} unit=" ms" width={70} allowDataOverflow />
                <Tooltip {...chartTooltip} /><Legend wrapperStyle={{ fontSize: 12 }} />
                <Bar dataKey="RSA-2048" fill="#f87171" radius={[6, 6, 0, 0]} /><Bar dataKey="ML-KEM-768" fill="#22d3ee" radius={[6, 6, 0, 0]} />
              </BarChart></ResponsiveContainer></div>
          </section>

          <div className="grid gap-6 lg:grid-cols-2">
            <section className="card overflow-hidden">
              <div className="border-b border-line px-5 py-4"><h2 className="font-display text-lg font-semibold">Timings</h2></div>
              <table className="w-full"><thead><tr className="border-b border-line"><th className="th">Operation</th><th className="th">RSA-2048</th><th className="th">ML-KEM-768</th></tr></thead>
                <tbody className="divide-y divide-line">{rows.map(([op, rsa, pq]) => (
                  <tr key={op}><td className="td font-medium">{op}</td><td className="td mono text-bad">{formatMs(rsa.mean_ms)}</td><td className="td mono text-cy">{formatMs(pq.mean_ms)}</td></tr>))}</tbody></table>
            </section>
            <section className="card overflow-hidden">
              <div className="border-b border-line px-5 py-4"><h2 className="font-display text-lg font-semibold">Sizes (bytes)</h2></div>
              <table className="w-full"><thead><tr className="border-b border-line"><th className="th">Item</th><th className="th">RSA-2048</th><th className="th">ML-KEM-768</th></tr></thead>
                <tbody className="divide-y divide-line">{sizeRows.map(([n, a, p]) => (
                  <tr key={n}><td className="td font-medium">{n}</td><td className="td mono text-bad">{a.toLocaleString()}</td><td className="td mono text-cy">{p.toLocaleString()}</td></tr>))}</tbody></table>
            </section>
          </div>

          <Callout tone="info" title="How to read this">
            ML-KEM keys and ciphertexts are larger than RSA’s but its operations are typically very fast. The decisive difference is security: RSA-2048 is broken by Shor’s algorithm on a sufficiently large quantum computer, while ML-KEM is based on the Module-LWE lattice problem with no known efficient quantum attack. {c.note}
          </Callout>
        </div>
      )}
    </>
  )
}
