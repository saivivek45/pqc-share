import { Link } from 'react-router-dom'
import { ArrowRight, FileDown, FileUp, Inbox, ShieldAlert, ShieldCheck, Share2 } from 'lucide-react'
import { EmptyState, ErrorState, PageHeader, Skeleton, StatCard, StatusBadge } from '../components/ui'
import { useAsync } from '../hooks/useAsync'
import { api } from '../services/api'
import { formatBytes, timeAgo } from '../utils/format'
import { useAuth } from '../context/AuthContext'

export default function Dashboard() {
  const { user } = useAuth()
  const { data, error, loading, reload } = useAsync(api.dashboard)

  return (
    <>
      <PageHeader title="Dashboard" subtitle="Your post-quantum secure sharing activity at a glance.">
        <Link to="/share" className="btn-primary"><FileUp className="h-4 w-4" /> Share a file</Link>
      </PageHeader>

      {error ? <ErrorState message={error} onRetry={() => void reload()} /> : (
        <>
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            {loading || !data ? Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-[132px]" />) : (
              <>
                <StatCard label="Total shared" value={data.total_files_shared} icon={<Share2 className="h-[18px] w-[18px]" />} hint={`${data.files_sent} sent · ${data.files_received} received`} />
                <StatCard label="Received" value={data.files_received} icon={<FileDown className="h-[18px] w-[18px]" />} tone="vio" hint="Encrypted for your ML-KEM key" />
                <StatCard label="Decryptions" value={data.successful_decryptions} icon={<ShieldCheck className="h-[18px] w-[18px]" />} tone="em" hint="Signature + GCM tag verified" />
                <StatCard label="Integrity failures" value={data.failed_integrity_checks} icon={<ShieldAlert className="h-[18px] w-[18px]" />} tone="bad" hint={data.failed_integrity_checks ? 'Tampered packages detected' : 'No tampering detected'} />
              </>
            )}
          </div>

          <section className="card mt-8 overflow-hidden animate-fade-up">
            <div className="flex items-center justify-between border-b border-line px-5 py-4">
              <h2 className="font-display text-lg font-semibold">Recent transfers</h2>
              <Link to="/received" className="flex items-center gap-1 text-sm text-cy hover:underline">View inbox <ArrowRight className="h-3.5 w-3.5" /></Link>
            </div>
            {loading ? <div className="space-y-3 p-5">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-10" />)}</div>
              : !data || data.recent.length === 0 ? (
                <EmptyState icon={<Inbox className="h-6 w-6" />} title="No transfers yet" hint="Encrypt your first file for another user to see it appear here."
                  action={<Link to="/share" className="btn-primary mt-2">Share your first file</Link>} />
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead><tr className="border-b border-line"><th className="th">File</th><th className="th">Direction</th><th className="th">Size</th><th className="th">Status</th><th className="th">When</th></tr></thead>
                    <tbody className="divide-y divide-line">
                      {data.recent.map((s) => {
                        const out = s.sender.id === user?.id
                        return (
                          <tr key={s.id} className="transition hover:bg-panel2/50">
                            <td className="td font-medium">{s.filename}</td>
                            <td className="td text-mute">{out ? <>→ <b className="text-ink">{s.receiver.username}</b></> : <>← <b className="text-ink">{s.sender.username}</b></>}</td>
                            <td className="td mono text-mute">{formatBytes(s.filesize)}</td>
                            <td className="td"><StatusBadge status={s.status} /></td>
                            <td className="td text-dim">{timeAgo(s.created_at)}</td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
              )}
          </section>
        </>
      )}
    </>
  )
}
