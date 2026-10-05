import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Download, FileDown, Info, Inbox, Send, Share2, ShieldCheck, Unlock } from 'lucide-react'
import { Callout, EmptyState, ErrorState, Fingerprint, Modal, PageHeader, Pill, Skeleton, Spinner, StatusBadge } from '../components/ui'
import { useAsync } from '../hooks/useAsync'
import { useToast } from '../context/ToastContext'
import { api } from '../services/api'
import type { Peer, Share } from '../types'
import { formatBytes, formatMs, fullDate, timeAgo, triggerDownload } from '../utils/format'

export default function Transfers({ direction }: { direction: 'received' | 'sent' }) {
  const recv = direction === 'received'
  const { data, error, loading, reload } = useAsync(recv ? api.received : api.sent, [direction])
  const toast = useToast()
  const [busy, setBusy] = useState<string | null>(null)
  const [alert, setAlert] = useState<{ id: number; msg: string } | null>(null)
  const [info, setInfo] = useState<Share | null>(null)
  const [fwd, setFwd] = useState<Share | null>(null)

  async function run(key: string, share: Share, fn: () => Promise<string>) {
    setBusy(key); setAlert(null)
    try { toast.push('success', await fn()) }
    catch (e) {
      const msg = e instanceof Error ? e.message : 'Operation failed.'
      setAlert({ id: share.id, msg }); toast.push('error', msg)
    } finally { setBusy(null); void reload(true) }
  }

  const verify = (s: Share) => run(`v${s.id}`, s, async () => { const r = await api.verify(s.id); return `${r.message} (${r.algorithm})` })
  const decrypt = (s: Share) => run(`d${s.id}`, s, async () => { const r = await api.decrypt(s.id); return `Decrypted in ${formatMs(r.timings_ms.total)}. Ready to download.` })
  const download = (s: Share) => run(`dl${s.id}`, s, async () => { const { blob, filename } = await api.download(s.id); triggerDownload(blob, filename); return `Downloaded ${filename} (integrity re-verified).` })

  return (
    <>
      <PageHeader title={recv ? 'Received files' : 'Sent files'}
        subtitle={recv ? 'Verify the sender’s signature, then decrypt with your ML-KEM private key. Any tampering is detected and the file is refused.' : 'Files you encrypted for others. Only recipients can decrypt them.'} />

      {alert && <div className="mb-5"><Callout tone="bad" title="Integrity check failed">{alert.msg}</Callout></div>}

      {error ? <ErrorState message={error} onRetry={() => void reload()} /> : (
        <div className="card overflow-hidden animate-fade-up">
          {loading ? <div className="space-y-3 p-5">{[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-12" />)}</div>
            : !data || data.length === 0 ? (
              <EmptyState icon={recv ? <Inbox className="h-6 w-6" /> : <Send className="h-6 w-6" />}
                title={recv ? 'Your inbox is empty' : 'Nothing sent yet'} hint={recv ? 'Files other users encrypt for you will appear here.' : 'Encrypt a file for another user to get started.'}
                action={!recv && <Link to="/share" className="btn-primary mt-2">Share a file</Link>} />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead><tr className="border-b border-line">
                    <th className="th">File</th><th className="th">{recv ? 'From' : 'To'}</th><th className="th">Size</th><th className="th">Status</th><th className="th">When</th><th className="th text-right">Actions</th>
                  </tr></thead>
                  <tbody className="divide-y divide-line">
                    {data.map((s) => (
                      <tr key={s.id} className="transition hover:bg-panel2/50">
                        <td className="td"><p className="font-medium">{s.filename}</p><p className="text-xs text-dim">{s.aes_algorithm}</p></td>
                        <td className="td">{recv ? s.sender.username : s.receiver.username}</td>
                        <td className="td mono text-mute">{formatBytes(s.filesize)}</td>
                        <td className="td"><StatusBadge status={s.status} /></td>
                        <td className="td text-dim" title={fullDate(s.created_at)}>{timeAgo(s.created_at)}</td>
                        <td className="td">
                          <div className="flex flex-wrap items-center justify-end gap-2">
                            {recv && s.status !== 'DECRYPTED' && (
                              <>
                                <button className="btn-ghost !px-3 !py-1.5 text-xs" disabled={!!busy} onClick={() => verify(s)}>
                                  {busy === `v${s.id}` ? <Spinner /> : <ShieldCheck className="h-3.5 w-3.5" />} Verify
                                </button>
                                <button className="btn-primary !px-3 !py-1.5 text-xs" disabled={!!busy} onClick={() => decrypt(s)}>
                                  {busy === `d${s.id}` ? <Spinner /> : <Unlock className="h-3.5 w-3.5" />} Verify &amp; decrypt
                                </button>
                              </>
                            )}
                            {recv && s.status === 'DECRYPTED' && (
                              <>
                                <button className="btn-primary !px-3 !py-1.5 text-xs" disabled={!!busy} onClick={() => download(s)}>
                                  {busy === `dl${s.id}` ? <Spinner /> : <Download className="h-3.5 w-3.5" />} Download
                                </button>
                                <button className="btn-ghost !px-3 !py-1.5 text-xs" disabled={!!busy} onClick={() => setFwd(s)}><Share2 className="h-3.5 w-3.5" /> Forward</button>
                              </>
                            )}
                            <button className="btn-ghost !p-1.5" aria-label="Cryptographic details" title="Cryptographic details" onClick={() => setInfo(s)}><Info className="h-4 w-4" /></button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
        </div>
      )}
      {!loading && recv && <p className="mt-4 flex items-center gap-2 text-xs text-dim"><FileDown className="h-3.5 w-3.5" /> Every download re-runs signature verification and AES-GCM tag checking. Plaintext is never stored on the server.</p>}

      <DetailsModal share={info} onClose={() => setInfo(null)} />
      <ForwardModal share={fwd} onClose={() => setFwd(null)} onDone={() => { setFwd(null); void reload(true) }} />
    </>
  )
}

function DetailsModal({ share, onClose }: { share: Share | null; onClose: () => void }) {
  const { data, error, loading } = useAsync(() => (share ? api.packageInfo(share.id) : Promise.resolve(null)), [share?.id])
  return (
    <Modal open={!!share} onClose={onClose} title="Cryptographic details">
      {share && (
        <div className="space-y-4 text-sm">
          <div className="grid grid-cols-2 gap-3">
            {[['Key encapsulation', share.kem_algorithm], ['Symmetric cipher', share.aes_algorithm], ['Signature', share.signature_algorithm], ['Package size', formatBytes(share.package_size)]].map(([k, v]) => (
              <div key={k} className="rounded-xl border border-line bg-bg2 p-3"><p className="text-[11px] uppercase tracking-wider text-dim">{k}</p><p className="mono mt-1 text-ink">{v}</p></div>
            ))}
          </div>
          <div><p className="label">Sender signing key</p><Fingerprint value={share.sender_fingerprint} full /></div>
          <div><p className="label">Receiver KEM key</p><Fingerprint value={share.receiver_fingerprint} full /></div>
          {share.status_detail && <Callout tone="bad" title="Why it failed">{share.status_detail}</Callout>}
          <div>
            <p className="label">Package header (public metadata)</p>
            {loading ? <Skeleton className="h-24" /> : error ? <p className="text-bad">{error}</p> : (
              <div className="max-h-44 overflow-auto rounded-xl border border-line bg-bg2 p-3">
                {Object.entries(data ?? {}).map(([k, v]) => <div key={k} className="mono flex gap-2 text-[11px]"><span className="w-44 shrink-0 text-dim">{k}</span><span className="break-all text-mute">{String(v)}</span></div>)}
              </div>
            )}
          </div>
          <div className="flex justify-end"><button className="btn-ghost" onClick={onClose}>Close</button></div>
        </div>
      )}
    </Modal>
  )
}

function ForwardModal({ share, onClose, onDone }: { share: Share | null; onClose: () => void; onDone: () => void }) {
  const [peers, setPeers] = useState<Peer[]>([])
  const [to, setTo] = useState<number | ''>('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const toast = useToast()
  useAsync(async () => { if (share) setPeers(await api.peers()); return null }, [share?.id])
  const options = peers.filter((p) => p.id !== share?.sender.id)

  async function go() {
    if (!share || to === '') return
    setBusy(true); setErr(null)
    try { const r = await api.forward(share.id, to); toast.push('success', `Re-encrypted and sent to ${r.share.receiver.username}.`); onDone() }
    catch (e) { setErr(e instanceof Error ? e.message : 'Failed.') } finally { setBusy(false) }
  }
  return (
    <Modal open={!!share} onClose={onClose} title="Forward file securely">
      <p className="mb-4 text-sm text-mute">The file is verified, decrypted in memory, then freshly encrypted with the new recipient’s ML-KEM key and signed by you.</p>
      <label className="label" htmlFor="fwd">Recipient</label>
      <select id="fwd" className="input" value={to} onChange={(e) => setTo(e.target.value ? Number(e.target.value) : '')}>
        <option value="">Choose…</option>{options.map((p) => <option key={p.id} value={p.id}>{p.username}</option>)}
      </select>
      {err && <div className="mt-4"><Callout tone="bad" title="Could not forward">{err}</Callout></div>}
      <div className="mt-6 flex justify-end gap-2">
        <button className="btn-ghost" onClick={onClose}>Cancel</button>
        <button className="btn-primary" disabled={to === '' || busy} onClick={go}>{busy && <Spinner />} Forward</button>
      </div>
      <div className="mt-3"><Pill tone="mute">ML-KEM-768</Pill></div>
    </Modal>
  )
}
