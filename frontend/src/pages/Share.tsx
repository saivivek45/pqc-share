import { useCallback, useEffect, useRef, useState, type DragEvent } from 'react'
import { Link } from 'react-router-dom'
import { ArrowRight, CheckCircle2, FileUp, Fingerprint as FpIcon, KeyRound, Lock, PenTool, UploadCloud, Users, X } from 'lucide-react'
import { Callout, Fingerprint, PageHeader, Spinner } from '../components/ui'
import { useToast } from '../context/ToastContext'
import { api } from '../services/api'
import type { Peer, UploadOut } from '../types'
import { formatBytes, formatMs } from '../utils/format'

const STEPS = [
  { key: 'kem_encapsulate', title: 'ML-KEM-768 encapsulation', desc: 'Fresh 256-bit shared secret sealed to the receiver’s public key', icon: KeyRound },
  { key: 'aes_encrypt', title: 'AES-256-GCM encryption', desc: 'File encrypted with HKDF-derived key; header bound as AAD', icon: Lock },
  { key: 'sign', title: 'ML-DSA-65 signature', desc: 'Package signed with your signing key for sender authenticity', icon: PenTool },
]

export default function Share() {
  const toast = useToast()
  const [peers, setPeers] = useState<Peer[] | null>(null)
  const [peerErr, setPeerErr] = useState<string | null>(null)
  const [receiver, setReceiver] = useState<number | ''>('')
  const [file, setFile] = useState<File | null>(null)
  const [drag, setDrag] = useState(false)
  const [busy, setBusy] = useState(false)
  const [phase, setPhase] = useState(0)
  const [result, setResult] = useState<UploadOut | null>(null)
  const [error, setError] = useState<string | null>(null)
  const input = useRef<HTMLInputElement>(null)

  useEffect(() => { api.peers().then(setPeers).catch((e: Error) => setPeerErr(e.message)) }, [])
  useEffect(() => {
    if (!busy) return
    setPhase(0)
    const t = setInterval(() => setPhase((p) => Math.min(p + 1, STEPS.length - 1)), 650)
    return () => clearInterval(t)
  }, [busy])

  const onDrop = useCallback((e: DragEvent) => { e.preventDefault(); setDrag(false); if (e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]) }, [])
  const peer = peers?.find((p) => p.id === receiver)

  async function submit() {
    if (!file || receiver === '') return
    setBusy(true); setError(null); setResult(null)
    try {
      const r = await api.upload(receiver, file)
      setResult(r)
      toast.push('success', `Encrypted and shared with ${r.share.receiver.username}.`)
      setFile(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Upload failed.')
    } finally { setBusy(false) }
  }

  return (
    <>
      <PageHeader title="Share a file" subtitle="Files are encrypted on the server with the receiver’s ML-KEM public key and signed with your ML-DSA key. The plaintext is never stored." />
      <div className="grid gap-6 lg:grid-cols-5">
        <div className="card space-y-6 p-6 lg:col-span-3 animate-fade-up">
          <div>
            <label className="label" htmlFor="receiver">Recipient</label>
            {peerErr ? <p className="text-sm text-bad">{peerErr}</p> : (
              <select id="receiver" className="input" value={receiver} onChange={(e) => setReceiver(e.target.value ? Number(e.target.value) : '')} disabled={busy}>
                <option value="">{peers ? (peers.length ? 'Choose a recipient…' : 'No other users registered yet') : 'Loading…'}</option>
                {peers?.map((p) => <option key={p.id} value={p.id}>{p.username}</option>)}
              </select>
            )}
            {peer?.kem_fingerprint && (
              <div className="mt-2 flex items-center gap-2 text-xs text-dim"><FpIcon className="h-3.5 w-3.5" /> Encrypting to ML-KEM key <Fingerprint value={peer.kem_fingerprint} /></div>
            )}
            {peers?.length === 0 && <p className="mt-2 text-xs text-dim">Register a second account (or use the demo users) to have someone to send to.</p>}
          </div>

          <div>
            <span className="label">File</span>
            <div role="button" tabIndex={0} id="dropzone" aria-label="Select file"
              onClick={() => !busy && input.current?.click()} onKeyDown={(e) => e.key === 'Enter' && input.current?.click()}
              onDragOver={(e) => { e.preventDefault(); setDrag(true) }} onDragLeave={() => setDrag(false)} onDrop={onDrop}
              className={`grid cursor-pointer place-items-center rounded-2xl border-2 border-dashed px-6 py-12 text-center transition ${drag ? 'border-cy bg-cy/10' : 'border-line2 bg-bg2/50 hover:border-cy/50'}`}>
              <input ref={input} type="file" hidden onChange={(e) => setFile(e.target.files?.[0] ?? null)} data-testid="file-input" />
              {file ? (
                <div className="flex items-center gap-3">
                  <div className="grid h-12 w-12 place-items-center rounded-xl bg-cy/10 text-cy"><FileUp className="h-6 w-6" /></div>
                  <div className="text-left"><p className="font-medium">{file.name}</p><p className="mono text-xs text-mute">{formatBytes(file.size)}</p></div>
                  <button className="ml-2 text-dim hover:text-bad" aria-label="Remove file" onClick={(e) => { e.stopPropagation(); setFile(null) }}><X className="h-4 w-4" /></button>
                </div>
              ) : (
                <>
                  <UploadCloud className="h-10 w-10 text-cy" />
                  <p className="mt-3 font-medium">Drop a file here, or click to browse</p>
                  <p className="mt-1 text-xs text-dim">Any file type · up to 100 MB</p>
                </>
              )}
            </div>
          </div>

          {error && <Callout tone="bad" title="Could not share file">{error}</Callout>}
          <button id="encrypt-share" className="btn-primary w-full !py-3" disabled={!file || receiver === '' || busy} onClick={submit}>
            {busy ? <><Spinner /> Encrypting…</> : <><Lock className="h-4 w-4" /> Encrypt &amp; share</>}
          </button>
        </div>

        <div className="space-y-4 lg:col-span-2">
          <div className="card p-6 animate-fade-up">
            <h2 className="font-display text-lg font-semibold">Encryption pipeline</h2>
            <p className="mb-5 mt-1 text-xs text-dim">{result ? 'Measured timings of the real operations that just ran.' : 'What happens when you press the button.'}</p>
            <ol className="space-y-5">
              {STEPS.map((s, i) => {
                const done = result || (busy && i < phase)
                const active = busy && i === phase
                return (
                  <li key={s.key} className="flex gap-3.5">
                    <div className={`grid h-10 w-10 shrink-0 place-items-center rounded-xl border transition ${done ? 'border-em/40 bg-em/10 text-em' : active ? 'border-cy/50 bg-cy/10 text-cy' : 'border-line2 bg-panel2 text-dim'}`}>
                      {done ? <CheckCircle2 className="h-5 w-5" /> : active ? <Spinner className="h-5 w-5" /> : <s.icon className="h-5 w-5" />}
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-baseline justify-between gap-2">
                        <p className={`text-sm font-medium ${done || active ? 'text-ink' : 'text-mute'}`}>{s.title}</p>
                        {result && <span className="mono text-xs text-em">{formatMs(result.timings_ms[s.key] ?? 0)}</span>}
                      </div>
                      <p className="text-xs text-dim">{s.desc}</p>
                    </div>
                  </li>
                )
              })}
            </ol>
          </div>

          {result && (
            <div className="animate-fade-up space-y-3">
              <Callout tone="good" title="File encrypted and delivered">
                <b className="text-ink">{result.share.filename}</b> ({formatBytes(result.share.filesize)}) → package of {formatBytes(result.share.package_size)} for <b className="text-ink">{result.share.receiver.username}</b>. Total {formatMs(result.timings_ms.total)}.
              </Callout>
              <Link to="/sent" className="btn-ghost w-full">View in Sent <ArrowRight className="h-4 w-4" /></Link>
            </div>
          )}
          <div className="flex items-start gap-2.5 px-1 text-xs text-dim"><Users className="mt-0.5 h-3.5 w-3.5 shrink-0" /> Only the recipient’s private key can recover the session key. Even you, the sender, cannot decrypt the package afterwards.</div>
        </div>
      </div>
    </>
  )
}
