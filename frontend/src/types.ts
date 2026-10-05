export interface User { id: number; username: string; email: string; created_at: string }
export interface TokenOut { access_token: string; token_type: string; expires_at: string; user: User }

export type ShareStatus = 'ENCRYPTED' | 'VERIFIED' | 'DECRYPTED' | 'INTEGRITY_FAILED'

export interface Share {
  id: number; file_id: number; filename: string; filesize: number; package_size: number
  status: ShareStatus; status_detail: string | null
  sender: { id: number; username: string }; receiver: { id: number; username: string }
  kem_algorithm: string; signature_algorithm: string; aes_algorithm: string
  sender_fingerprint: string; receiver_fingerprint: string
  created_at: string; verified_at: string | null; decrypted_at: string | null
}
export interface UploadOut { share: Share; timings_ms: Record<string, number> }
export interface VerifyOut { share: Share; signature_valid: boolean; sender_fingerprint: string; algorithm: string; message: string }
export interface DecryptOut { share: Share; timings_ms: Record<string, number>; message: string }

export interface Dashboard {
  total_files_shared: number; files_sent: number; files_received: number
  successful_decryptions: number; failed_integrity_checks: number; recent: Share[]
}
export interface KeyInfo {
  id: number; kind: 'KEM' | 'SIG'; algorithm: string; fingerprint: string; fingerprint_pretty: string
  public_key_bytes: number; status: string; created_at: string
}
export interface PublicKeys {
  kem_algorithm: string; kem_fingerprint: string; kem_public_key: string
  signature_algorithm: string; signature_fingerprint: string; signature_public_key: string
}
export interface Peer { id: number; username: string; kem_fingerprint: string | null; signature_fingerprint: string | null }
export interface AuditEvent { id: number; event: string; detail: string | null; created_at: string }

export interface Stat { mean_ms: number; min_ms: number; max_ms: number; stdev_ms: number; samples: number }
export interface PipelineRes {
  size_mb: number
  aes_encrypt: Stat & { throughput_mb_s: number }; aes_decrypt: Stat & { throughput_mb_s: number }
  total_encrypt: Stat & { throughput_mb_s: number }; total_decrypt: Stat & { throughput_mb_s: number }
  encrypt_breakdown_ms: Record<string, number>; package_overhead_bytes: number
}
export interface BenchResults {
  environment: { python: string; platform: string; processor: string; cpu_count: number; kem: string }
  primitives: {
    kem_algorithm: string; signature_algorithm: string
    kem_keygen: Stat; kem_encapsulate: Stat; kem_decapsulate: Stat
    sig_keygen: Stat; sig_sign: Stat; sig_verify: Stat
    sizes_bytes: Record<string, number>
  }
  pipeline: PipelineRes[]
  comparison: {
    post_quantum: { algorithm: string; keygen_ms: Stat; encrypt_ms: Stat; decrypt_ms: Stat; public_key_bytes: number; private_key_bytes: number; ciphertext_bytes: number }
    rsa: { algorithm: string; keygen_ms: Stat; encrypt_ms: Stat; decrypt_ms: Stat; public_key_bytes: number; private_key_bytes: number; ciphertext_bytes: number }
    iterations: number; note: string
  }
}
export interface Benchmark { id: number; kind: string; parameters: { sizes_mb: number[]; iterations: number }; results: BenchResults; created_at: string }

export interface SecurityInfo {
  disclaimer: string
  algorithms: Record<string, Record<string, string | number | boolean>>
  package: { version: number; format: string; header_fields: string[]; gcm_aad: string; signed_message: string }
  limits: { max_upload_mb: number; token_ttl_minutes: number }
  key_storage: string
}
