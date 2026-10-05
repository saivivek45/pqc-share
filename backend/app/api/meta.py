from __future__ import annotations

import threading

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, current_user
from app.core.config import get_settings
from app.core.db import get_db
from app.crypto import get_kem, get_signer, primitives as P
from app.models import AuditLog, Benchmark, FileShare, User
from app.schemas import AuditOut, BenchmarkOut, BenchmarkRunIn, DashboardOut
from app.services import audit, benchmark as bench
from app.services import file_service as fs

dashboard_router = APIRouter(tags=["dashboard"])
security_router = APIRouter(prefix="/security", tags=["security"])
bench_router = APIRouter(prefix="/benchmarks", tags=["benchmarks"])


@dashboard_router.get("/dashboard", response_model=DashboardOut)
def dashboard(user: User = Depends(current_user), db: Session = Depends(get_db)):
    sent = db.scalar(select(func.count()).select_from(FileShare).where(FileShare.sender_id == user.id)) or 0
    recv = db.scalar(select(func.count()).select_from(FileShare).where(FileShare.receiver_id == user.id)) or 0
    mine = (FileShare.sender_id == user.id) | (FileShare.receiver_id == user.id)
    ok = db.scalar(select(func.count()).select_from(FileShare).where(FileShare.receiver_id == user.id, FileShare.decrypted_at.is_not(None))) or 0
    bad = db.scalar(select(func.count()).select_from(FileShare).where(mine, FileShare.status == "INTEGRITY_FAILED")) or 0
    return DashboardOut(total_files_shared=sent + recv, files_sent=sent, files_received=recv, successful_decryptions=ok,
                        failed_integrity_checks=bad, recent=[fs.to_out(s) for s in fs.list_shares(db, user, None, 8)])


@dashboard_router.get("/audit", response_model=list[AuditOut])
def my_audit(limit: int = 50, user: User = Depends(current_user), db: Session = Depends(get_db)):
    limit = max(1, min(limit, 200))
    return list(db.scalars(select(AuditLog).where(AuditLog.user_id == user.id).order_by(AuditLog.id.desc()).limit(limit)))


@security_router.get("/info")
def security_info(_: User = Depends(current_user)):
    kem, sig = get_kem().info, get_signer().info
    return {
        "disclaimer": "Academic project. Not independently security audited.",
        "algorithms": {
            "kem": {**kem.__dict__, "role": "Establishes a shared secret with the receiver using a post-quantum KEM (lattice-based, Module-LWE).",
                    "why": "Replaces RSA/ECDH key transport, which Shor's algorithm breaks on a quantum computer."},
            "symmetric": {"name": P.AES_ALGORITHM, "standard": "NIST SP 800-38D", "key_bits": 256, "nonce_bits": 96, "tag_bits": 128,
                          "role": "Encrypts and authenticates file contents and binds header metadata as AAD.",
                          "why": "Fast AEAD; 256-bit keys retain >=128-bit security against Grover's algorithm."},
            "signature": {**sig.__dict__, "role": "Authenticates the sender and the entire package.",
                          "why": "Post-quantum signatures (lattice-based) replace RSA/ECDSA, which Shor's algorithm breaks."},
            "kdf": {"name": P.KDF_ALGORITHM, "standard": "RFC 5869", "role": "Derives the AES key from the KEM secret with domain separation and context binding."},
            "hash": {"name": "SHA3-256", "standard": "NIST FIPS 202", "role": "Public-key fingerprints and the ciphertext digest that is signed."},
            "password": {"name": "Argon2id", "standard": "RFC 9106", "role": "Memory-hard password hashing."},
        },
        "package": {
            "version": 1,
            "format": "PQSH magic | u32 header length | JSON header | AES-GCM ciphertext||tag",
            "header_fields": ["version", "package_id", "filename", "filesize", "timestamp", "kem_algorithm", "signature_algorithm",
                              "aes_algorithm", "kdf_algorithm", "nonce", "kem_ciphertext", "sender_id", "sender_fingerprint",
                              "receiver_fingerprint", "ciphertext_len", "tag_length", "signature"],
            "gcm_aad": "canonical JSON of all header fields except `signature`",
            "signed_message": "domain || AAD || SHA3-256(ciphertext||tag)",
        },
        "limits": {"max_upload_mb": get_settings().max_upload_mb, "token_ttl_minutes": get_settings().token_ttl_minutes},
        "key_storage": "Private keys are stored only as AES-256-GCM blobs wrapped under an HKDF-derived key from the server master key. They never leave the server and are never returned by any API.",
    }


_bench_lock = threading.Lock()


@bench_router.get("", response_model=list[BenchmarkOut])
def history(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(Benchmark).where(Benchmark.user_id == user.id).order_by(Benchmark.id.desc()).limit(10)).all()
    return [BenchmarkOut(id=r.id, kind=r.kind, parameters=r.parameters, results=r.results, created_at=r.created_at) for r in rows]


@bench_router.post("/run", response_model=BenchmarkOut)
def run(body: BenchmarkRunIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not _bench_lock.acquire(blocking=False):
        raise HTTPException(409, "A benchmark is already running.")
    try:
        results = {
            "environment": bench.environment(),
            "primitives": bench.run_primitives(body.iterations),
            "pipeline": [bench.run_pipeline(s, min(body.iterations, 5)) for s in body.sizes_mb],
            "comparison": bench.run_comparison(body.iterations),
        }
    finally:
        _bench_lock.release()
    row = Benchmark(user_id=user.id, kind="full", parameters=body.model_dump(), results=results)
    db.add(row)
    db.commit()
    audit.log(db, "BENCHMARK_RUN", user.id, f"sizes={body.sizes_mb} n={body.iterations}", client_ip(request))
    return BenchmarkOut(id=row.id, kind=row.kind, parameters=row.parameters, results=row.results, created_at=row.created_at)
