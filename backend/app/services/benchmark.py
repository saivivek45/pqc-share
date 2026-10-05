"""Live, measured benchmarks. Nothing here is precomputed or hardcoded: every number comes from
timing the real primitives on the machine running the server."""
from __future__ import annotations

import os
import platform
import statistics
import time
from collections.abc import Callable

from app.crypto import decrypt_package, encrypt_package, get_kem, get_signer, parse_package, primitives as P, verify_signature
from app.crypto.rsa_baseline import measure_rsa2048


def _time(fn: Callable[[], object], n: int) -> list[float]:
    out = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        out.append((time.perf_counter() - t0) * 1000.0)
    return out


def stats(samples: list[float]) -> dict:
    return {
        "mean_ms": statistics.fmean(samples),
        "min_ms": min(samples),
        "max_ms": max(samples),
        "stdev_ms": statistics.pstdev(samples) if len(samples) > 1 else 0.0,
        "samples": len(samples),
    }


def environment() -> dict:
    return {
        "python": platform.python_version(), "platform": platform.platform(),
        "processor": platform.processor() or platform.machine(), "cpu_count": os.cpu_count(),
        "kem": get_kem().info.library,
    }


def run_primitives(iterations: int) -> dict:
    kem, sig = get_kem(), get_signer()
    kpk, ksk = kem.keygen()
    ct, _ = kem.encapsulate(kpk)
    spk, ssk = sig.keygen()
    msg = os.urandom(64)
    s = sig.sign(ssk, msg)
    return {
        "kem_algorithm": kem.info.name, "signature_algorithm": sig.info.name,
        "kem_keygen": stats(_time(kem.keygen, iterations)),
        "kem_encapsulate": stats(_time(lambda: kem.encapsulate(kpk), iterations)),
        "kem_decapsulate": stats(_time(lambda: kem.decapsulate(ksk, ct), iterations)),
        "sig_keygen": stats(_time(sig.keygen, iterations)),
        "sig_sign": stats(_time(lambda: sig.sign(ssk, msg), iterations)),
        "sig_verify": stats(_time(lambda: sig.verify(spk, msg, s), iterations)),
        "sizes_bytes": {
            "kem_public_key": len(kpk), "kem_private_key": len(ksk), "kem_ciphertext": len(ct),
            "sig_public_key": len(spk), "sig_private_key": len(ssk), "signature": len(s),
        },
    }


def run_pipeline(size_mb: float, iterations: int) -> dict:
    """Full real file pipeline on `size_mb` of random data."""
    kem, sig = get_kem(), get_signer()
    rpk, rsk = kem.keygen()
    spk, ssk = sig.keygen()
    rfp, sfp = P.fingerprint(rpk), P.fingerprint(spk)
    data = os.urandom(int(size_mb * 1024 * 1024))
    key, nonce, aad = os.urandom(32), os.urandom(12), b"bench"
    aes_enc, aes_dec, tot_enc, tot_dec, parts = [], [], [], [], []
    for _ in range(iterations):
        t0 = time.perf_counter()
        ct = P.aes_encrypt(key, nonce, data, aad)
        aes_enc.append((time.perf_counter() - t0) * 1000)
        t0 = time.perf_counter()
        P.aes_decrypt(key, nonce, ct, aad)
        aes_dec.append((time.perf_counter() - t0) * 1000)

        t0 = time.perf_counter()
        res = encrypt_package(data, "bench.bin", sender_id=0, sender_sig_private_key=ssk, sender_sig_fingerprint=sfp,
                              receiver_kem_public_key=rpk, receiver_kem_fingerprint=rfp)
        tot_enc.append((time.perf_counter() - t0) * 1000)
        parts.append(res.timings_ms)

        t0 = time.perf_counter()
        pkg = parse_package(res.blob)
        verify_signature(pkg, spk)
        out = decrypt_package(pkg, receiver_kem_private_key=rsk, receiver_kem_fingerprint=rfp)
        tot_dec.append((time.perf_counter() - t0) * 1000)
        assert len(out.plaintext) == len(data)

    mb = len(data) / (1024 * 1024)
    mean = statistics.fmean
    return {
        "size_mb": size_mb,
        "aes_encrypt": {**stats(aes_enc), "throughput_mb_s": mb / (mean(aes_enc) / 1000)},
        "aes_decrypt": {**stats(aes_dec), "throughput_mb_s": mb / (mean(aes_dec) / 1000)},
        "total_encrypt": {**stats(tot_enc), "throughput_mb_s": mb / (mean(tot_enc) / 1000)},
        "total_decrypt": {**stats(tot_dec), "throughput_mb_s": mb / (mean(tot_dec) / 1000)},
        "encrypt_breakdown_ms": {k: mean(p[k] for p in parts) for k in parts[0]},
        "package_overhead_bytes": len(res.blob) - len(data),
    }


def run_comparison(iterations: int) -> dict:
    kem = get_kem()
    pk, sk = kem.keygen()
    ct, _ = kem.encapsulate(pk)
    n = max(1, min(iterations, 20))
    pq = {
        "algorithm": f"{kem.info.name} (FIPS 203)",
        "keygen_ms": _time(kem.keygen, n),
        "encrypt_ms": _time(lambda: kem.encapsulate(pk), n),
        "decrypt_ms": _time(lambda: kem.decapsulate(sk, ct), n),
        "public_key_bytes": len(pk), "private_key_bytes": len(sk), "ciphertext_bytes": len(ct),
    }
    rsa = measure_rsa2048(min(n, 10))
    return {
        "post_quantum": {**{k: v for k, v in pq.items() if not k.endswith("_ms")},
                         **{k: stats(pq[k]) for k in ("keygen_ms", "encrypt_ms", "decrypt_ms")}},
        "rsa": {**{k: v for k, v in rsa.items() if not k.endswith("_ms")},
                **{k: stats(rsa[k]) for k in ("keygen_ms", "encrypt_ms", "decrypt_ms")}},
        "iterations": n,
        "note": "Experimental measurements taken live by this application on this machine.",
    }
