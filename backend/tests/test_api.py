"""API-level integration tests: auth, keys, full share/verify/decrypt flow, attacks."""
import os
from pathlib import Path

from tests.conftest import PASSWORD, register


def upload(client, headers, receiver_id, data=b"hello pqc world", name="note.txt"):
    return client.post("/files/upload", headers=headers, data={"receiver_id": receiver_id}, files={"file": (name, data)})


def test_registration_password_hashing_and_login(client):
    uid, h = register(client, "alice")
    from app.core.db import get_db
    from app.models import User

    db = next(get_db())
    u = db.get(User, uid)
    assert u.password_hash.startswith("$argon2id$") and PASSWORD not in u.password_hash
    assert client.post("/auth/login", json={"username": "alice", "password": PASSWORD}).status_code == 200
    assert client.post("/auth/login", json={"username": "alice", "password": "wrong"}).status_code == 401
    assert client.post("/auth/register", json={"username": "alice", "email": "x@y.com", "password": PASSWORD}).status_code == 409
    assert client.post("/auth/register", json={"username": "weak", "email": "w@y.com", "password": "short"}).status_code == 422
    assert client.get("/auth/me", headers=h).json()["username"] == "alice"


def test_logout_revokes_token(client):
    _, h = register(client, "alice")
    assert client.post("/auth/logout", headers=h).status_code == 204
    assert client.get("/auth/me", headers=h).status_code == 401
    assert client.get("/dashboard").status_code == 401


def test_login_throttle(client):
    register(client, "alice")
    codes = [client.post("/auth/login", json={"username": "alice", "password": "bad"}).status_code for _ in range(10)]
    assert codes[-1] == 429


def test_keys_generated_separate_and_private_never_exposed(client):
    _, h = register(client, "alice")
    keys = client.get("/keys", headers=h).json()
    assert {k["kind"] for k in keys} == {"KEM", "SIG"}
    kem = next(k for k in keys if k["kind"] == "KEM"); sig = next(k for k in keys if k["kind"] == "SIG")
    assert kem["algorithm"] == "ML-KEM-768" and sig["algorithm"] == "ML-DSA-65" and kem["fingerprint"] != sig["fingerprint"]
    text = client.get("/keys", headers=h).text + client.get("/keys/public", headers=h).text
    assert "private" not in text.lower().replace("private_key_bytes", "")
    assert "wrapped" not in text.lower()


def test_full_flow_encrypt_verify_decrypt_download(client):
    aid, ah = register(client, "alice"); bid, bh = register(client, "bob")
    data = os.urandom(300_000)
    r = upload(client, ah, bid, data, "../../evil/../report.pdf")
    assert r.status_code == 201, r.text
    share = r.json()["share"]
    assert share["filename"] == "report.pdf" and share["status"] == "ENCRYPTED"  # path stripped

    inbox = client.get("/files/received", headers=bh).json()
    assert len(inbox) == 1 and inbox[0]["sender"]["username"] == "alice"
    assert client.get("/files/sent", headers=ah).json()[0]["receiver"]["username"] == "bob"
    assert client.get(f"/files/{share['id']}/package", headers=bh).json()["kem_algorithm"] == "ML-KEM-768"

    assert client.get(f"/files/{share['id']}/download", headers=bh).status_code == 409  # must decrypt first
    v = client.post(f"/files/{share['id']}/verify", headers=bh).json()
    assert v["signature_valid"] and v["share"]["status"] == "VERIFIED"
    d = client.post(f"/files/{share['id']}/decrypt", headers=bh)
    assert d.status_code == 200 and d.json()["share"]["status"] == "DECRYPTED"
    dl = client.get(f"/files/{share['id']}/download", headers=bh)
    assert dl.content == data and "report.pdf" in dl.headers["content-disposition"]

    stats = client.get("/dashboard", headers=bh).json()
    assert stats["files_received"] == 1 and stats["successful_decryptions"] == 1 and stats["failed_integrity_checks"] == 0


def test_stored_package_does_not_contain_plaintext(client):
    _, ah = register(client, "alice"); bid, _ = register(client, "bob")
    marker = b"SUPER-SECRET-MARKER-" * 20
    upload(client, ah, bid, marker)
    from app.core.config import get_settings
    blobs = list(get_settings().packages_path.glob("*.pqsh"))
    assert len(blobs) == 1 and b"SUPER-SECRET-MARKER" not in blobs[0].read_bytes()


def test_tampered_stored_file_is_rejected_with_clear_message(client):
    """Encrypt -> modify one byte on disk -> decrypt MUST fail, no data returned."""
    _, ah = register(client, "alice"); bid, bh = register(client, "bob")
    sid = upload(client, ah, bid, os.urandom(5000)).json()["share"]["id"]
    from app.core.config import get_settings
    p = next(get_settings().packages_path.glob("*.pqsh"))
    raw = bytearray(p.read_bytes()); raw[-100] ^= 0x01; p.write_bytes(bytes(raw))

    r = client.post(f"/files/{sid}/decrypt", headers=bh)
    assert r.status_code == 422 and "Integrity verification failed" in r.json()["detail"]
    assert client.get(f"/files/{sid}/download", headers=bh).status_code == 409
    assert client.get("/files/received", headers=bh).json()[0]["status"] == "INTEGRITY_FAILED"
    assert client.get("/dashboard", headers=bh).json()["failed_integrity_checks"] == 1
    events = [e["event"] for e in client.get("/audit", headers=bh).json()]
    assert "INTEGRITY_CHECK_FAILED" in events or "SIGNATURE_INVALID" in events


def test_other_users_cannot_access_or_decrypt(client):
    _, ah = register(client, "alice"); bid, bh = register(client, "bob"); _, ch = register(client, "carol")
    sid = upload(client, ah, bid).json()["share"]["id"]
    for path, method in ((f"/files/{sid}", "get"), (f"/files/{sid}/decrypt", "post"), (f"/files/{sid}/verify", "post"),
                         (f"/files/{sid}/download", "get"), (f"/files/{sid}/package", "get")):
        assert getattr(client, method)(path, headers=ch).status_code == 404
    # the sender cannot decrypt what they sent either (no KEM private key for it)
    assert client.post(f"/files/{sid}/decrypt", headers=ah).status_code == 404


def test_validation_limits(client):
    aid, ah = register(client, "alice"); bid, _ = register(client, "bob")
    assert upload(client, ah, aid).status_code == 400  # self
    assert upload(client, ah, 9999).status_code == 404
    assert upload(client, ah, bid, b"").status_code == 400
    assert upload(client, ah, bid, b"x" * (3 * 1024 * 1024)).status_code == 413  # limit is 2 MB in tests
    assert client.post("/files/upload", data={"receiver_id": bid}, files={"file": ("a", b"b")}).status_code == 401


def test_forward_reshare(client):
    _, ah = register(client, "alice"); bid, bh = register(client, "bob"); cid, ch = register(client, "carol")
    sid = upload(client, ah, bid, b"chain of custody").json()["share"]["id"]
    r = client.post(f"/files/{sid}/share", headers=bh, json={"receiver_id": cid})
    assert r.status_code == 201
    new = r.json()["share"]
    assert new["sender"]["username"] == "bob" and new["receiver"]["username"] == "carol"
    client.post(f"/files/{new['id']}/decrypt", headers=ch)
    assert client.get(f"/files/{new['id']}/download", headers=ch).content == b"chain of custody"


def test_audit_log_contains_no_secrets(client):
    _, ah = register(client, "alice"); bid, bh = register(client, "bob")
    upload(client, ah, bid, b"plaintext-should-never-be-logged")
    from app.core.db import get_db
    from app.models import AuditLog
    db = next(get_db())
    blob = " ".join(f"{r.event} {r.detail}" for r in db.query(AuditLog))
    assert PASSWORD not in blob and "plaintext-should-never-be-logged" not in blob
    events = {r.event for r in db.query(AuditLog)}
    assert {"USER_REGISTERED", "FILE_UPLOADED", "FILE_ENCRYPTED", "FILE_SHARED", "FILE_RECEIVED"} <= events


def test_security_info_and_benchmark_run(client):
    _, h = register(client, "alice")
    info = client.get("/security/info", headers=h).json()
    assert info["algorithms"]["kem"]["name"] == "ML-KEM-768" and info["algorithms"]["signature"]["name"] == "ML-DSA-65"
    r = client.post("/benchmarks/run", headers=h, json={"sizes_mb": [0.1], "iterations": 2})
    assert r.status_code == 200, r.text
    res = r.json()["results"]
    assert res["primitives"]["kem_encapsulate"]["mean_ms"] > 0
    assert res["pipeline"][0]["total_decrypt"]["throughput_mb_s"] > 0
    assert res["comparison"]["rsa"]["public_key_bytes"] > 0
    assert len(client.get("/benchmarks", headers=h).json()) == 1
