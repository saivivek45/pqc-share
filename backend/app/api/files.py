from __future__ import annotations

from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Response, UploadFile, status
from sqlalchemy.orm import Session

from app.api.deps import client_ip, current_user
from app.core.config import get_settings
from app.core.db import get_db
from app.crypto import parse_package
from app.models import User
from app.schemas import DecryptOut, ShareIn, ShareOut, UploadOut, VerifyOut
from app.services import file_service as fs

router = APIRouter(prefix="/files", tags=["files"])


def _handle(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except fs.ShareError as e:
        raise HTTPException(e.status, e.message)


async def _read_limited(upload: UploadFile) -> bytes:
    limit = get_settings().max_upload_bytes
    buf = bytearray()
    while chunk := await upload.read(1024 * 1024):
        buf += chunk
        if len(buf) > limit:
            raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, f"File exceeds the {get_settings().max_upload_mb} MB limit.")
    return bytes(buf)


@router.post("/upload", response_model=UploadOut, status_code=status.HTTP_201_CREATED)
async def upload(request: Request, receiver_id: int = Form(...), file: UploadFile = File(...),
                 user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Encrypt & share in one step; plaintext is never written to disk."""
    receiver = db.get(User, receiver_id)
    if receiver is None:
        raise HTTPException(404, "Recipient not found.")
    data = await _read_limited(file)
    share, timings = _handle(fs.encrypt_and_share, db, user, receiver, file.filename, data, client_ip(request))
    return UploadOut(share=fs.to_out(share), timings_ms=timings)


@router.get("/sent", response_model=list[ShareOut])
def sent(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return [fs.to_out(s) for s in fs.list_shares(db, user, "sent")]


@router.get("/received", response_model=list[ShareOut])
def received(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return [fs.to_out(s) for s in fs.list_shares(db, user, "received")]


@router.get("/{share_id}", response_model=ShareOut)
def detail(share_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return fs.to_out(_handle(fs.get_share_for, db, share_id, user))


@router.get("/{share_id}/package")
def package_header(share_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Public package metadata (no secrets are inside a package header)."""
    share = _handle(fs.get_share_for, db, share_id, user)
    pkg = _handle(lambda: parse_package(fs.read_package(share.file.storage_name)))
    h = dict(pkg.header)
    for k in ("kem_ciphertext", "signature", "nonce"):
        h[k + "_preview"] = h[k][:48] + "…"
        h[k + "_bytes"] = len(h[k]) * 3 // 4
        del h[k]
    return h


@router.post("/{share_id}/verify", response_model=VerifyOut)
def verify(share_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    share = _handle(fs.get_share_for, db, share_id, user, as_receiver=True)
    pkg = _handle(fs.verify_share, db, share, user, client_ip(request))
    return VerifyOut(share=fs.to_out(share), signature_valid=True, sender_fingerprint=pkg.header["sender_fingerprint"],
                     algorithm=pkg.header["signature_algorithm"], message="Sender signature verified.")


@router.post("/{share_id}/decrypt", response_model=DecryptOut)
def decrypt(share_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    share = _handle(fs.get_share_for, db, share_id, user, as_receiver=True)
    res = _handle(fs.decrypt_share, db, share, user, client_ip(request))
    return DecryptOut(share=fs.to_out(share), timings_ms=res.timings_ms,
                      message="Signature verified, GCM authentication tag valid. File is ready to download.")


@router.get("/{share_id}/download")
def download(share_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    share = _handle(fs.get_share_for, db, share_id, user, as_receiver=True)
    res = _handle(fs.download_share, db, share, user, client_ip(request))
    return Response(res.plaintext, media_type="application/octet-stream", headers={
        "Content-Disposition": f"attachment; filename*=UTF-8''{quote(res.filename)}",
        "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
    })


@router.post("/{share_id}/share", response_model=UploadOut, status_code=status.HTTP_201_CREATED)
def forward(share_id: int, body: ShareIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Re-share a file you received: verified+decrypted in memory, re-encrypted for a new receiver, re-signed by you."""
    share = _handle(fs.get_share_for, db, share_id, user, as_receiver=True)
    receiver = db.get(User, body.receiver_id)
    if receiver is None:
        raise HTTPException(404, "Recipient not found.")
    new, timings = _handle(fs.forward_share, db, share, user, receiver, client_ip(request))
    return UploadOut(share=fs.to_out(new), timings_ms=timings)
