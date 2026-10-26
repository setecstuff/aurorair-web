"""
Security primitives: password hashing, encryption of secrets at rest, TOTP (MFA), IP allowlists, enrolment QR.

* Passwords: Argon2id (argon2-cffi defaults = RFC 9106 "low memory" profile: t=3, m=64 MiB, p=4) with a random
  16-byte salt per hash, stored as a PHC string. Hashes are re-computed transparently when parameters change.
* Secrets at rest (TOTP seeds, MISP / VirusTotal API keys): AES-256-GCM, key derived from SECRET_KEY with HKDF.
* TOTP: RFC 6238, SHA-1, 6 digits, 30 s, +-1 step tolerance, a code is accepted only once (replay protection).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import ipaddress
import os
import secrets
import struct
import time
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import settings

STATIC_DIR = Path(__file__).parent / "static"
LOGO_PNG = STATIC_DIR / "logo.png"

# --------------------------------------------------------------------------- #
# Passwords
# --------------------------------------------------------------------------- #

_ph = PasswordHasher()       # Argon2id, salt_len=16 (random per hash), hash_len=32


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password: str, stored: str) -> bool:
    try:
        return _ph.verify(stored, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError, ValueError, TypeError):
        return False


def needs_rehash(stored: str) -> bool:
    try:
        return _ph.check_needs_rehash(stored)
    except (InvalidHashError, ValueError):
        return True


DUMMY_HASH = hash_password(secrets.token_urlsafe(16))   # equalises login timing for unknown users

# --------------------------------------------------------------------------- #
# Encryption of secrets stored in the database
# --------------------------------------------------------------------------- #


class SecretKeyMissing(RuntimeError):
    pass


@lru_cache(maxsize=1)
def _aead() -> AESGCM:
    if len(settings.secret_key) < 32:
        raise SecretKeyMissing("SECRET_KEY must be set (at least 32 characters) - see .env.example")
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"aurora-ir-web", info=b"secrets-at-rest-v1") \
        .derive(settings.secret_key.encode())
    return AESGCM(key)


def check_secret_key() -> None:
    _aead()


def encrypt(plain: str) -> str:
    if not plain:
        return ""
    nonce = os.urandom(12)
    return "v1:" + base64.b64encode(nonce + _aead().encrypt(nonce, plain.encode(), b"aurora")).decode()


def decrypt(token: str | None) -> str:
    if not token:
        return ""
    if not token.startswith("v1:"):
        raise ValueError("unknown secret format")
    raw = base64.b64decode(token[3:])
    return _aead().decrypt(raw[:12], raw[12:], b"aurora").decode()


# --------------------------------------------------------------------------- #
# TOTP (RFC 6238)
# --------------------------------------------------------------------------- #

TOTP_PERIOD, TOTP_DIGITS = 30, 6


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret_b32: str, counter: int) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % 10 ** TOTP_DIGITS
    return str(code).zfill(TOTP_DIGITS)


def totp_now(secret_b32: str, at: float | None = None) -> str:
    return _hotp(secret_b32, int((at or time.time()) // TOTP_PERIOD))


def totp_verify(secret_b32: str, code: str, last_step: int = 0, at: float | None = None) -> int | None:
    """Returns the matched time step (store it as the new last_step) or None. Steps <= last_step are refused."""
    code = (code or "").strip().replace(" ", "")
    if not (code.isdigit() and len(code) == TOTP_DIGITS):
        return None
    now = int((at or time.time()) // TOTP_PERIOD)
    for step in (now - 1, now, now + 1):
        if step > last_step and hmac.compare_digest(_hotp(secret_b32, step), code):
            return step
    return None


def otpauth_uri(secret_b32: str, account: str, image_url: str = "") -> str:
    # Kept short so the QR code stays small: algorithm, digits and period are left out because SHA1 / 6 / 30 s
    # are the otpauth defaults, and the image URL keeps its ':' and '/' (valid in a query value).
    issuer = settings.mfa_issuer
    query = f"secret={secret_b32}&issuer={quote(issuer, safe='')}"
    if image_url:
        query += f"&image={quote(image_url, safe=':/')}"    # shown by FreeOTP and other apps that support it
    return f"otpauth://totp/{quote(issuer, safe='')}:{quote(account, safe='')}?{query}"


def qr_png_with_logo(data: str) -> bytes:
    """Enrolment QR code (error correction H) with the application logo in the centre."""
    import qrcode
    from PIL import Image
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=8, border=3)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#14304f", back_color="white").convert("RGB")
    if LOGO_PNG.exists():
        logo = Image.open(LOGO_PNG).convert("RGBA")
        side = img.size[0] // 4                                # 25% of the width: well within H's 30% margin
        logo = logo.resize((side, side), Image.LANCZOS)
        pad = Image.new("RGB", (side + 12, side + 12), "white")
        pos = ((img.size[0] - pad.size[0]) // 2, (img.size[1] - pad.size[1]) // 2)
        img.paste(pad, pos)
        img.paste(logo, (pos[0] + 6, pos[1] + 6), logo)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


# --------------------------------------------------------------------------- #
# IP allowlists (IPv4 / IPv6 addresses and CIDR ranges; empty = any address)
# --------------------------------------------------------------------------- #

MAX_ALLOWLIST = 100


class AllowlistError(ValueError):
    pass


def normalise_allowlist(entries) -> list[str]:
    if entries is None:
        return []
    if isinstance(entries, str):
        entries = [e for e in entries.replace(",", "\n").split("\n")]
    if not isinstance(entries, list):
        raise AllowlistError("allowlist must be a list of IP addresses / CIDR ranges")
    out: list[str] = []
    for e in entries:
        if not isinstance(e, str):
            raise AllowlistError("allowlist entries must be text")
        e = e.strip()
        if not e:
            continue
        try:
            net = ipaddress.ip_network(e, strict=False)
        except ValueError:
            raise AllowlistError(f"'{e[:60]}' is not an IPv4/IPv6 address or CIDR range")
        s = str(net) if net.num_addresses > 1 else str(net.network_address)
        if s not in out:
            out.append(s)
    if len(out) > MAX_ALLOWLIST:
        raise AllowlistError(f"at most {MAX_ALLOWLIST} entries")
    return out


def ip_allowed(ip: str, allowlist: list[str]) -> bool:
    if not allowlist:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    for e in allowlist:
        try:
            if addr in ipaddress.ip_network(e, strict=False):
                return True
        except (ValueError, TypeError):
            continue
    return False
