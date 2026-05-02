"""
MUTE :: crypto.py
All cryptographic operations.

Passphrase → HKDF → room_key + daily_onion_seed
Ephemeral X25519 ECDH → session_key (Perfect Forward Secrecy)
XSalsa20-Poly1305 encryption with random-length padding
HMAC-protected public key exchange (MITM prevention)
"""

import os
import ctypes
import hashlib
import hmac
import base64
import struct
from datetime import date, timedelta
from typing import Optional, Tuple

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import nacl.public
import nacl.secret
import nacl.utils
import nacl.bindings
import nacl.signing


APP_CONTEXT = b"mute-v1"
PADDING_BLOCK = 1024  # bytes — all messages padded to multiple of this


# ─── Key Derivation ────────────────────────────────────────────────────────────

def derive_keys(passphrase: str, for_date=None) -> Tuple[bytearray, bytearray]:
    """
    Passphrase → (room_key, daily_onion_seed)
    room_key:        used to authenticate public keys during handshake (MITM prevention)
    daily_onion_seed: deterministic .onion address, rotates every day
    Returns bytearrays so they can be securely wiped after use.
    """
    pw = passphrase.encode("utf-8")

    room_key = bytearray(HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=APP_CONTEXT + b":room-key",
    ).derive(pw))

    day = (for_date or date.today()).isoformat().encode("utf-8")
    daily_seed = bytearray(HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=day,
        info=APP_CONTEXT + b":onion-seed",
    ).derive(pw))

    return room_key, daily_seed


def seed_to_onion(daily_seed: bytes) -> Tuple[bytes, str]:
    """
    Deterministically derive Ed25519 key seed and v3 .onion address from daily_seed.
    Returns (key_seed_32_bytes, "xxxx...xxxx.onion")
    Both parties compute identical results from the same passphrase on the same day.
    """
    key_seed = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=APP_CONTEXT + b":onion-key",
    ).derive(bytes(daily_seed))

    signing_key = nacl.signing.SigningKey(key_seed)
    pubkey = bytes(signing_key.verify_key)  # 32 bytes Ed25519 pubkey

    # v3 .onion address: base32(pubkey[32] + checksum[2] + version[1])
    version = b"\x03"
    checksum = hashlib.sha3_256(b".onion checksum" + pubkey + version).digest()[:2]
    onion_bytes = pubkey + checksum + version  # 35 bytes total
    hostname = base64.b32encode(onion_bytes).decode().lower() + ".onion"

    return key_seed, hostname


def key_seed_to_expanded(key_seed: bytes) -> str:
    """
    Expand 32-byte seed to 64-byte Ed25519 private key (RFC 8032 clamp),
    return as base64 string for stem's create_ephemeral_hidden_service.
    """
    h = bytearray(hashlib.sha512(key_seed).digest())
    h[0]  &= 248
    h[31] &= 127
    h[31] |= 64
    return base64.b64encode(bytes(h)).decode()


# ─── Ephemeral ECDH Handshake ──────────────────────────────────────────────────

def generate_keypair() -> Tuple[nacl.public.PrivateKey, bytes]:
    """Generate fresh X25519 ephemeral keypair. Returns (privkey, pubkey_bytes[32])."""
    priv = nacl.public.PrivateKey.generate()
    return priv, bytes(priv.public_key)


def sign_pubkey(pubkey_bytes: bytes, room_key: bytes) -> bytes:
    """HMAC-SHA256(pubkey, room_key) — prevents relay/MITM from swapping public keys."""
    return hmac.new(bytes(room_key), pubkey_bytes, hashlib.sha256).digest()


def verify_pubkey(pubkey_bytes: bytes, mac: bytes, room_key: bytes) -> bool:
    """Verify HMAC of received pubkey. Returns False if tampered."""
    expected = hmac.new(bytes(room_key), pubkey_bytes, hashlib.sha256).digest()
    return hmac.compare_digest(expected, mac)


def derive_session_key(our_priv: nacl.public.PrivateKey,
                       their_pub_bytes: bytes,
                       room_key: bytes) -> bytearray:
    """
    X25519 ECDH shared secret → HKDF-SHA256 with room_key as salt.
    Returns bytearray so it can be securely wiped during PFS rotation.
    """
    shared = nacl.bindings.crypto_box_beforenm(their_pub_bytes, bytes(our_priv))

    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(room_key),
        info=APP_CONTEXT + b":session",
    ).derive(shared)

    return bytearray(session_key)


def confirm_token(session_key: bytes) -> bytes:
    """Both sides compute this after handshake to verify matching session keys."""
    return hmac.new(bytes(session_key), b"mute-confirm", hashlib.sha256).digest()


# ─── Message Encryption ────────────────────────────────────────────────────────

def encrypt(plaintext: str, session_key: bytes) -> bytes:
    """
    Encrypt with random-length padding:
    - padded to next multiple of PADDING_BLOCK
    - plus 0-3 extra random blocks
    Hides message length from traffic analysis.
    """
    data = plaintext.encode("utf-8")
    extra_blocks = int.from_bytes(os.urandom(1), "big") % 4
    target = ((len(data) // PADDING_BLOCK) + 1 + extra_blocks) * PADDING_BLOCK
    padded = data + b"\x00" * (target - len(data))

    box = nacl.secret.SecretBox(bytes(session_key))
    return box.encrypt(padded)


def decrypt(ciphertext: bytes, session_key: bytes) -> str:
    """Decrypt and strip null-byte padding."""
    box = nacl.secret.SecretBox(bytes(session_key))
    padded = box.decrypt(ciphertext)
    return padded.rstrip(b"\x00").decode("utf-8")


# ─── Message Framing ───────────────────────────────────────────────────────────

def frame(ciphertext: bytes) -> bytes:
    """Prefix ciphertext with 4-byte big-endian length."""
    return struct.pack(">I", len(ciphertext)) + ciphertext


def read_length(header: bytes) -> int:
    """Parse 4-byte big-endian length prefix."""
    return struct.unpack(">I", header)[0]


# ─── Secure Memory Wipe ────────────────────────────────────────────────────────

def wipe(ba: bytearray) -> None:
    """Overwrite bytearray in-place with zeros. Use for all key material."""
    if isinstance(ba, bytearray) and len(ba) > 0:
        for i in range(len(ba)):
            ba[i] = 0