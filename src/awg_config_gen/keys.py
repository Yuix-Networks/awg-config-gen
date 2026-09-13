"""WireGuard key material.

X25519 comes from `cryptography` rather than a hand-rolled scalar
multiplication. A config generator's whole job is producing private keys,
and "we implemented the curve ourselves" is not a sentence anyone wants to
read in that context.
"""

import base64
import secrets

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

KEY_BYTES = 32
KEY_B64_LENGTH = 44


class KeyError_(ValueError):
    """A key that is not a valid WireGuard key."""


def generate_private_key():
    """A new X25519 private key, base64 as WireGuard writes it."""
    key = X25519PrivateKey.generate()
    raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return base64.b64encode(raw).decode()


def public_key(private_key_b64):
    """Derive the public key from a private key."""
    raw = decode_key(private_key_b64, "private key")
    key = X25519PrivateKey.from_private_bytes(raw)
    return base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()


def generate_keypair():
    """(private, public), base64."""
    private = generate_private_key()
    return private, public_key(private)


def generate_preshared_key():
    """A symmetric pre-shared key.

    Optional in WireGuard and worth having: it is mixed into the handshake
    so that a future attacker who breaks X25519 still cannot decrypt traffic
    they recorded today.
    """
    return base64.b64encode(secrets.token_bytes(KEY_BYTES)).decode()


def decode_key(value, what="key"):
    """Validate and decode a base64 WireGuard key to 32 raw bytes."""
    if not isinstance(value, str):
        raise KeyError_("%s must be a string, got %s" % (what, type(value).__name__))
    text = value.strip()
    if len(text) != KEY_B64_LENGTH:
        raise KeyError_(
            "%s must be %d base64 characters, got %d"
            % (what, KEY_B64_LENGTH, len(text))
        )
    try:
        raw = base64.b64decode(text, validate=True)
    except Exception as exc:
        raise KeyError_("%s is not valid base64: %s" % (what, exc)) from exc
    if len(raw) != KEY_BYTES:
        raise KeyError_("%s must decode to %d bytes, got %d" % (what, KEY_BYTES, len(raw)))
    return raw


def is_valid_key(value):
    try:
        decode_key(value)
    except KeyError_:
        return False
    return True


def keys_match(private_key_b64, public_key_b64):
    """True when the public key is the one derived from this private key.

    Worth checking before writing a config: a mismatched pair produces a
    tunnel that never completes a handshake, with no error that says why.
    """
    try:
        derived = public_key(private_key_b64)
    except KeyError_:
        return False
    return secrets.compare_digest(derived, public_key_b64.strip())


def validate_public_key(value):
    """Reject public keys that cannot work.

    An all-zero key is a low-order point: the shared secret becomes zero
    regardless of the other side, so the handshake is worthless. `cryptography`
    accepts the bytes happily, which is why this is checked here.
    """
    raw = decode_key(value, "public key")
    try:
        X25519PublicKey.from_public_bytes(raw)
    except Exception as exc:
        raise KeyError_("public key is not a valid X25519 point: %s" % exc) from exc
    if raw == bytes(KEY_BYTES):
        raise KeyError_("public key is all zeroes, which is a low-order point")
    return True
