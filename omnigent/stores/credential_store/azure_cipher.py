"""Azure Key Vault / Managed HSM-backed :class:`SecretCipher` — the managed
Azure counterpart to AWS KMS, for deployments that don't run on AWS.

A third implementation of the same ``SecretCipher`` port that
:class:`KmsSecretCipher` and :class:`VaultSecretCipher` implement. The row
identity — ``(workspace_id, user_id, provider, account_id)`` — is passed as
AES-GCM *additional authenticated data*, the direct analogue of KMS's
*encryption context*: the same primitive, enforced by the backend, with no
global-key path. Decryption must present the same AAD, so a wrong row identity
fails authentication and degrades to "reconnect".

AES keys, and therefore AAD, exist only on Managed HSM (``oct``) and Key Vault
Premium (``oct-HSM``). Key Vault Standard is RSA/EC and has no AAD parameter at
all; a non-AES key raises store-wide rather than silently dropping the binding.

Selected with ``OMNIGENT_CREDENTIAL_AZURE_KEY_ID``; credentials come from
``DefaultAzureCredential``, so AKS Workload Identity, a user-assigned managed
identity or a service principal all work unconfigured. Only ``keys/encrypt``
and ``keys/decrypt`` are needed.
"""

from __future__ import annotations

import base64
import logging

_logger = logging.getLogger(__name__)

#: Names the Key Vault / Managed HSM key used to encrypt integration secrets:
#: the full identifier, ``https://<vault>.vault.azure.net/keys/<name>[/<ver>]``.
#: Unset ⇒ the Azure cipher is not selected.
CREDENTIAL_AZURE_KEY_ENV_VAR = "OMNIGENT_CREDENTIAL_AZURE_KEY_ID"

#: AES-256-GCM. The only algorithm this backend uses: AAD exists for GCM alone.
_ALGORITHM = "A256GCM"

#: Envelope marker. A Key Vault ciphertext embeds neither the key identifier nor
#: the GCM nonce and tag, all three of which decryption needs, so they ride with
#: it. The version field reserves room for a second format without migrating
#: rows already written.
_ENVELOPE_PREFIX = "osakv"
_ENVELOPE_VERSION = "1"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    """Strictly decode URL-safe base64; ``urlsafe_b64decode`` would silently drop
    stray characters and accept garbage."""
    return base64.b64decode(text.encode("ascii"), altchars=b"-_", validate=True)


def _wrap(key_id: str, iv: bytes, tag: bytes, ciphertext: bytes) -> str:
    """Envelope a ciphertext with the key identifier, GCM nonce and tag."""
    return ":".join(
        (
            _ENVELOPE_PREFIX,
            _ENVELOPE_VERSION,
            _b64(key_id.encode("utf-8")),
            _b64(iv),
            _b64(tag),
            _b64(ciphertext),
        )
    )


def _unwrap(stored: str) -> tuple[str, bytes, bytes, bytes] | None:
    """Return ``(key_id, iv, tag, ciphertext)``, or ``None`` when *stored* is not
    one of our envelopes (corrupt, or written by another backend)."""
    parts = stored.split(":", 5)
    if len(parts) != 6:
        return None
    prefix, version, key_b64, iv_b64, tag_b64, ct_b64 = parts
    if prefix != _ENVELOPE_PREFIX or version != _ENVELOPE_VERSION:
        return None
    try:
        key_id = _unb64(key_b64).decode("utf-8")
        return (
            key_id,
            _unb64(iv_b64),
            _unb64(tag_b64),
            _unb64(ct_b64),
        )
    except (ValueError, UnicodeDecodeError):
        return None


def _split_key_id(key_id: str) -> tuple[str, str, str | None]:
    """Split a key identifier into ``(vault_url, key_name, version)``.

    The vault URL is lowercased and any trailing slash dropped so a pasted or
    differently-cased identifier is not mistaken for a different key.
    """
    parts = key_id.strip().rstrip("/").split("/")
    if len(parts) < 5 or parts[0].lower() not in ("https:", "http:") or parts[3] != "keys":
        raise ValueError(
            f"{CREDENTIAL_AZURE_KEY_ENV_VAR} must be a full Key Vault key identifier "
            f"like https://<vault>.vault.azure.net/keys/<name>[/<version>], got {key_id!r}"
        )
    vault_url = "/".join(parts[:3]).lower()
    return vault_url, parts[4], parts[5] if len(parts) > 5 else None
