"""Envelope and key-identifier handling for the Azure Key Vault cipher."""

from __future__ import annotations

from typing import Any

import pytest
from azure.core.exceptions import HttpResponseError

from omnigent.stores.credential_store.azure_cipher import (
    CREDENTIAL_AZURE_KEY_ENV_VAR,
    AzureKeyVaultSecretCipher,
    _split_key_id,
    _unwrap,
    _wrap,
)

KEY_ID = "https://kv.vault.azure.net/keys/omnigent-credentials/9f8e7d"


def test_envelope_roundtrip() -> None:
    stored = _wrap(KEY_ID, b"\x00iv-bytes", b"tag\xff", b"ct\x01\x02")
    assert stored.startswith("osakv:1:")
    assert _unwrap(stored) == (KEY_ID, b"\x00iv-bytes", b"tag\xff", b"ct\x01\x02")


def test_unwrap_rejects_foreign_and_corrupt() -> None:
    # A ciphertext from another backend, read after an operator
    # switches OMNIGENT_CREDENTIAL_CIPHER, must be reported as unrecognized
    # rather than raising.
    assert _unwrap("osvault:b3RoZXI=:vault:v1:abc") is None
    assert _unwrap("AQICAHhwbG9i") is None  # raw base64 KMS blob
    assert _unwrap("") is None
    assert _unwrap("osakv:1:only:three") is None
    assert _unwrap("osakv:2:" + "a:" * 3 + "a") is None  # unknown format version
    assert _unwrap("osakv:1:!!!:!!!:!!!:!!!") is None  # undecodable base64


def test_split_key_id_parses_versioned_and_unversioned() -> None:
    assert _split_key_id(KEY_ID) == (
        "https://kv.vault.azure.net",
        "omnigent-credentials",
        "9f8e7d",
    )
    assert _split_key_id("https://kv.vault.azure.net/keys/k") == (
        "https://kv.vault.azure.net",
        "k",
        None,
    )
    assert _split_key_id("https://h.managedhsm.azure.net/keys/k/v")[0] == (
        "https://h.managedhsm.azure.net"
    )


def test_split_key_id_normalizes_case_and_trailing_slash() -> None:
    # DNS is case-insensitive and operators paste trailing
    # slashes. Neither may read as a different key.
    assert _split_key_id("HTTPS://KV.Vault.Azure.Net/keys/k/") == _split_key_id(
        "https://kv.vault.azure.net/keys/k"
    )


def test_split_key_id_rejects_malformed() -> None:
    for bad in (
        "",
        "not-a-url",
        "https://kv.vault.azure.net",
        "https://kv.vault.azure.net/secrets/s",
    ):
        with pytest.raises(ValueError):
            _split_key_id(bad)


CTX_ALICE = {"workspace_id": "0", "user_id": "alice", "provider": "github", "account_id": ""}
CTX_BOB = {"workspace_id": "0", "user_id": "bob", "provider": "github", "account_id": ""}

#: Stand-in for the service's single-block encrypt limit. The real value is not
#: hardcoded anywhere in the implementation; the fake only needs *a* threshold
#: to prove an oversized payload raises instead of being truncated.
FAKE_BLOCK_LIMIT = 4096


def _http_error(status: int, message: str) -> HttpResponseError:
    err = HttpResponseError(message=message)
    err.status_code = status
    return err


class _FakeCryptoClient:
    """In-memory CryptographyClient: decrypt succeeds only under the same AAD.

    Mirrors ``_FakeKmsClient`` in test_vault_cipher.py — it compares the AAD
    rather than performing real AES-GCM.
    """

    def __init__(self, key_id: str, *, key_type: str = "oct-HSM") -> None:
        self.key_id = key_id
        self._key_type = key_type
        self._store: dict[bytes, tuple[bytes, bytes]] = {}
        self._n = 0
        # Widened beyond HttpResponseError: Task 4 assigns an AssertionError to
        # prove the service is never reached on a key repoint.
        self.raise_on_decrypt: BaseException | None = None

    def encrypt(
        self,
        algorithm: str,
        plaintext: bytes,
        *,
        iv: bytes | None = None,
        additional_authenticated_data: bytes | None = None,
    ) -> Any:
        assert algorithm == "A256GCM"
        assert iv is None, "the service generates the GCM nonce"
        if self._key_type not in ("oct", "oct-HSM"):
            raise _http_error(400, f"algorithm {algorithm} is not supported for key type")
        if len(plaintext) > FAKE_BLOCK_LIMIT:
            raise _http_error(400, "the request payload exceeds the maximum block size")
        self._n += 1
        blob = f"ct-{self._n}".encode()
        self._store[blob] = (additional_authenticated_data or b"", plaintext)
        return _FakeEncryptResult(self.key_id, blob, b"iv-%d" % self._n, b"tag-%d" % self._n)

    def decrypt(
        self,
        algorithm: str,
        ciphertext: bytes,
        *,
        iv: bytes | None = None,
        authentication_tag: bytes | None = None,
        additional_authenticated_data: bytes | None = None,
    ) -> Any:
        if self.raise_on_decrypt is not None:
            raise self.raise_on_decrypt
        entry = self._store.get(ciphertext)
        if entry is None or entry[0] != (additional_authenticated_data or b""):
            raise _http_error(400, "the authentication tag could not be verified")
        return _FakeDecryptResult(entry[1])


class _FakeEncryptResult:
    def __init__(self, key_id: str, ciphertext: bytes, iv: bytes, tag: bytes) -> None:
        self.key_id = key_id
        self.ciphertext = ciphertext
        self.iv = iv
        self.authentication_tag = tag


class _FakeDecryptResult:
    def __init__(self, plaintext: bytes) -> None:
        self.plaintext = plaintext


def _make_azure(*, key_type: str = "oct-HSM") -> AzureKeyVaultSecretCipher:
    return AzureKeyVaultSecretCipher(KEY_ID, client=_FakeCryptoClient(KEY_ID, key_type=key_type))


def test_roundtrip_and_binding() -> None:
    cipher = _make_azure()
    stored = cipher.encrypt("ghu_secret_token", context=CTX_ALICE)
    assert stored.startswith("osakv:1:")
    assert cipher.decrypt(stored, context=CTX_ALICE) == "ghu_secret_token"
    assert cipher.decrypt(stored, context=CTX_BOB) is None


def test_non_ascii_roundtrips() -> None:
    # account_id is a user-facing label and tokens are not guaranteed ASCII;
    # both must survive as UTF-8.
    ctx = {**CTX_ALICE, "account_id": "orgé-日本"}
    cipher = _make_azure()
    assert cipher.decrypt(cipher.encrypt("tøken-✓", context=ctx), context=ctx) == "tøken-✓"


def test_oversized_plaintext_raises() -> None:
    # An over-limit secret must fail loudly, never be truncated.
    cipher = _make_azure()
    with pytest.raises(ValueError, match="single-block"):
        cipher.encrypt("x" * (FAKE_BLOCK_LIMIT + 1), context=CTX_ALICE)


def test_unversioned_key_id_is_rejected() -> None:
    # Without keys/get the SDK reports the configured id, not the version that
    # encrypted, so an unversioned id would orphan every row on rotation.
    with pytest.raises(ValueError, match=CREDENTIAL_AZURE_KEY_ENV_VAR):
        AzureKeyVaultSecretCipher(
            "https://kv.vault.azure.net/keys/omnigent-credentials",
            client=_FakeCryptoClient("https://kv.vault.azure.net/keys/omnigent-credentials"),
        )
