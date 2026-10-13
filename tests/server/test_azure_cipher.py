"""Envelope and key-identifier handling for the Azure Key Vault cipher."""

from __future__ import annotations

import pytest

from omnigent.stores.credential_store.azure_cipher import (
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
