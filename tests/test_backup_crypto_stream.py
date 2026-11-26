from pathlib import Path
import struct

import pytest
from cryptography.exceptions import InvalidTag

from backup_crypto_stream import (
    HEADER_SIZE,
    RECORD_DATA,
    RECORD_FINAL,
    RECORD_FORMAT,
    RECORD_HEADER_SIZE,
    decrypt_file_streaming,
    encrypt_file_streaming,
)

PASSWORD = "TCC-Streaming-Backup-2026!"


def _records(encrypted: bytes, chunk_size: int):
    """Devuelve los registros completos de un archivo de prueba V2."""
    offset = HEADER_SIZE
    result = []
    while offset < len(encrypted):
        record_header = encrypted[offset : offset + RECORD_HEADER_SIZE]
        record_type, _counter, plaintext_size = struct.unpack(
            RECORD_FORMAT,
            record_header,
        )
        record_size = RECORD_HEADER_SIZE + (
            plaintext_size + 16 if record_type == RECORD_DATA else 16
        )
        result.append(encrypted[offset : offset + record_size])
        offset += record_size
        if record_type == RECORD_FINAL:
            break
    assert offset == len(encrypted)
    return result


def test_streaming_roundtrip_multiple_blocks(tmp_path: Path):
    original = tmp_path / "backup.bin"
    encrypted = tmp_path / "backup.bin.enc"
    restored = tmp_path / "restored.bin"
    payload = bytes(range(256)) * 29
    original.write_bytes(payload)

    encrypt_file_streaming(original, encrypted, PASSWORD, chunk_size=1024)
    decrypt_file_streaming(encrypted, restored, PASSWORD)

    assert restored.read_bytes() == payload
    assert original.read_bytes() == payload
    assert encrypted.exists()


def test_empty_file_roundtrip(tmp_path: Path):
    original = tmp_path / "empty.bin"
    encrypted = tmp_path / "empty.enc"
    restored = tmp_path / "empty-restored.bin"
    original.write_bytes(b"")

    encrypt_file_streaming(original, encrypted, PASSWORD, chunk_size=1024)
    decrypt_file_streaming(encrypted, restored, PASSWORD)

    assert restored.read_bytes() == b""


def test_wrong_password_does_not_publish_plaintext(tmp_path: Path):
    original = tmp_path / "source.bin"
    encrypted = tmp_path / "source.enc"
    restored = tmp_path / "restored.bin"
    original.write_bytes(b"secret" * 500)

    encrypt_file_streaming(original, encrypted, PASSWORD, chunk_size=1024)

    with pytest.raises(InvalidTag):
        decrypt_file_streaming(encrypted, restored, "wrong-password-123")

    assert not restored.exists()
    assert not list(tmp_path.glob(".backup-security-*.tmp"))


def test_tampered_later_block_does_not_publish_partial_plaintext(tmp_path: Path):
    original = tmp_path / "source.bin"
    encrypted = tmp_path / "source.enc"
    restored = tmp_path / "restored.bin"
    original.write_bytes(b"A" * 1024 + b"B" * 1024 + b"C" * 100)

    encrypt_file_streaming(original, encrypted, PASSWORD, chunk_size=1024)
    content = bytearray(encrypted.read_bytes())
    second_record_offset = HEADER_SIZE + RECORD_HEADER_SIZE + 1024 + 16
    content[second_record_offset + RECORD_HEADER_SIZE + 10] ^= 0x01
    encrypted.write_bytes(content)

    with pytest.raises(InvalidTag):
        decrypt_file_streaming(encrypted, restored, PASSWORD)

    assert not restored.exists()
    assert not list(tmp_path.glob(".backup-security-*.tmp"))


def test_truncated_file_is_rejected(tmp_path: Path):
    original = tmp_path / "source.bin"
    encrypted = tmp_path / "source.enc"
    restored = tmp_path / "restored.bin"
    original.write_bytes(b"Z" * 2048)

    encrypt_file_streaming(original, encrypted, PASSWORD, chunk_size=1024)
    encrypted.write_bytes(encrypted.read_bytes()[:-7])

    with pytest.raises(ValueError, match="truncado|incompleto"):
        decrypt_file_streaming(encrypted, restored, PASSWORD)

    assert not restored.exists()


def test_reordered_records_are_rejected(tmp_path: Path):
    original = tmp_path / "source.bin"
    encrypted = tmp_path / "source.enc"
    restored = tmp_path / "restored.bin"
    original.write_bytes(b"A" * 1024 + b"B" * 1024)

    encrypt_file_streaming(original, encrypted, PASSWORD, chunk_size=1024)
    content = encrypted.read_bytes()
    records = _records(content, 1024)
    assert len(records) == 3
    reordered = content[:HEADER_SIZE] + records[1] + records[0] + records[2]
    encrypted.write_bytes(reordered)

    with pytest.raises(ValueError, match="Secuencia"):
        decrypt_file_streaming(encrypted, restored, PASSWORD)

    assert not restored.exists()


def test_trailing_data_after_final_record_is_rejected(tmp_path: Path):
    original = tmp_path / "source.bin"
    encrypted = tmp_path / "source.enc"
    restored = tmp_path / "restored.bin"
    original.write_bytes(b"payload")

    encrypt_file_streaming(original, encrypted, PASSWORD, chunk_size=1024)
    encrypted.write_bytes(encrypted.read_bytes() + b"unexpected")

    with pytest.raises(ValueError, match="después del registro FINAL"):
        decrypt_file_streaming(encrypted, restored, PASSWORD)

    assert not restored.exists()


def test_existing_destination_is_never_overwritten(tmp_path: Path):
    original = tmp_path / "source.bin"
    encrypted = tmp_path / "source.enc"
    original.write_bytes(b"payload")
    encrypted.write_bytes(b"preserve-me")

    with pytest.raises(FileExistsError):
        encrypt_file_streaming(original, encrypted, PASSWORD, chunk_size=1024)

    assert encrypted.read_bytes() == b"preserve-me"


def test_short_password_is_rejected(tmp_path: Path):
    original = tmp_path / "source.bin"
    encrypted = tmp_path / "source.enc"
    original.write_bytes(b"payload")

    with pytest.raises(ValueError, match="al menos 12 caracteres"):
        encrypt_file_streaming(original, encrypted, "short", chunk_size=1024)

    assert not encrypted.exists()


def test_invalid_chunk_size_is_rejected(tmp_path: Path):
    original = tmp_path / "source.bin"
    encrypted = tmp_path / "source.enc"
    original.write_bytes(b"payload")

    with pytest.raises(ValueError, match="tamaño de bloque"):
        encrypt_file_streaming(original, encrypted, PASSWORD, chunk_size=10)

    assert not encrypted.exists()
