from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from backup_crypto import _write_new_file, decrypt_file, encrypt_file

PASSWORD = "TCC-Seguridad-Backup-2026!"


def test_encrypt_decrypt_roundtrip(tmp_path: Path):
    original = tmp_path / "backup.zip"
    encrypted = tmp_path / "backup.zip.enc"
    restored = tmp_path / "restored.zip"
    original.write_bytes(b"contenido de prueba del backup" * 100)

    encrypt_file(original, encrypted, PASSWORD)
    decrypt_file(encrypted, restored, PASSWORD)

    assert restored.read_bytes() == original.read_bytes()
    assert original.exists()


def test_wrong_password_does_not_create_output(tmp_path: Path):
    original = tmp_path / "backup.zip"
    encrypted = tmp_path / "backup.enc"
    restored = tmp_path / "restored.zip"
    original.write_bytes(b"datos confidenciales")
    encrypt_file(original, encrypted, PASSWORD)

    with pytest.raises(InvalidTag):
        decrypt_file(encrypted, restored, "otra contraseña incorrecta")

    assert not restored.exists()


def test_tampered_ciphertext_is_rejected(tmp_path: Path):
    original = tmp_path / "backup.zip"
    encrypted = tmp_path / "backup.enc"
    restored = tmp_path / "restored.zip"
    original.write_bytes(b"datos")
    encrypt_file(original, encrypted, PASSWORD)

    content = bytearray(encrypted.read_bytes())
    content[-1] ^= 0x01
    encrypted.write_bytes(content)

    with pytest.raises(InvalidTag):
        decrypt_file(encrypted, restored, PASSWORD)

    assert not restored.exists()


def test_existing_destination_is_not_overwritten(tmp_path: Path):
    original = tmp_path / "backup.zip"
    encrypted = tmp_path / "backup.enc"
    original.write_bytes(b"datos")
    encrypted.write_bytes(b"no sobrescribir")

    with pytest.raises(FileExistsError):
        encrypt_file(original, encrypted, PASSWORD)

    assert encrypted.read_bytes() == b"no sobrescribir"


def test_empty_file_roundtrip(tmp_path: Path):
    original = tmp_path / "empty.zip"
    encrypted = tmp_path / "empty.enc"
    restored = tmp_path / "empty-restored.zip"
    original.write_bytes(b"")

    encrypt_file(original, encrypted, PASSWORD)
    decrypt_file(encrypted, restored, PASSWORD)

    assert restored.read_bytes() == b""


def test_encryption_rejects_short_password(tmp_path: Path):
    original = tmp_path / "backup.zip"
    encrypted = tmp_path / "backup.enc"
    original.write_bytes(b"datos")

    with pytest.raises(ValueError, match="al menos 12 caracteres"):
        encrypt_file(original, encrypted, "short")

    assert not encrypted.exists()


def test_open_race_does_not_delete_another_process_file(tmp_path: Path, monkeypatch):
    destination = tmp_path / "created-by-another-process.enc"
    other_process_content = b"contenido ajeno"
    real_open = Path.open

    def simulate_exclusive_create_race(path: Path, mode: str = "r", *args, **kwargs):
        if path == destination and mode == "xb":
            destination.write_bytes(other_process_content)
            raise FileExistsError("El archivo fue creado concurrentemente.")
        return real_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", simulate_exclusive_create_race)

    with pytest.raises(FileExistsError):
        _write_new_file(destination, b"contenido propio")

    assert destination.read_bytes() == other_process_content
