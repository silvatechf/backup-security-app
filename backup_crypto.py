"""Cifrado y recuperación de archivos de backup mediante AES-256-GCM.

V1: procesa cada archivo completo en memoria. Para archivos grandes,
utilizar una futura implementación autenticada por bloques/streaming.
"""
from __future__ import annotations

import argparse
import getpass
import os
import struct
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"BKSEC001"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32  # 32 bytes = AES-256
ITERATIONS = 600_000
MIN_PASSWORD_LENGTH = 12
HEADER_FORMAT = ">8sI16s12s"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)


def derive_key(password: str, salt: bytes, iterations: int = ITERATIONS) -> bytes:
    """Deriva una clave de 256 bits a partir de una contraseña y una sal."""
    if not password:
        raise ValueError("La contraseña no puede estar vacía.")
    if len(salt) != SALT_SIZE:
        raise ValueError("Longitud de sal no válida.")
    if iterations != ITERATIONS:
        raise ValueError("Parámetros de derivación no admitidos.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def _validate_paths(source: Path, destination: Path) -> None:
    if source.is_symlink() or not source.is_file():
        raise ValueError("El archivo de origen no existe o no es un archivo regular.")
    if source.resolve() == destination.resolve():
        raise ValueError("El origen y el destino deben ser diferentes.")
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"El destino ya existe: {destination}")


def _write_new_file(destination: Path, content: bytes) -> None:
    """Crea un archivo nuevo sin sobrescribir ni borrar archivos ajenos."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    created_by_this_operation = False

    try:
        output = destination.open("xb")
        created_by_this_operation = True
        with output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        # Solo se elimina un archivo cuya creación exclusiva tuvo éxito aquí.
        if created_by_this_operation:
            try:
                destination.unlink(missing_ok=True)
            except OSError:
                pass
        raise


def encrypt_file(source: Path, destination: Path, password: str) -> None:
    """Cifra un archivo y conserva intacto el original."""
    source = Path(source)
    destination = Path(destination)
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"La contraseña debe tener al menos {MIN_PASSWORD_LENGTH} caracteres."
        )
    _validate_paths(source, destination)

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    header = struct.pack(HEADER_FORMAT, MAGIC, ITERATIONS, salt, nonce)
    key = derive_key(password, salt)

    plaintext = source.read_bytes()
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, header)
    _write_new_file(destination, header + ciphertext)


def decrypt_file(source: Path, destination: Path, password: str) -> None:
    """Descifra un archivo solo si la etiqueta de autenticación es válida."""
    source = Path(source)
    destination = Path(destination)
    _validate_paths(source, destination)

    encrypted_data = source.read_bytes()
    if len(encrypted_data) < HEADER_SIZE + 16:
        raise ValueError("Archivo cifrado incompleto o demasiado corto.")

    header = encrypted_data[:HEADER_SIZE]
    magic, iterations, salt, nonce = struct.unpack(HEADER_FORMAT, header)

    if magic != MAGIC:
        raise ValueError("Formato de archivo no reconocido.")
    if iterations != ITERATIONS:
        raise ValueError("Parámetros criptográficos no admitidos.")

    key = derive_key(password, salt, iterations)
    plaintext = AESGCM(key).decrypt(
        nonce,
        encrypted_data[HEADER_SIZE:],
        header,
    )
    _write_new_file(destination, plaintext)


def _read_password(operation: str) -> str:
    password = getpass.getpass("Introduzca la contraseña: ")
    if operation == "encrypt":
        confirmation = getpass.getpass("Confirme la contraseña: ")
        if password != confirmation:
            raise ValueError("Las contraseñas no coinciden.")
    elif not password:
        raise ValueError("La contraseña no puede estar vacía.")
    return password


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Protección de copias de seguridad mediante AES-256-GCM."
    )
    parser.add_argument("operation", choices=("encrypt", "decrypt"))
    parser.add_argument("source", type=Path, help="Archivo de origen.")
    parser.add_argument("destination", type=Path, help="Archivo de destino.")
    args = parser.parse_args()

    try:
        password = _read_password(args.operation)
        if args.operation == "encrypt":
            encrypt_file(args.source, args.destination, password)
            print(f"Backup cifrado correctamente: {args.destination}")
        else:
            decrypt_file(args.source, args.destination, password)
            print(f"Backup recuperado correctamente: {args.destination}")
        return 0
    except InvalidTag:
        print(
            "Error: contraseña incorrecta o archivo manipulado/corrupto.",
            file=sys.stderr,
        )
        return 1
    except (ValueError, FileExistsError, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
