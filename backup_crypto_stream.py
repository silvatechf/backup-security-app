"""Cifrado autenticado por bloques para copias de seguridad (formato V2).

Cada bloque utiliza AES-256-GCM con un nonce derivado de un prefijo aleatorio
por archivo y un contador monotónico. Un registro FINAL autenticado permite
detectar truncamiento incluso cuando el archivo termina en un límite de bloque.

El descifrado escribe primero en un temporal privado y solo publica el resultado
cuando todos los bloques y el registro FINAL han sido autenticados.
"""
from __future__ import annotations

import os
import struct
import tempfile
from pathlib import Path
from typing import BinaryIO

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"BKSCV002"
SALT_SIZE = 16
NONCE_PREFIX_SIZE = 8
KEY_SIZE = 32
ITERATIONS = 600_000
MIN_PASSWORD_LENGTH = 12
MIN_CHUNK_SIZE = 1_024
DEFAULT_CHUNK_SIZE = 1_048_576
MAX_CHUNK_SIZE = 8_388_608
NONCE_COUNTER_MAX = (1 << 32) - 1
TAG_SIZE = 16

HEADER_FORMAT = ">8sI16s8sI"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
RECORD_FORMAT = ">BII"
RECORD_HEADER_SIZE = struct.calcsize(RECORD_FORMAT)
RECORD_DATA = 1
RECORD_FINAL = 0


def _derive_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("La contraseña no puede estar vacía.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def _validate_paths(source: Path, destination: Path) -> None:
    if source.is_symlink() or not source.is_file():
        raise ValueError("El origen debe ser un archivo regular, no un enlace simbólico.")
    if source.resolve() == destination.resolve():
        raise ValueError("El origen y el destino deben ser diferentes.")
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"El destino ya existe: {destination}")


def _validate_chunk_size(chunk_size: int) -> None:
    if (
        isinstance(chunk_size, bool)
        or not isinstance(chunk_size, int)
        or not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE
    ):
        raise ValueError(
            f"El tamaño de bloque debe estar entre {MIN_CHUNK_SIZE} "
            f"y {MAX_CHUNK_SIZE} bytes."
        )


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        part = stream.read(size - len(data))
        if not part:
            raise ValueError("Archivo cifrado truncado o incompleto.")
        data.extend(part)
    return bytes(data)


def _nonce(prefix: bytes, counter: int) -> bytes:
    return prefix + struct.pack(">I", counter)


def _create_temp_file(destination: Path) -> tuple[int, Path]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(
        prefix=".backup-security-",
        suffix=".tmp",
        dir=destination.parent,
    )
    return fd, Path(name)


def _publish_without_overwrite(temp_path: Path, destination: Path) -> None:
    """Publica atómicamente mediante hard link, sin reemplazar el destino."""
    os.link(temp_path, destination)
    temp_path.unlink()


def encrypt_file_streaming(
    source: Path,
    destination: Path,
    password: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> None:
    """Cifra un archivo en bloques autenticados sin cargarlo entero en memoria."""
    source = Path(source)
    destination = Path(destination)

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"La contraseña debe tener al menos {MIN_PASSWORD_LENGTH} caracteres."
        )
    _validate_chunk_size(chunk_size)
    _validate_paths(source, destination)

    salt = os.urandom(SALT_SIZE)
    nonce_prefix = os.urandom(NONCE_PREFIX_SIZE)
    header = struct.pack(
        HEADER_FORMAT,
        MAGIC,
        ITERATIONS,
        salt,
        nonce_prefix,
        chunk_size,
    )
    key = _derive_key(password, salt)
    cipher = AESGCM(key)

    fd, temp_path = _create_temp_file(destination)
    try:
        with source.open("rb") as input_file, os.fdopen(fd, "wb") as output_file:
            output_file.write(header)
            counter = 0

            while True:
                plaintext = input_file.read(chunk_size)
                if not plaintext:
                    break
                if counter >= NONCE_COUNTER_MAX:
                    raise ValueError("El archivo supera el límite de bloques del formato.")

                record_header = struct.pack(
                    RECORD_FORMAT,
                    RECORD_DATA,
                    counter,
                    len(plaintext),
                )
                ciphertext = cipher.encrypt(
                    _nonce(nonce_prefix, counter),
                    plaintext,
                    header + record_header,
                )
                output_file.write(record_header)
                output_file.write(ciphertext)
                counter += 1

            final_header = struct.pack(
                RECORD_FORMAT,
                RECORD_FINAL,
                counter,
                0,
            )
            final_tag = cipher.encrypt(
                _nonce(nonce_prefix, counter),
                b"",
                header + final_header,
            )
            output_file.write(final_header)
            output_file.write(final_tag)
            output_file.flush()
            os.fsync(output_file.fileno())

        _publish_without_overwrite(temp_path, destination)
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass


def decrypt_file_streaming(
    source: Path,
    destination: Path,
    password: str,
) -> None:
    """Verifica todos los bloques y publica el archivo solo tras el registro FINAL."""
    source = Path(source)
    destination = Path(destination)
    _validate_paths(source, destination)

    fd = None
    temp_path = None
    try:
        with source.open("rb") as input_file:
            header = _read_exact(input_file, HEADER_SIZE)
            magic, iterations, salt, nonce_prefix, chunk_size = struct.unpack(
                HEADER_FORMAT,
                header,
            )

            if magic != MAGIC:
                raise ValueError("Formato de archivo V2 no reconocido.")
            if iterations != ITERATIONS:
                raise ValueError("Parámetros de derivación no admitidos.")
            _validate_chunk_size(chunk_size)

            key = _derive_key(password, salt)
            cipher = AESGCM(key)
            fd, temp_path = _create_temp_file(destination)

            with os.fdopen(fd, "wb") as output_file:
                fd = None
                expected_counter = 0

                while True:
                    first_byte = input_file.read(1)
                    if not first_byte:
                        raise ValueError("Falta el registro FINAL autenticado.")

                    record_header = first_byte + _read_exact(
                        input_file,
                        RECORD_HEADER_SIZE - 1,
                    )
                    record_type, counter, plaintext_size = struct.unpack(
                        RECORD_FORMAT,
                        record_header,
                    )

                    if record_type == RECORD_DATA:
                        if counter != expected_counter:
                            raise ValueError("Secuencia de bloques no válida.")
                        if expected_counter >= NONCE_COUNTER_MAX:
                            raise ValueError("Se ha superado el límite de bloques.")
                        if not 1 <= plaintext_size <= chunk_size:
                            raise ValueError("Tamaño de bloque no válido.")

                        ciphertext = _read_exact(
                            input_file,
                            plaintext_size + TAG_SIZE,
                        )
                        plaintext = cipher.decrypt(
                            _nonce(nonce_prefix, counter),
                            ciphertext,
                            header + record_header,
                        )
                        output_file.write(plaintext)
                        expected_counter += 1

                    elif record_type == RECORD_FINAL:
                        if counter != expected_counter or plaintext_size != 0:
                            raise ValueError("Registro FINAL no válido.")

                        final_tag = _read_exact(input_file, TAG_SIZE)
                        cipher.decrypt(
                            _nonce(nonce_prefix, counter),
                            final_tag,
                            header + record_header,
                        )
                        if input_file.read(1):
                            raise ValueError("Se han detectado datos después del registro FINAL.")
                        break
                    else:
                        raise ValueError("Tipo de registro no reconocido.")

                output_file.flush()
                os.fsync(output_file.fileno())

        _publish_without_overwrite(temp_path, destination)
    finally:
        if fd is not None:
            os.close(fd)
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
