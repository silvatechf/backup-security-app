"""Interfaz de línea de comandos para cifrado autenticado por bloques V2."""
from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag

from backup_crypto_stream import decrypt_file_streaming, encrypt_file_streaming


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Cifrado de backups por bloques con AES-256-GCM (V2)."
    )
    parser.add_argument("operation", choices=("encrypt", "decrypt"))
    parser.add_argument("source", type=Path, help="Archivo de origen.")
    parser.add_argument("destination", type=Path, help="Archivo de destino.")
    args = parser.parse_args()

    try:
        password = getpass.getpass("Introduzca la contraseña: ")
        if args.operation == "encrypt":
            confirmation = getpass.getpass("Confirme la contraseña: ")
            if password != confirmation:
                raise ValueError("Las contraseñas no coinciden.")
            encrypt_file_streaming(args.source, args.destination, password)
            print(f"Backup cifrado (V2) correctamente: {args.destination}")
        else:
            decrypt_file_streaming(args.source, args.destination, password)
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
