# Sistema de cifrado y protección de copias de seguridad

## 1. Descripción

Proyecto académico en Python para proteger archivos de copias de seguridad mediante **AES-256-GCM**.

El repositorio contiene dos formatos:

- **V1:** cifrado autenticado de un archivo completo en memoria. Se conserva para compatibilidad y aprendizaje.
- **V2:** cifrado autenticado por bloques, con memoria acotada, autenticación por registro y marcador FINAL para detectar truncamiento.

El usuario selecciona explícitamente cada archivo. El programa no recorre ni cifra indiscriminadamente el sistema operativo, no modifica los archivos originales y no elimina los backups de origen.

## 2. Objetivos

- Proteger la confidencialidad de los backups.
- Detectar modificaciones, corrupción, reordenación y truncamiento.
- Derivar claves a partir de contraseñas sin almacenarlas.
- Permitir recuperación controlada de los datos.
- Demostrar pruebas de seguridad reproducibles y CI.

## 3. Tecnologías

| Tecnología | Uso |
|---|---|
| Python 3.10+ | Lenguaje |
| `cryptography` | Primitivas criptográficas |
| AES-256-GCM | Cifrado autenticado |
| PBKDF2-HMAC-SHA256 | Derivación de claves |
| `pytest` | Pruebas automatizadas |
| Ruff | Análisis estático |

## 4. Instalación en Windows (PowerShell)

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
```

Si PowerShell bloquea la activación del entorno virtual, se puede ejecutar el intérprete directamente desde `.venv\Scripts\python.exe`.

## 5. Preparar un backup de prueba

Crear una carpeta con documentos ficticios y generar un ZIP:

```powershell
Compress-Archive -Path .\datos-prueba\* -DestinationPath .\backups\backup.zip
```

No utilizar documentos sensibles reales durante las primeras pruebas.

## 6. Uso de V1

V1 carga el archivo completo en memoria. Es adecuada únicamente para archivos pequeños o moderados.

### Cifrar

```powershell
python backup_crypto.py encrypt .\backups\backup.zip .\encrypted\backup.zip.enc
```

### Descifrar

```powershell
python backup_crypto.py decrypt .\encrypted\backup.zip.enc .\restored\backup.zip
```

V1 utiliza AES-256-GCM, PBKDF2-HMAC-SHA256 con 600.000 iteraciones, sal de 16 bytes y nonce de 12 bytes. La contraseña debe tener al menos 12 caracteres.

## 7. Uso de V2 — cifrado por bloques

V2 procesa el archivo en bloques de 1 MiB por defecto y no carga el archivo completo en memoria. El tamaño de bloque permitido por la API es de 1 KiB a 8 MiB.

### Cifrar

```powershell
python backup_crypto_stream_cli.py encrypt .\backups\backup.zip .\encrypted\backup.zip.v2.enc
```

### Descifrar

```powershell
python backup_crypto_stream_cli.py decrypt .\encrypted\backup.zip.v2.enc .\restored\backup.zip
```

V2 utiliza un nonce único por bloque dentro del archivo, registros autenticados y un registro FINAL autenticado. El descifrado utiliza un archivo temporal privado y publica el resultado únicamente después de validar todos los registros.

La publicación usa hard links para evitar sobrescribir un destino existente. El sistema de archivos debe soportar hard links; si no los soporta, la operación falla de forma segura.

**Compatibilidad:** V1 y V2 son formatos distintos y utilizan comandos separados. Para descifrar un archivo V1 se debe utilizar el comando V1; para un archivo V2, el comando V2.

## 8. Verificación de integridad

Comparar los hashes SHA-256 del archivo original y del archivo recuperado:

```powershell
Get-FileHash .\backups\backup.zip -Algorithm SHA256
Get-FileHash .\restored\backup.zip -Algorithm SHA256
```

Los valores `Hash` deben coincidir.

Las pruebas V2 también verifican que el sistema rechaza datos manipulados, registros reordenados, archivos truncados y bytes añadidos después del registro FINAL.

## 9. Pruebas automatizadas y análisis estático

```powershell
python -m pytest -v
python -m ruff check .
```

La suite cubre cifrado y recuperación, contraseña incorrecta, manipulación, truncamiento, reordenación, destino existente, contraseña corta y tratamiento de archivos vacíos.

GitHub Actions ejecuta Ruff y pytest para Python 3.10, 3.11, 3.12 y 3.13.

## 10. Documentación técnica

- [Modelo de amenazas V1](docs/threat-model-v1.md)
- [Formato criptográfico V2](docs/streaming-format-v2.md)
- [Política de seguridad](SECURITY.md)
- [Guía de contribución](CONTRIBUTING.md)

## 11. Limitaciones y riesgos conocidos

- **Gestión de claves:** la contraseña es el único mecanismo de recuperación. Si se pierde, los datos no se pueden recuperar.
- **Metadatos:** el cifrado no oculta nombres, tamaños ni fechas de los archivos.
- **Almacenamiento:** no se implementan almacenamiento remoto, inmutabilidad ni protección contra eliminación.
- **Disponibilidad:** el cifrado no sustituye una estrategia 3-2-1 ni las pruebas periódicas de restauración.
- **Sistema de archivos:** la publicación V2 depende del soporte de hard links en el sistema de archivos de destino.
- **Producción:** este prototipo no es una plataforma de backup de producción ni una certificación de seguridad.

## 12. Mejoras futuras

- Gestión de claves mediante un gestor de secretos o KMS.
- Registro de auditoría sin contraseñas ni claves.
- Backups incrementales y verificación automatizada de restauración.
- Almacenamiento externo con control de acceso e inmutabilidad.
- Pruebas de interoperabilidad en Windows, Linux y macOS.
- Revisión criptográfica independiente del formato V2.

## 13. Conclusión

El proyecto demuestra dos aproximaciones de protección de backups mediante cifrado autenticado: una implementación inicial de archivo completo y una evolución por bloques orientada a limitar el consumo de memoria y reforzar la detección de alteraciones durante la recuperación.

**Aviso:** proyecto académico. No utilizar como única copia de información importante. Antes de un uso productivo se requiere revisión de seguridad, pruebas adicionales y un diseño específico para el entorno de despliegue.
