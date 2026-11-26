# Sistema de cifrado y protección de copias de seguridad — V1

## 1. Descripción

Prototipo académico en Python para proteger archivos de copias de seguridad mediante **AES-256-GCM**. El sistema cifra un archivo de backup y permite recuperarlo posteriormente con la contraseña correcta.

La versión V1 trabaja sobre un archivo seleccionado explícitamente. No recorre ni cifra indiscriminadamente el sistema operativo, no modifica los archivos originales y no elimina los backups de origen.

## 2. Objetivos

- Proteger la confidencialidad de los backups.
- Detectar modificaciones y corrupción mediante autenticación criptográfica.
- Derivar claves a partir de una contraseña sin almacenarla.
- Permitir la recuperación controlada de los datos.
- Demostrar buenas prácticas de seguridad y validación.

## 3. Tecnologías

| Tecnología | Uso |
|---|---|
| Python 3.10+ | Lenguaje |
| `cryptography` | Primitivas criptográficas |
| AES-256-GCM | Cifrado autenticado |
| PBKDF2-HMAC-SHA256 | Derivación de clave |
| `pytest` | Pruebas automatizadas |

## 4. Arquitectura criptográfica

1. Se genera una sal aleatoria de 16 bytes.
2. Se genera un nonce aleatorio de 12 bytes.
3. PBKDF2-HMAC-SHA256 deriva una clave de 32 bytes (256 bits), con 600.000 iteraciones.
4. AES-256-GCM cifra el contenido y genera una etiqueta de autenticación.
5. La cabecera del formato se utiliza como AAD (Additional Authenticated Data), por lo que también queda autenticada.
6. Durante la recuperación, AES-GCM valida la etiqueta antes de devolver el contenido descifrado.

Cada cifrado genera una sal y un nonce nuevos. No reutilizar manualmente valores criptográficos.

## 5. Requisitos

- Python 3.10 o superior.
- Windows, Linux o macOS.
- Dependencias instaladas desde `requirements.txt`.

## 6. Instalación en Windows (PowerShell)

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
```

Si PowerShell bloquea la activación del entorno virtual, se puede ejecutar el intérprete directamente desde `.venv\Scripts\python.exe`.

## 7. Preparar un backup de prueba

Crear una carpeta de prueba y colocar dentro documentos ficticios. Después, generar un ZIP:

```powershell
Compress-Archive -Path .\datos-prueba\* -DestinationPath .\backups\backup.zip
```

No utilizar documentos sensibles reales durante las primeras pruebas.

## 8. Uso

### Cifrar

```powershell
python backup_crypto.py encrypt .\backups\backup.zip .\encrypted\backup.zip.enc
```

El programa solicita una contraseña y su confirmación. Se recomienda una contraseña larga, única y almacenada de forma segura.

### Descifrar

```powershell
python backup_crypto.py decrypt .\encrypted\backup.zip.enc .\restored\backup.zip
```

La contraseña se solicita sin mostrarla en pantalla. El archivo de destino no se sobrescribe si ya existe.

## 9. Verificación de integridad

Comparar los hashes SHA-256 del archivo original y del archivo recuperado:

```powershell
Get-FileHash .\backups\backup.zip -Algorithm SHA256
Get-FileHash .\restored\backup.zip -Algorithm SHA256
```

Los valores `Hash` deben coincidir.

También se puede probar la autenticación modificando una copia del archivo cifrado. El descifrado debe fallar sin generar el archivo de salida.

## 10. Pruebas automatizadas

```powershell
pytest -v
```

La suite comprueba:

- Cifrado y recuperación correctos.
- Rechazo de contraseña incorrecta.
- Detección de manipulación del contenido cifrado.
- Protección frente a sobrescritura del destino.
- Tratamiento de archivos vacíos.

## 11. Formato del archivo cifrado

La cabecera contiene:

| Campo | Tamaño |
|---|---:|
| Identificador de formato | 8 bytes |
| Iteraciones PBKDF2 | 4 bytes |
| Sal | 16 bytes |
| Nonce | 12 bytes |
| Contenido cifrado + etiqueta GCM | Variable |

La cabecera completa se autentica como AAD. La etiqueta GCM permite detectar una contraseña incorrecta o cualquier alteración del contenido autenticado.

## 12. Limitaciones conocidas — V1

- **Memoria:** el archivo completo se carga en memoria. No está diseñado para backups de varios gigabytes.
- **Gestión de claves:** la contraseña es el único mecanismo de recuperación. Si se pierde, los datos no se pueden recuperar.
- **Almacenamiento:** el prototipo no implementa almacenamiento remoto, inmutabilidad ni protección contra eliminación.
- **Metadatos:** cifra el contenido del archivo, pero no oculta el nombre, tamaño ni fechas del archivo cifrado.
- **Disponibilidad:** el cifrado no sustituye una estrategia 3-2-1 de backups ni las pruebas de restauración.
- **Contraseña:** PBKDF2 dificulta ataques de fuerza bruta, pero no compensa una contraseña débil.

## 13. Mejoras futuras

- Cifrado autenticado por bloques para archivos grandes.
- Gestión de claves mediante un gestor de secretos o KMS.
- Registro de auditoría sin contraseñas ni claves.
- Backups incrementales y verificación de restauración.
- Almacenamiento externo con control de acceso e inmutabilidad.
- Modelo de amenazas y análisis de riesgos.

## 14. Conclusión

La V1 demuestra la aplicación de cifrado autenticado para proteger la confidencialidad e integridad de copias de seguridad. También permite evaluar escenarios de fallo, recuperación y manipulación de datos mediante pruebas reproducibles.

**Aviso:** proyecto académico. Antes de utilizarlo en producción, se requiere revisión de seguridad, pruebas adicionales y un diseño específico para el entorno de despliegue.
