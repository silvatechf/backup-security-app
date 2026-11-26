# Sistema de cifrado y protección de copias de seguridad

## 1. Problema que aborda

Los archivos de backup pueden contener información sensible y, si se almacenan sin protección, una persona que obtenga acceso al medio de almacenamiento podría leerlos. Además, un archivo cifrado que haya sido modificado, truncado o dañado no debe aceptarse silenciosamente como una copia recuperable.

Este proyecto explora dos necesidades concretas:

- **Confidencialidad:** impedir que el contenido del backup sea legible sin la contraseña correcta.
- **Integridad y recuperación fiable:** detectar manipulación o corrupción y evitar publicar un archivo descifrado incompleto.

La evolución de V1 a V2 aborda también un problema de escalabilidad: leer un archivo completo en memoria deja de ser práctico cuando el tamaño del backup crece.

> El alcance es deliberadamente acotado: es una herramienta local de cifrado y recuperación de archivos seleccionados por el usuario. No es un sistema integral de backup, no administra retención ni almacenamiento remoto y no protege por sí sola contra ransomware.

## 2. Qué demuestra el proyecto

El repositorio documenta decisiones de ingeniería y controles verificables, no solo el uso de una biblioteca criptográfica:

- Cifrado autenticado AES-256-GCM para confidencialidad e integridad/autenticidad del contenido cifrado.
- Derivación de una clave de 256 bits desde una contraseña mediante PBKDF2-HMAC-SHA256 con 600.000 iteraciones y una sal aleatoria de 16 bytes por archivo.
- Evolución desde el procesamiento completo en memoria (V1) a registros autenticados por bloques (V2).
- Nonces de 12 bytes en V2 formados por un prefijo aleatorio de 8 bytes por archivo y un contador de 32 bits por registro.
- Cabecera y cabeceras de registro autenticadas como AAD.
- Registro FINAL autenticado para detectar truncamiento, incluso si el archivo termina en un límite de bloque.
- Validación de la secuencia de registros y rechazo de datos posteriores al registro FINAL.
- Descifrado hacia un archivo temporal y publicación del resultado solo después de autenticar todos los registros.
- Creación del destino sin sobrescritura; V2 utiliza hard links y falla de forma segura si el sistema de archivos no los admite.
- Pruebas automatizadas de casos positivos y negativos, además de CI multiplataforma.

## 3. Evolución de diseño: V1 y V2

| Aspecto | V1 | V2 |
|---|---|---|
| Procesamiento | Archivo completo en memoria | Bloques de tamaño acotado |
| Cifrado | AES-256-GCM | AES-256-GCM por registro |
| Derivación de clave | PBKDF2-HMAC-SHA256, 600.000 iteraciones | Igual |
| Salt | 16 bytes aleatorios | 16 bytes aleatorios |
| Nonce | 12 bytes aleatorios por archivo | Prefijo aleatorio de 8 bytes + contador de 32 bits |
| Integridad | Etiqueta GCM del archivo | Etiqueta GCM por registro + FINAL autenticado |
| Publicación | Escritura exclusiva del destino después del descifrado autenticado | Temporal en el directorio destino y publicación mediante hard link después de validar FINAL |
| Uso recomendado | Archivos pequeños o moderados | Archivos grandes, sujeto a pruebas en el entorno objetivo |

V1 se conserva como formato independiente. Los archivos V1 y V2 no son intercambiables y se procesan con sus respectivas CLI.

## 4. Arquitectura y flujo de seguridad

### Cifrado V2

1. Validar el archivo de origen, el destino, la contraseña y el tamaño de bloque.
2. Generar salt y prefijo de nonce aleatorios para el archivo.
3. Derivar una clave AES de 256 bits con PBKDF2-HMAC-SHA256.
4. Escribir la cabecera del formato.
5. Leer un bloque de entrada, cifrarlo con AES-GCM y autenticar la cabecera del archivo y la cabecera del registro como AAD.
6. Incrementar el contador para el siguiente registro.
7. Escribir un registro FINAL autenticado.
8. Vaciar y sincronizar el archivo temporal y publicarlo sin sobrescribir el destino.

### Descifrado V2

1. Validar la cabecera y los parámetros admitidos.
2. Derivar la clave a partir de la contraseña y la sal almacenada.
3. Comprobar que cada registro tiene el contador esperado y un tamaño permitido.
4. Autenticar y descifrar cada bloque hacia un temporal.
5. Exigir un registro FINAL válido y rechazar bytes adicionales.
6. Publicar el archivo recuperado únicamente después de completar todas las verificaciones.

El temporal puede contener plaintext durante el proceso, pero no se publica como archivo de destino antes de completar la autenticación. Ante errores gestionados, se intenta eliminar el temporal. Una terminación abrupta del proceso puede dejar un temporal residual; la recuperación y limpieza tras fallos abruptos requieren pruebas adicionales.

Más detalles: [Security design and architecture](docs/security-design.md) y [V2 threat model](docs/threat-model-v2.md).

## 5. Tecnologías

| Tecnología | Uso |
|---|---|
| Python 3.10+ | Implementación |
| `cryptography` | Primitivas criptográficas |
| AES-256-GCM | Cifrado autenticado |
| PBKDF2-HMAC-SHA256 | Derivación de claves desde contraseña |
| `pytest` | Pruebas automatizadas |
| Ruff | Análisis estático |
| GitHub Actions | CI en Windows y Ubuntu |

## 6. Instalación en Windows (PowerShell)

```powershell
py -3 -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
```

Si PowerShell bloquea la activación del entorno virtual, se puede ejecutar el intérprete directamente desde `.venv\\Scripts\\python.exe`.

## 7. Preparar un backup de prueba

Crear una carpeta con documentos ficticios y generar un ZIP:

```powershell
Compress-Archive -Path .\\datos-prueba\\* -DestinationPath .\\backups\\backup.zip
```

No utilizar documentos sensibles reales durante las primeras pruebas.

## 8. Uso de V1

V1 carga el archivo completo en memoria. Es adecuada únicamente para archivos pequeños o moderados.

### Cifrar

```powershell
python backup_crypto.py encrypt .\\backups\\backup.zip .\\encrypted\\backup.zip.enc
```

### Descifrar

```powershell
python backup_crypto.py decrypt .\\encrypted\\backup.zip.enc .\\restored\\backup.zip
```

V1 utiliza AES-256-GCM, PBKDF2-HMAC-SHA256 con 600.000 iteraciones, sal de 16 bytes y nonce de 12 bytes. La contraseña debe tener al menos 12 caracteres.

## 9. Uso de V2 — cifrado por bloques

V2 procesa el archivo en bloques de 1 MiB por defecto y no carga el archivo completo en memoria. El tamaño de bloque permitido por la API es de 1 KiB a 8 MiB.

### Cifrar

```powershell
python backup_crypto_stream_cli.py encrypt .\\backups\\backup.zip .\\encrypted\\backup.zip.v2.enc
```

### Descifrar

```powershell
python backup_crypto_stream_cli.py decrypt .\\encrypted\\backup.zip.v2.enc .\\restored\\backup.zip
```

La memoria utilizada por el procesamiento de contenido está acotada por el tamaño del bloque y los buffers de E/S, no por el tamaño total del archivo. No se han publicado todavía benchmarks de memoria, throughput ni latencia; deben medirse antes de realizar afirmaciones cuantitativas de rendimiento.

**Compatibilidad:** V1 y V2 son formatos distintos y utilizan comandos separados. Para descifrar un archivo V1 se debe utilizar el comando V1; para un archivo V2, el comando V2.

## 10. Verificación de integridad del resultado

Comparar los hashes SHA-256 del archivo original y del archivo recuperado:

```powershell
Get-FileHash .\\backups\\backup.zip -Algorithm SHA256
Get-FileHash .\\restored\\backup.zip -Algorithm SHA256
```

Los valores `Hash` deben coincidir.

## 11. Pruebas automatizadas y CI

Ejecutar localmente:

```powershell
python -m pytest -v
python -m ruff check .
```

La suite actual contiene 17 pruebas: 7 para V1 y 10 para V2. Entre los escenarios cubiertos se encuentran:

- Round-trip, incluyendo archivo vacío y múltiples bloques.
- Contraseña incorrecta y ciphertext manipulado.
- Alteración de un bloque posterior sin publicar plaintext parcial.
- Truncamiento, reordenación y bytes añadidos después de FINAL.
- Destino existente, contraseña corta y tamaño de bloque no válido.
- Una condición de carrera en la creación exclusiva de archivos V1.

GitHub Actions ejecuta Ruff y pytest en una matriz de Windows y Ubuntu con Python 3.10, 3.11, 3.12 y 3.13 (8 combinaciones). La existencia de CI y pruebas no equivale a una auditoría criptográfica ni demuestra por sí sola preparación para producción.

## 12. Limitaciones y riesgos conocidos

- **Gestión de claves:** la contraseña es el mecanismo de recuperación. Si se pierde, no hay recuperación implementada. No hay KMS, rotación ni custodia centralizada.
- **Calidad de contraseña:** el mínimo de 12 caracteres es una validación básica, no una garantía de entropía suficiente.
- **Metadatos:** el cifrado no oculta nombres, tamaños ni fechas de los archivos.
- **Consistencia de origen:** no se toma una snapshot ni se bloquea el archivo de origen; cambios concurrentes durante la lectura pueden afectar la consistencia del backup cifrado.
- **Temporales:** errores gestionados activan limpieza best-effort; una terminación abrupta puede dejar temporales en disco.
- **Almacenamiento:** no se implementan almacenamiento remoto, inmutabilidad ni protección contra eliminación.
- **Ransomware:** un proceso malicioso con permisos suficientes puede borrar o reemplazar backups accesibles. Se necesitan copias aisladas o inmutables.
- **Sistema de archivos:** la publicación V2 depende del soporte de hard links en el sistema de archivos de destino.
- **Formato propio:** V2 es un formato binario diseñado para este prototipo y requiere revisión criptográfica independiente e interoperabilidad antes de cualquier uso crítico.
- **Producción:** no es una plataforma empresarial de backup ni una certificación de seguridad.

## 13. Próximas mejoras

1. Revisión independiente del formato V2 y de sus invariantes criptográficos.
2. Pruebas con archivos grandes, medición de memoria, throughput y tiempo de recuperación.
3. Pruebas de interrupción abrupta, reinicio y limpieza de temporales.
4. Detección de cambios del archivo de origen durante el cifrado o integración con snapshots.
5. Gestión de claves mediante un gestor de secretos o KMS, con rotación y recuperación planificada.
6. Almacenamiento externo con control de acceso e inmutabilidad.
7. Pruebas de interoperabilidad en los sistemas de archivos objetivo.

## 14. Conclusión

El valor principal del proyecto está en el proceso de ingeniería: identificar una limitación de escalabilidad en la primera implementación, diseñar un formato autenticado por bloques, definir controles contra manipulación y truncamiento, proteger la publicación del plaintext y documentar tanto las garantías como los riesgos residuales.

Es un prototipo técnico demostrativo de Python y Application Security. No debe utilizarse como única copia de información importante ni considerarse listo para producción sin las revisiones y pruebas pendientes.
