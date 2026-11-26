# Guía interna de defensa técnica — Backup Security App

> Material personal de preparación para entrevistas. No forma parte de la documentación pública del producto ni debe utilizarse para afirmar capacidades que no se hayan implementado o medido.

## 1. Presentación de 30 segundos

"I built a Python-based file encryption prototype for backup protection. The first version used AES-256-GCM but loaded the entire file into memory. I identified that scalability limitation and designed a second, versioned format that encrypts data in authenticated chunks. V2 validates record order, authenticates a final marker to detect truncation, and writes decrypted data to a temporary file that is only published after the complete stream has been verified. I also added security-focused tests and cross-platform CI."

## 2. Problema y valor

**Problema:** un backup puede exponer datos sensibles si alguien obtiene acceso al almacenamiento. Además, una copia modificada o truncada no debe aceptarse como válida durante la recuperación. La V1 también tenía un límite de escalabilidad porque cargaba todo el archivo en memoria.

**Valor demostrado:**
- Confidencialidad e integridad autenticada mediante AES-GCM.
- Procesamiento por bloques para evitar que el uso de memoria del contenido crezca con el tamaño total del archivo.
- Detección de alteración, reordenación, truncamiento y bytes adicionales.
- Prevención de publicación del archivo final antes de autenticar el flujo completo.
- Pruebas negativas y CI en Windows/Ubuntu y Python 3.10–3.13.
- Documentación de límites, amenazas y deuda técnica.

**No afirmar:** que es una plataforma de backup completa, que protege contra ransomware, que fue auditada, que está lista para producción o que es más rápida sin benchmarks.

## 3. Arquitectura que debes explicar

### V1

- Archivo completo leído con `read_bytes`.
- Salt aleatorio de 16 bytes.
- PBKDF2-HMAC-SHA256 con 600.000 iteraciones deriva 32 bytes.
- Nonce aleatorio de 12 bytes.
- AES-256-GCM cifra el plaintext y autentica la cabecera como AAD.
- El archivo recuperado se escribe solo después de que GCM valide el ciphertext.

### V2

- Cabecera versionada con magic `BKSCV002`, iteraciones, salt, prefijo de nonce y tamaño de bloque.
- Bloques de 1 MiB por defecto; API acepta 1 KiB–8 MiB.
- Nonce por registro: prefijo aleatorio de 8 bytes + contador big-endian de 32 bits.
- Cada DATA record cifra con AES-GCM; AAD = cabecera del archivo + cabecera del registro.
- El contador debe coincidir con el siguiente esperado.
- FINAL es una operación GCM sobre plaintext vacío, con su propio nonce y AAD. Su tag autentica el fin del flujo.
- El descifrador exige FINAL, valida que no haya bytes después y solo entonces publica el temporal mediante hard link.

## 4. Preguntas técnicas y respuestas modelo

### Why did you choose AES-256-GCM?

"AES-GCM is an authenticated encryption mode. It provides confidentiality and integrity/authenticity in one construction. If the ciphertext or authenticated associated data is modified, decryption fails authentication. That is important for backups because I don't want to restore data that has been silently tampered with."

Punto clave: no decir que AES-256 por sí solo garantiza seguridad. La gestión correcta de nonces, claves y parámetros también es esencial.

### What is the difference between encryption and authenticated encryption?

"Encryption aims to keep data confidential. Authenticated encryption also detects unauthorized modifications. With AEAD, the decrypt operation verifies the authentication tag before returning accepted plaintext."

### Why did you move from V1 to streaming?

"V1 reads the whole file into memory, so memory consumption grows with file size. V2 processes bounded chunks. This addresses the memory scalability issue, although I still need reproducible benchmarks to quantify memory usage and throughput."

### How do you prevent nonce reuse in V2?

"Each file gets a random eight-byte nonce prefix. Each record appends a monotonically increasing 32-bit counter, so records within that file use distinct 96-bit nonces. The key is derived using a per-file random salt. The counter sequence is also validated during decryption."

Si te preguntan por límites: el formato tiene un contador finito de 32 bits y el diseño depende de mantener la secuencia y no reutilizar la combinación clave/nonce. No inventes una garantía matemática entre archivos: el prefijo y el salt son aleatorios.

### What is the purpose of the salt?

"The salt is an input to PBKDF2. It makes the derived key specific to the file and prevents the same password from producing the same derived key across files when different salts are used. It is not a secret and can be stored in the file header."

### What is the purpose of AAD?

"AAD is authenticated but not encrypted. I authenticate the file header and each record header so that format parameters, record type, counter and declared plaintext length are protected against modification."

### How do you detect truncation?

"V2 requires an authenticated FINAL record. If the file is cut off before that record, decryption fails. The FINAL record is authenticated with AES-GCM using the next counter value. The parser also rejects extra bytes after FINAL."

### How do you avoid publishing partial plaintext?

"Decryption writes authenticated chunks to a temporary file in the destination directory. It publishes the destination only after every data record and the FINAL record have been authenticated. If authentication fails, the final destination is not created and cleanup of the temporary file is attempted."

Caveat: no afirmar que no puede quedar ningún temporal. Una terminación abrupta puede impedir la limpieza; esto requiere pruebas y una política de recuperación.

### Why use a hard link?

"It allows the program to create the destination name without replacing an existing destination. The temporary file is in the same directory, which is important because hard links generally require the same filesystem. If hard links are unsupported, the implementation fails rather than silently using an unsafe overwrite fallback."

### Why PBKDF2? Is 600,000 iterations enough?

"PBKDF2-HMAC-SHA256 derives a fixed-length key from a password using a salt and a configurable work factor. This prototype currently fixes the iteration count at 600,000. Whether that is appropriate depends on current guidance and the target hardware, so it should be reviewed and benchmarked. The minimum password length alone does not guarantee password entropy."

No presentar el valor como universalmente óptimo o como sustituto de un gestor de claves.

### Does it protect against ransomware?

"No. It protects the confidentiality and integrity of encrypted files, but it does not stop malware with sufficient permissions from deleting or replacing backups. A real backup strategy also needs isolated or immutable storage, access controls, retention and tested recovery."

### Can it encrypt a 100 GB file?

"V2 is designed to process files without loading the entire file into memory, so the content-processing memory requirement is bounded by the chunk size and I/O buffers. I have not yet published a 100 GB test or benchmark, so I would describe that as an architectural capability to validate, not a measured result."

### Is it production-ready?

"No. It is a security-focused prototype. Before production use, I would require an independent cryptographic review, large-file and crash-recovery tests, filesystem compatibility validation, key lifecycle management and protected or immutable storage."

## 5. Diferencias que debes dominar

| Concepto | Explicación corta |
|---|---|
| Salt | Aleatoriza la derivación de clave; no necesita ser secreto |
| Nonce | Valor que debe ser único para una misma clave en GCM |
| Key | Secreto usado por AES-GCM |
| AAD | Datos autenticados pero no cifrados |
| Authentication tag | Evidencia criptográfica de integridad/autenticidad |
| FINAL record | Señal autenticada de que el flujo terminó correctamente |
| Temporary file | Evita publicar el resultado antes de validar todo el flujo |
| Hard link | Publicación del nombre destino sin reemplazar uno existente |

## 6. Evidencias concretas que puedes citar

- Código V1: `backup_crypto.py`.
- Código V2: `backup_crypto_stream.py`.
- CLI V2: `backup_crypto_stream_cli.py`.
- Formato V2: `docs/streaming-format-v2.md`.
- Diseño de seguridad: `docs/security-design.md`.
- Threat model: `docs/threat-model-v2.md`.
- Tests: `tests/test_backup_crypto.py` y `tests/test_backup_crypto_stream.py`.
- CI: `.github/workflows/ci.yml`.
- Matriz CI: Ubuntu y Windows × Python 3.10–3.13.

La suite actual tiene 17 tests: 7 V1 y 10 V2. La matriz de CI tiene 8 combinaciones.

## 7. Preguntas que podrían dejarte expuesto

Prepárate para reconocer estas limitaciones sin ponerte a la defensiva:

1. ¿Cómo garantizas que el archivo origen no cambió durante el cifrado? Actualmente no hay snapshot ni lock.
2. ¿Qué ocurre si el proceso termina abruptamente durante el descifrado? Puede quedar un temporal residual; falta probar recuperación/limpieza.
3. ¿Qué pasa si el sistema de archivos no soporta hard links? La publicación falla de forma segura.
4. ¿Cómo rotas o recuperas claves? No está implementado.
5. ¿Has medido RAM, throughput y latencia con archivos de varios GB? No todavía.
6. ¿Quién revisó el formato criptográfico? No hay auditoría independiente documentada.
7. ¿Cómo proteges los backups frente a ransomware? No lo hace por sí solo; se necesita almacenamiento aislado o inmutable.

## 8. Próxima mejora que defendería

Mi prioridad sería una validación de fiabilidad antes de añadir funcionalidades:

1. Añadir pruebas de interrupción abrupta y limpieza de temporales.
2. Probar archivos grandes y medir memoria/tiempo con metodología reproducible.
3. Validar hard links, permisos y comportamiento en Windows y Linux.
4. Resolver la consistencia del archivo origen durante lectura.
5. Solicitar revisión independiente del formato V2.

## 9. Frase de cierre para entrevista

"The most important part of this project was not simply calling an encryption API. It was designing the complete file lifecycle around security: key derivation, nonce management, authenticated records, failure handling, safe publication, testing and explicit threat boundaries. I also documented what the prototype does not protect against, because security engineering requires being precise about residual risk."
