# Modelo de amenazas — V2

## 1. Objetivo

Identificar amenazas relacionadas con el cifrado autenticado por bloques, la recuperación y la publicación del archivo descifrado.

## 2. Activos y supuestos

Activos: plaintext del backup, contraseña, clave derivada, ciphertext, archivo temporal y resultado recuperado.

Se asume que el sistema operativo, el proceso Python, la biblioteca `cryptography` y el sistema de archivos no están comprometidos. La herramienta no protege frente a un atacante con control del equipo o privilegios suficientes sobre los archivos.

## 3. Amenazas y controles

| Amenaza | Control V2 | Riesgo residual |
|---|---|---|
| Lectura no autorizada del ciphertext | AES-256-GCM y clave derivada de contraseña | Contraseña débil, robada o capturada en el equipo |
| Modificación de un bloque | Tag GCM por DATA record y AAD | Denegación de servicio mediante alteración |
| Reordenación de registros | Contador secuencial esperado | Un atacante aún puede eliminar o corromper el archivo |
| Truncamiento | FINAL autenticado obligatorio | No recupera los bytes perdidos |
| Bytes añadidos tras FINAL | Rechazo de trailing bytes | No evita sustitución o borrado del archivo |
| Contraseña incorrecta | Fallo de autenticación | No hay recuperación de contraseña |
| Publicación de plaintext parcial | Temporal y publicación tras FINAL | Temporal residual tras caída abrupta |
| Sobrescritura del destino | Publicación con hard link | Requiere soporte del sistema de archivos |
| Archivo origen modificado durante lectura | No hay snapshot ni lock | Puede cifrarse una vista inconsistente del origen |
| Ransomware o borrado | Fuera del alcance | Se requiere almacenamiento aislado/inmutable |

## 4. Activos y límites de confianza

El plaintext existe en memoria y en un temporal durante el descifrado. La contraseña se recibe desde la CLI y se utiliza para derivar la clave. Un host comprometido puede capturar ambos. El sistema de archivos controla la disponibilidad, permisos, semántica de hard links y persistencia de los archivos.

## 5. Invariantes de seguridad del formato

- La cabecera tiene magic y parámetros de derivación esperados.
- El tamaño de bloque está dentro del rango admitido.
- Cada DATA record utiliza el siguiente contador esperado.
- La cabecera de archivo y la cabecera del registro forman el AAD.
- Cada DATA record debe superar autenticación GCM antes de escribir su plaintext al temporal.
- Debe existir exactamente un FINAL autenticado con el siguiente contador esperado.
- No se admiten bytes después de FINAL.
- El destino final no se publica hasta validar todo el flujo.
- La publicación no reemplaza un destino existente.

## 6. Fuera del alcance

- Gestión centralizada, rotación y recuperación de claves.
- Identidad, autorización multiusuario y auditoría centralizada.
- Protección de metadatos.
- Protección contra borrado, ransomware o compromiso del host.
- Replicación, retención, almacenamiento remoto y disaster recovery.

## 7. Validación y evidencia

La suite V2 cubre round-trip multi-bloque, archivo vacío, contraseña incorrecta, alteración de un bloque posterior, truncamiento, reordenación, bytes posteriores a FINAL, destino existente, contraseña corta y tamaño de bloque inválido.

La CI ejecuta Ruff y pytest en Windows y Ubuntu para Python 3.10–3.13. Estas pruebas validan escenarios definidos; no reemplazan una revisión criptográfica independiente, fuzzing, pruebas de caída abrupta ni validación de todos los sistemas de archivos objetivo.

## 8. Riesgo residual y trabajo futuro

1. Revisión independiente del formato y de los límites de nonce.
2. Pruebas de fallos abruptos y manejo de temporales residuales.
3. Pruebas de consistencia ante modificación concurrente del origen.
4. Pruebas de hard links y permisos en los sistemas de archivos objetivo.
5. Benchmark con tamaños de archivo representativos.
6. Gestión de claves y almacenamiento resistente a borrado/ransomware.
