# Formato criptográfico V2 — cifrado autenticado por bloques

## Objetivo

V2 permite procesar archivos con memoria de contenido acotada y detectar alteraciones, reordenación, eliminación y truncamiento de registros. V1 se mantiene como formato independiente; V2 no cambia retroactivamente archivos existentes.

## Cabecera

Estructura binaria big-endian: `>8sI16s8sI`.

| Campo | Tamaño | Descripción |
|---|---:|---|
| Magic | 8 bytes | Identificador `BKSCV002` |
| Iteraciones | 4 bytes | PBKDF2-HMAC-SHA256: 600.000 |
| Salt | 16 bytes | Aleatorio por archivo |
| Nonce prefix | 8 bytes | Aleatorio por archivo |
| Chunk size | 4 bytes | Entre 1 KiB y 8 MiB |

La cabecera completa se incluye como AAD en todos los registros.

## Derivación de clave y nonce

- PBKDF2-HMAC-SHA256 deriva una clave de 32 bytes.
- Cada registro utiliza un nonce de 12 bytes: prefijo aleatorio de 8 bytes + contador de 32 bits big-endian.
- El contador comienza en cero y aumenta exactamente una vez por registro.
- No se permite reutilizar el contador dentro de un mismo archivo.
- La sal aleatoria hace que la clave derivada dependa del archivo, incluso cuando se reutiliza la misma contraseña.

La unicidad del nonce se mantiene dentro de un archivo mediante el contador secuencial. Entre archivos, el salt y el prefijo aleatorios reducen la probabilidad de reutilización de clave/nonce. Esta construcción es una decisión de diseño del prototipo y requiere revisión criptográfica independiente antes de un uso crítico.

## Registros

Cabecera de registro: `>BII` (tipo, contador, longitud del texto claro).

### DATA (tipo 1)

- Longitud entre 1 byte y el tamaño máximo de bloque declarado.
- Cuerpo: ciphertext y etiqueta GCM de 16 bytes.
- AAD: cabecera del archivo + cabecera del registro.
- El contador debe coincidir con el siguiente valor esperado.

### FINAL (tipo 0)

- Longitud cero.
- Contador igual al número de bloques DATA.
- Cuerpo: etiqueta GCM de 16 bytes para un mensaje vacío.
- Autentica el final del archivo y permite detectar truncamiento.
- No se permiten bytes después del registro FINAL.

## Seguridad de recuperación

El descifrado escribe en un archivo temporal creado en el directorio de destino. Cada bloque se autentica antes de escribir su plaintext al temporal. El archivo final solo se publica después de autenticar todos los registros y el marcador FINAL.

La publicación utiliza `os.link` para crear el destino sin reemplazar un nombre existente. Si la autenticación falla, el destino final no se publica y se intenta eliminar el temporal. Una terminación abrupta puede dejar un temporal residual; la limpieza tras caída abrupta no está demostrada por los tests actuales.

## Garantías y límites

- El procesamiento del contenido está acotado por el tamaño del bloque y los buffers de E/S, no por el tamaño total del archivo.
- No se han publicado benchmarks de memoria o rendimiento.
- El formato no cifra nombres, tamaños ni fechas de archivos.
- El contador tiene un límite de 32 bits y no puede reutilizarse con la misma clave.
- El prototipo no gestiona rotación ni recuperación de contraseñas.
- La publicación por hard link requiere soporte del sistema de archivos. Si no está disponible, la operación falla de forma segura.
- No se toma una snapshot ni se bloquea el archivo origen durante la lectura.
- El formato V2 requiere revisión criptográfica independiente y pruebas de interoperabilidad en los sistemas de archivos objetivo antes de considerarse para un uso crítico.

Más información: [Security design and architecture](security-design.md) y [V2 threat model](threat-model-v2.md).
