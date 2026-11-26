# Formato criptográfico V2 — cifrado autenticado por bloques

## Objetivo

V2 permite procesar archivos grandes con memoria acotada y detectar alteraciones, reordenación, eliminación y truncamiento de registros. V1 se mantiene como formato independiente; V2 no cambia retroactivamente archivos existentes.

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

La sal aleatoria deriva una clave específica para cada archivo, reduciendo la posibilidad de reutilización de nonces entre archivos cifrados con la misma contraseña.

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

El descifrado escribe en un archivo temporal privado en el mismo directorio de destino. El archivo final solo se publica después de autenticar todos los registros y el marcador FINAL. La publicación utiliza creación por hard link para evitar reemplazar un destino existente.

Si la autenticación falla, el temporal se elimina y no se publica una copia parcialmente descifrada.

## Limitaciones y decisiones

- El tamaño de memoria está acotado aproximadamente por el tamaño del bloque y las estructuras de E/S.
- El formato no cifra nombres, tamaños ni fechas de archivos.
- El nonce prefix tiene 64 bits aleatorios; la clave se deriva de una sal aleatoria de 128 bits por archivo.
- El prototipo no gestiona rotación ni recuperación de contraseñas.
- La publicación por hard link requiere soporte del sistema de archivos. Si no está disponible, la operación falla de forma segura; no se usa un fallback que sobrescriba destinos.
- El formato V2 requiere pruebas de interoperabilidad en los sistemas de archivos objetivo antes de considerarse apto para producción.
