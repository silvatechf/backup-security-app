# Diseño de seguridad y arquitectura

## 1. Propósito y alcance

Este documento describe las decisiones de seguridad de la herramienta local de cifrado y recuperación de archivos de backup. El sistema protege el contenido de un archivo seleccionado explícitamente por el usuario. No crea, programa, almacena ni replica backups por sí mismo.

## 2. Activos

- Contenido del backup y sus copias recuperadas.
- Contraseña introducida por el usuario.
- Clave AES derivada durante cada operación.
- Integridad del archivo cifrado y del archivo recuperado.
- Rutas de origen, destino y archivos temporales.

## 3. Componentes y límites de confianza

- CLI V1 y API Python V1.
- CLI V2 y API Python V2.
- Biblioteca `cryptography` para AES-GCM y PBKDF2.
- Sistema operativo y sistema de archivos para lectura, temporales y publicación.
- Usuario y terminal que reciben la contraseña.

El intérprete, el sistema operativo, la dependencia criptográfica y el equipo donde se ejecuta forman parte de la base de confianza. Un atacante con control del proceso, del equipo o de los permisos de usuario puede acceder al plaintext o a la contraseña mientras se utilizan.

## 4. Flujo criptográfico V2

1. Se genera un salt aleatorio de 16 bytes y un prefijo aleatorio de nonce de 8 bytes.
2. PBKDF2-HMAC-SHA256, con 600.000 iteraciones, deriva 32 bytes de clave desde la contraseña y el salt.
3. AES-256-GCM cifra cada bloque.
4. El nonce de cada registro es la concatenación del prefijo de 8 bytes y un contador big-endian de 32 bits.
5. La cabecera del archivo y la cabecera del registro se suministran como AAD.
6. El registro FINAL autentica el fin de la secuencia usando el siguiente contador y un plaintext vacío.

El contador avanza secuencialmente y el descifrador exige el siguiente valor esperado. La unicidad del nonce se garantiza dentro de un archivo mientras se respete la secuencia del formato. El prefijo aleatorio y la clave derivada de un salt aleatorio reducen la probabilidad de reutilización entre archivos, pero no sustituyen una revisión formal del diseño.

## 5. Integridad y recuperación

Cada registro DATA se autentica antes de que su plaintext se escriba al temporal. El archivo final no se publica hasta que se verifica el registro FINAL y se confirma que no existen bytes adicionales.

El temporal se crea en el directorio destino mediante `tempfile.mkstemp`. Después de escribir, se ejecuta `flush` y `os.fsync`. La publicación utiliza `os.link`, que crea el nombre destino sin reemplazar uno ya existente. El temporal se elimina después de la publicación.

Si la autenticación falla, el destino final no se publica y el código intenta eliminar el temporal. La limpieza es best-effort: una terminación abrupta puede dejar residuos temporales. La semántica de hard links y durabilidad debe validarse en los sistemas de archivos concretos.

## 6. Controles implementados

| Control | Implementación | Evidencia actual |
|---|---|---|
| Confidencialidad | AES-256-GCM | Round-trip V1/V2 |
| Integridad/autenticidad | Tag GCM por archivo (V1) o registro (V2) | Tests de manipulación |
| Derivación de clave | PBKDF2-HMAC-SHA256, 600.000 iteraciones | Parámetros fijados en código y formato |
| Salt por archivo | 16 bytes aleatorios | Cabecera V1/V2 |
| Nonce V2 | Prefijo aleatorio + contador secuencial | Validación de secuencia |
| Truncamiento | Registro FINAL autenticado | Test de truncamiento |
| Reordenación | Contador esperado | Test de reordenación |
| Datos añadidos | Rechazo de bytes después de FINAL | Test de trailing data |
| No publicación parcial | Temporal + publicación tras validación completa | Test de alteración de bloque posterior |
| No sobrescritura | Creación exclusiva V1 y hard link V2 | Test de destino existente |
| Calidad de código | Ruff y pytest en CI | Workflow Windows/Ubuntu, Python 3.10–3.13 |

## 7. Amenazas fuera de alcance

- Malware o atacante con privilegios sobre el equipo donde se ejecuta la herramienta.
- Captura de contraseña mediante keylogger, terminal comprometida o memoria del proceso.
- Borrado del backup o del archivo cifrado.
- Ransomware con permisos de escritura sobre el almacenamiento.
- Robo de metadatos no cifrados.
- Disponibilidad del servicio, replicación, retención y recuperación ante desastres.
- Garantía de consistencia si el archivo de origen cambia durante la lectura.
- Gestión de identidad, control de acceso multiusuario y auditoría centralizada.

## 8. Decisiones y trade-offs

### AES-GCM frente a cifrado sin autenticación

GCM proporciona cifrado autenticado (AEAD): el descifrador no debe aceptar ciphertext o AAD alterados. Un modo de cifrado sin autenticación requeriría diseñar y mantener un mecanismo de autenticación adicional.

### Streaming frente a lectura completa

V1 utiliza `read_bytes`, por lo que el consumo de memoria crece con el archivo. V2 limita el procesamiento del contenido al bloque actual y a los buffers de E/S. Esto reduce el requisito de memoria, pero no demuestra por sí solo mayor velocidad.

### Temporal frente a escritura directa

La salida descifrada se mantiene en un temporal hasta que se autentica el flujo completo. Esto evita publicar un archivo final parcial tras un error de autenticación. No elimina el riesgo de residuos temporales después de una terminación abrupta.

### Hard link frente a replace

El hard link crea el destino solo si el nombre no existe, evitando sobrescritura. No está disponible en todos los sistemas de archivos, por lo que la implementación falla en lugar de usar un fallback potencialmente inseguro.

## 9. Validación pendiente

- Revisión criptográfica independiente del formato V2.
- Pruebas de archivos grandes y mediciones reproducibles de memoria y rendimiento.
- Pruebas de caída abrupta del proceso, reinicio y limpieza de temporales.
- Pruebas de sistemas de archivos y permisos en Windows, Linux y macOS.
- Manejo de cambios concurrentes del archivo de origen.
- Diseño de gestión de claves, rotación y recuperación.
- Almacenamiento inmutable o aislado frente a ransomware.

## 10. Evaluación

Los controles implementados aportan evidencia de comportamiento para escenarios concretos. No constituyen una auditoría criptográfica, una garantía frente a un sistema comprometido ni una declaración de aptitud para producción.
