# Modelo de amenazas — V1

## Activos

- Contenido de la copia de seguridad.
- Contraseña utilizada para derivar la clave.
- Clave AES derivada durante la operación.
- Integridad y disponibilidad del archivo recuperable.

## Límites de confianza

El usuario selecciona explícitamente el archivo de origen y la ruta de destino. El sistema operativo, el intérprete Python y la dependencia criptográfica forman parte de la base de confianza.

## Amenazas consideradas

| Amenaza | Control V1 | Riesgo residual |
|---|---|---|
| Lectura no autorizada del backup cifrado | AES-256-GCM | Contraseña débil o comprometida |
| Modificación del archivo cifrado | Etiqueta GCM y AAD | Eliminación o bloqueo del archivo |
| Contraseña incorrecta | Fallo de autenticación | No existe recuperación de contraseña |
| Sobrescritura accidental | Creación exclusiva del destino | Condiciones de carrera complejas y fallos del sistema |
| Exposición de secretos en el repositorio | No se guardan claves ni contraseñas | Secretos que el usuario pueda añadir accidentalmente |

## Fuera del alcance de V1

- Cifrado de carpetas completas o recorrido del sistema operativo.
- Protección frente a malware con privilegios sobre el equipo.
- Copias inmutables, almacenamiento remoto y recuperación ante desastres.
- Gestión centralizada, rotación y recuperación de claves.
- Confidencialidad de nombres, tamaños y otros metadatos.

## Supuestos y recomendaciones

- Usar contraseñas largas, únicas y almacenadas en un gestor seguro.
- Mantener una copia independiente del backup original.
- Probar la restauración antes de considerar fiable una copia.
- Ejecutar el prototipo con datos de prueba, no con la única copia de información importante.

## Riesgo crítico conocido

La V1 utiliza operaciones de lectura completa (read_bytes) y escritura completa en memoria. No es apropiada para archivos grandes. La próxima evolución debe diseñar cifrado autenticado por bloques con un formato versionado y pruebas de truncamiento, reordenación, duplicación y manipulación de bloques.
