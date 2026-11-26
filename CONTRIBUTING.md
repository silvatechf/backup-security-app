# Contribuir

## Entorno local

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
python -m pytest -v
```

## Criterios

- Mantener la documentación técnica en español.
- Añadir pruebas para cambios funcionales y de seguridad.
- No añadir secretos, copias reales ni datos personales.
- No cambiar el formato cifrado sin actualizar su versión y documentar la compatibilidad.
- Abrir cambios mediante pull request hacia main.
