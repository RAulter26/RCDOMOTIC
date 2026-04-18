# Security Remediation Status

Estado local de endurecimiento antes de desplegar a produccion.

## Ya corregido en codigo local

- `/print/<id>` requiere login.
- `/export/excel/<id>` requiere login.
- `/print/inventario` requiere rol `admin`.
- `/api/inventario*`, `/api/proveedores*`, `/api/compras*`, `/api/parametros`,
  `/api/price_lists` y `/api/stats*` requieren rol `admin` de forma explicita.
- `/api/bot/*` deja de aceptar la llave por defecto en produccion si `BOT_KEY`
  no esta configurado.
- Se agregaron `.gitignore` y `.env.example`.

## No desplegar sin hacer antes

1. Configurar `BOT_KEY` real en Render.
2. Configurar `SECRET_KEY` real en Render.
3. Verificar que el bot/n8n usen la nueva `BOT_KEY`.

## Pendiente importante del repo

- `rc_domotic.db` sigue tracked en Git.
- `uploads/` sigue tracked en Git.
- Hace falta sacarlos del repo y luego purgar historial si se quiere eliminar la
  exposicion historica.

## Pendiente importante fuera del repo

- Rotar `BOT_KEY`, `N8N_API_KEY` y cualquier token compartido.
- Cerrar o proteger webhooks publicos sensibles en n8n.
- Revisar ownership, MFA y permisos en GitHub, Render, Vercel y GoDaddy.
