# RC DOMOTIC — Cotizador App v3.0
**Flask + SQLite3 | Sin internet | Funciona en PC, Mac o servidor**

## ✨ Novedades v3.0
- ✅ **Excel arreglado** — Export robusto con try/except, datos validados, 2 hojas
- 📂 **Selector por categoría** — Filtra productos por categoría al crear/editar cotización
- 🔄 **Merge duplicados** — Si agregas el mismo producto, suma cantidad (+1)
- 🖼 **Logo siempre** — Cache-busting, logo en navbar + PDF header + watermark
- 📄 **PDF mejorado** — Watermark con logo al 6% opacidad
- 📊 **Dashboard ventas** — Solo APROBADA: ventas mes, top productos, clientes, proyección
- 📦 **Catálogo Pro** — Vista simple/completa, filtros, tooltips
- ⚡ **Comandos** — Crear cotización pegando JSON (sin SQL libre, 100% seguro)
- 📝 **Auditoría** — Tabla commands_log registra cada comando ejecutado

## Requisitos
- Python 3.8+

## Instalación
```bash
pip install flask openpyxl
```

## Correr la app
```bash
cd cotizador_app
python app.py
```
Abre: **http://localhost:5000**

## 📱 Desde el celular (misma red WiFi)
1. IP de tu PC: `ipconfig` (Windows) o `ifconfig` (Mac/Linux)
2. En el celular: `http://TU_IP:5000`

## Actualizar desde v2.0 (SIN perder datos)
```bash
# 1. Backup de tu BD
cp rc_domotic.db rc_domotic_backup.db

# 2. Reemplazar SOLO estos archivos:
#    app.py
#    static/index.html
#    static/brand_logo.png  (logo oficial)
#    requirements.txt

# 3. Ejecutar
python app.py
```
**La BD NO se toca.** Las migraciones se aplican automáticamente con ALTER TABLE ADD COLUMN.

## Estructura
```
cotizador_app/
├── app.py                  ← Backend completo (935 líneas)
├── rc_domotic.db           ← BD (se crea sola, NUNCA se borra)
├── requirements.txt
├── README.md
├── static/
│   ├── index.html          ← Frontend SPA (560 líneas)
│   └── brand_logo.png      ← Logo oficial
└── uploads/products/       ← Imágenes de productos
```

## API
| Método | URL | Descripción |
|---|---|---|
| GET | `/api/catalogo` | Productos (`?categoria=CCTV`) |
| GET | `/api/catalogo/categorias` | Categorías |
| POST/PUT | `/api/catalogo` | CRUD producto |
| POST | `/api/catalogo/:id/imagen` | Subir imagen |
| GET | `/api/cotizaciones` | Listar (`?q=&estado=`) |
| POST/PUT/DELETE | `/api/cotizaciones/:id` | CRUD cotización |
| GET | `/api/cotizaciones/:id/margenes` | Rentabilidad interna |
| GET | `/api/cotizaciones/:id/whatsapp` | Link WhatsApp |
| GET | `/print/:id` | PDF imprimible |
| GET | `/export/excel/:id` | Excel (.xlsx) |
| GET | `/api/stats` | Stats generales |
| GET | `/api/stats/dashboard` | Dashboard APROBADA |
| POST | `/api/commands/create_quote` | Crear cot. por JSON |
| GET/PUT | `/api/parametros` | Config empresa |

## Comando JSON (ejemplo)
```json
{
  "cliente": "Juan Perez",
  "proyecto": "Conjunto Marsella",
  "ciudad": "Sincelejo",
  "descuento_pct": 5,
  "anticipo_pct": 70,
  "items": [
    {"codigo": "CAM-001", "cant": 2},
    {"codigo": "DOM-001", "cant": 3}
  ]
}
```
- Duplicados se mergean automáticamente
- Códigos inválidos se rechazan con error claro
- Cada comando queda en `commands_log`

## Confirmaciones de seguridad
- ✅ No se borra la BD
- ✅ No hay DROP TABLE
- ✅ Migraciones solo con ALTER TABLE ADD COLUMN
- ✅ IVA solo aplica a productos (no instalación/configuración)
- ✅ Dashboard ventas solo cuenta cotizaciones APROBADA
- ✅ No hay SQL libre — comandos son JSON validado
