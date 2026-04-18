// Drawer lateral: Ajustes (toggle precios, info) + Cotización

const Drawer = ({ open, side = 'right', onClose, title, children, footer }) => {
  return (
    <div className={`drawer-root ${open ? 'on' : ''} ${side}`} onClick={onClose}>
      <div className="drawer" onClick={e => e.stopPropagation()}>
        <div className="drawer-hdr">
          <div className="drawer-title">{title}</div>
          <button className="icon-btn" onClick={onClose}><IconClose size={18}/></button>
        </div>
        <div className="drawer-body">{children}</div>
        {footer && <div className="drawer-foot">{footer}</div>}
      </div>
    </div>
  );
};

const SettingsDrawer = ({ open, onClose, showPrice, setShowPrice, density, setDensity }) => {
  return (
    <Drawer open={open} side="left" onClose={onClose} title="Ajustes">
      <div className="settings">
        <div className="settings-block">
          <div className="settings-kicker mono">MODO COMERCIAL</div>
          <label className="toggle-row">
            <div>
              <div className="toggle-title">Mostrar precios</div>
              <div className="toggle-sub">Activa solo al cotizar. Desactiva frente al cliente.</div>
            </div>
            <button className={`switch ${showPrice ? 'on' : ''}`} onClick={() => setShowPrice(!showPrice)}>
              <span className="switch-dot"/>
            </button>
          </label>
        </div>

        <div className="settings-block">
          <div className="settings-kicker mono">DENSIDAD DE CATÁLOGO</div>
          <div className="seg">
            {['large', 'medium', 'list'].map(d => (
              <button key={d} className={`seg-btn ${density === d ? 'on' : ''}`} onClick={() => setDensity(d)}>
                {d === 'large' ? 'Grande' : d === 'medium' ? 'Media' : 'Lista'}
              </button>
            ))}
          </div>
        </div>

        <div className="settings-block">
          <div className="settings-kicker mono">CONTACTO</div>
          <div className="info-line">
            <span className="mono dim">WHATSAPP</span>
            <span>+57 312 304 2156</span>
          </div>
          <div className="info-line">
            <span className="mono dim">VISITAS</span>
            <span>Bogotá · Medellín · Cali</span>
          </div>
          <div className="info-line">
            <span className="mono dim">HORARIO</span>
            <span>Lun–Sáb · 8am–7pm</span>
          </div>
        </div>

        <div className="settings-block">
          <div className="settings-kicker mono">ACERCA</div>
          <p className="about-copy">
            Integración premium de hogares y espacios inteligentes.
            Diseño, instalación certificada y mantenimiento.
          </p>
        </div>
      </div>
    </Drawer>
  );
};

const QuoteDrawer = ({ open, onClose, items, setItems, showPrice }) => {
  const total = items.reduce((s, it) => s + it.price * it.qty, 0);
  const changeQty = (id, delta) => {
    setItems(items.map(it => it.id === id ? { ...it, qty: Math.max(1, it.qty + delta) } : it));
  };
  const removeItem = (id) => setItems(items.filter(it => it.id !== id));
  const clearAll = () => setItems([]);

  const buildMessage = () => {
    let m = '*Cotización RC Domotic*\n\n';
    items.forEach((it, i) => {
      m += `${String(i+1).padStart(2,'0')}. ${it.name} x${it.qty}`;
      if (showPrice) m += ` — ${fmtCOP(it.price * it.qty)}`;
      m += '\n';
    });
    if (showPrice) m += `\n*TOTAL:* ${fmtCOP(total)}`;
    m += '\n\nConfirmar disponibilidad y agendar visita, por favor.';
    return m;
  };

  return (
    <Drawer
      open={open} side="right" onClose={onClose}
      title={`Cotización · ${items.length}`}
      footer={items.length > 0 && (
        <div className="quote-foot">
          {showPrice && (
            <div className="quote-total">
              <span className="mono dim">TOTAL</span>
              <span className="quote-total-val mono">{fmtCOP(total)}</span>
            </div>
          )}
          <div className="quote-foot-btns">
            <a className="btn primary whatsapp flex" href={waLink(buildMessage())} target="_blank" rel="noreferrer">
              <IconWhatsapp size={16}/> Enviar por WhatsApp
            </a>
          </div>
          <button className="btn ghost small clear-all" onClick={clearAll}>
            <IconTrash size={14}/> Vaciar cotización
          </button>
        </div>
      )}
    >
      {items.length === 0 ? (
        <div className="empty">
          <div className="empty-mono mono">// COTIZACIÓN VACÍA</div>
          <div className="empty-title">Arma una cotización</div>
          <div className="empty-sub">Agrega productos desde el catálogo con el botón +. Luego envíala por WhatsApp.</div>
        </div>
      ) : (
        <div className="quote-list">
          {items.map(it => {
            const cat = CATEGORIES.find(c => c.id === it.cat);
            return (
              <div className="quote-item" key={it.id}>
                <div className="quote-img"><ProductPlaceholder label={it.name} compact/></div>
                <div className="quote-item-body">
                  <div className="quote-item-cat mono">{cat.short}</div>
                  <div className="quote-item-name">{it.name}</div>
                  {showPrice && (
                    <div className="quote-item-price mono">
                      {fmtCOP(it.price)} <span className="dim">× {it.qty}</span>
                    </div>
                  )}
                </div>
                <div className="quote-controls">
                  <div className="qty">
                    <button onClick={() => changeQty(it.id, -1)}><IconMinus size={12}/></button>
                    <span className="mono">{it.qty}</span>
                    <button onClick={() => changeQty(it.id, 1)}><IconPlus size={12}/></button>
                  </div>
                  <button className="remove" onClick={() => removeItem(it.id)}><IconTrash size={14}/></button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </Drawer>
  );
};

window.SettingsDrawer = SettingsDrawer;
window.QuoteDrawer = QuoteDrawer;
