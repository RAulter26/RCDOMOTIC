// Bottom sheet — detalle de producto
const DetailSheet = ({ product, onClose, onAddQuote, inQuote, showPrice }) => {
  const sheetRef = React.useRef(null);
  const [drag, setDrag] = React.useState(null);
  const [offset, setOffset] = React.useState(0);
  const cat = product ? CATEGORIES.find(c => c.id === product.cat) : null;

  React.useEffect(() => {
    if (product) document.body.style.overflow = 'hidden';
    else document.body.style.overflow = '';
    return () => { document.body.style.overflow = ''; };
  }, [product]);

  const onStart = (e) => {
    const y = e.touches ? e.touches[0].clientY : e.clientY;
    setDrag(y);
  };
  const onMove = (e) => {
    if (drag == null) return;
    const y = e.touches ? e.touches[0].clientY : e.clientY;
    setOffset(Math.max(0, y - drag));
  };
  const onEnd = () => {
    if (offset > 120) onClose();
    setDrag(null); setOffset(0);
  };

  if (!product) return null;

  const waMsg = `Hola RC Domotic, me interesa *${product.name}*${showPrice ? ` (${fmtCOP(product.price)})` : ''}. ¿Podemos hablar?`;

  return (
    <div className="sheet-root" onClick={onClose}>
      <div
        ref={sheetRef}
        className="sheet"
        style={{ transform: `translateY(${offset}px)`, transition: drag ? 'none' : 'transform .32s cubic-bezier(.22,.8,.2,1)' }}
        onClick={e => e.stopPropagation()}
      >
        <div className="sheet-grip-wrap"
             onMouseDown={onStart} onMouseMove={onMove} onMouseUp={onEnd} onMouseLeave={onEnd}
             onTouchStart={onStart} onTouchMove={onMove} onTouchEnd={onEnd}>
          <div className="sheet-grip"/>
        </div>

        <button className="sheet-close" onClick={onClose}><IconClose size={18}/></button>

        <div className="sheet-content">
          {/* Hero imagen */}
          <div className="sheet-hero">
            {product.img && product.img.startsWith('http')
              ? <img src={product.img} alt={product.name} style={{width:'100%',height:'100%',objectFit:'contain',background:'#fff'}}/>
              : <ProductPlaceholder label={product.name} sub={cat.short} tall/>}
            <div className="sheet-cat mono"><IconDot size={8}/> {cat.name.toUpperCase()}</div>
            <div className="sheet-id mono">REF · {product.id.toUpperCase()}</div>
          </div>

          <div className="sheet-body">
            <h2 className="sheet-name">{product.name}</h2>
            <p className="sheet-tag">{product.tagline}</p>

            {showPrice ? (
              <div className="sheet-price-row">
                <div>
                  <div className="sheet-price-label mono">PRECIO</div>
                  <div className="sheet-price mono">{fmtCOP(product.price)}</div>
                </div>
                <div className="sheet-price-note">IVA incluido · Instalación según proyecto</div>
              </div>
            ) : (
              <div className="sheet-price-row">
                <div>
                  <div className="sheet-price-label mono">PRECIO</div>
                  <div className="sheet-price muted">A consultar</div>
                </div>
                <div className="sheet-price-note">Cotizamos según configuración</div>
              </div>
            )}

            <div className="sheet-specs">
              <div className="sheet-specs-hdr mono">ESPECIFICACIONES</div>
              <ul>
                {product.specs.map((s, i) => (
                  <li key={i}>
                    <span className="mono dim">{String(i+1).padStart(2,'0')}</span>
                    <span>{s}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          <div className="sheet-actions">
            <button className={`btn solid ${inQuote ? 'added' : ''}`} onClick={() => onAddQuote(product)}>
              {inQuote
                ? <><IconCheck size={16}/> En cotización</>
                : <><IconPlus size={16}/> Agregar a cotización</>}
            </button>
            <a className="btn primary whatsapp" href={waLink(waMsg)} target="_blank" rel="noreferrer">
              <IconWhatsapp size={16}/> Consultar por WhatsApp
            </a>
          </div>
        </div>
      </div>
    </div>
  );
};

window.DetailSheet = DetailSheet;
