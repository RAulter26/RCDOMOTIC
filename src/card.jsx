// Product card — 3 densidades (grande / media / lista)

const fmtCOP = (n) => '$' + n.toLocaleString('es-CO');

const ProductImg = ({ product, tall, compact }) => {
  const cat = CATEGORIES.find(c => c.id === product.cat);
  if (product.img && product.img.startsWith('http')) {
    return <img src={product.img} alt={product.name} className="real-img"
                style={{ width:'100%', height:'100%', objectFit:'contain', background:'#fff' }}
                onError={(e) => { e.target.style.display = 'none'; }}/>;
  }
  return <ProductPlaceholder label={product.name} sub={cat.short} tall={tall} compact={compact}/>;
};

const ProductCard = ({ product, density, showPrice, onOpen, onAddQuote, inQuote }) => {
  const cat = CATEGORIES.find(c => c.id === product.cat);
  if (density === 'list') {
    return (
      <button className="card list" onClick={() => onOpen(product)}>
        <div className="card-img">
          <ProductImg product={product} compact/>
        </div>
        <div className="card-body">
          <div className="card-cat">{cat.short}</div>
          <div className="card-name">{product.name}</div>
          {showPrice && <div className="card-price mono">{fmtCOP(product.price)}</div>}
        </div>
        <div className="card-arrow"><IconArrow size={16} /></div>
      </button>
    );
  }
  const tall = density === 'large';
  return (
    <div className={`card ${density}`}>
      <button className="card-img-wrap" onClick={() => onOpen(product)}>
        <div className="card-img">
          <ProductImg product={product} tall={tall}/>
        </div>
        <div className="card-cat-pill"><IconDot size={8} /> {cat.short}</div>
      </button>
      <div className="card-body">
        <div className="card-name">{product.name}</div>
        <div className="card-tag">{product.tagline}</div>
        <div className="card-foot">
          {showPrice
            ? <div className="card-price mono">{fmtCOP(product.price)}</div>
            : <div className="card-price mono muted">Consultar precio</div>}
          <button className={`quote-btn ${inQuote ? 'on' : ''}`}
                  onClick={(e) => { e.stopPropagation(); onAddQuote(product); }}
                  aria-label={inQuote ? 'Quitar de cotización' : 'Agregar a cotización'}>
            {inQuote ? <IconCheck size={16} /> : <IconPlus size={16} />}
          </button>
        </div>
      </div>
    </div>
  );
};

window.ProductCard = ProductCard;
window.fmtCOP = fmtCOP;
