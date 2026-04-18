// Vista Catálogo — buscador, filtros por categoría, densidades

const Catalog = ({
  initialCategory, onOpen, onAddQuote, quoteItems,
  showPrice, density, onBack,
}) => {
  const [q, setQ] = React.useState('');
  const [cat, setCat] = React.useState(initialCategory || 'all');
  const [searching, setSearching] = React.useState(false);

  const filtered = React.useMemo(() => {
    const qq = q.trim().toLowerCase();
    return PRODUCTS.filter(p => {
      if (cat !== 'all' && p.cat !== cat) return false;
      if (!qq) return true;
      return p.name.toLowerCase().includes(qq) ||
             p.tagline.toLowerCase().includes(qq) ||
             p.specs.some(s => s.toLowerCase().includes(qq));
    });
  }, [q, cat]);

  const scrollerRef = React.useRef(null);
  React.useEffect(() => {
    if (scrollerRef.current) scrollerRef.current.scrollTo({ top: 0, behavior: 'smooth' });
  }, [cat]);

  const catName = cat === 'all' ? 'Todas las líneas' : CATEGORIES.find(c => c.id === cat)?.name;
  const qIds = new Set(quoteItems.map(i => i.id));

  return (
    <div className="catalog">
      {/* Search bar */}
      <div className="cat-search-bar">
        <div className={`search-wrap ${searching ? 'focused' : ''}`}>
          <IconSearch size={16}/>
          <input
            value={q}
            onChange={e => setQ(e.target.value)}
            onFocus={() => setSearching(true)}
            onBlur={() => setSearching(false)}
            placeholder="Buscar referencia, especificación…"
          />
          {q && <button className="search-clear" onClick={() => setQ('')}><IconClose size={14}/></button>}
        </div>
      </div>

      {/* Category chips */}
      <div className="chips-row">
        <div className="chips">
          <button className={`chip ${cat === 'all' ? 'on' : ''}`} onClick={() => setCat('all')}>
            Todas <span className="chip-count mono">{PRODUCTS.length}</span>
          </button>
          {CATEGORIES.map(c => (
            <button key={c.id} className={`chip ${cat === c.id ? 'on' : ''}`} onClick={() => setCat(c.id)}>
              {c.short} <span className="chip-count mono">{c.count}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Header line */}
      <div className="cat-hdr">
        <div>
          <div className="mono kicker">/ {cat === 'all' ? 'CATÁLOGO' : 'LÍNEA'}</div>
          <div className="cat-hdr-title">{catName}</div>
        </div>
        <div className="mono count-badge">
          {filtered.length} {filtered.length === 1 ? 'referencia' : 'referencias'}
        </div>
      </div>

      {/* Grid */}
      <div ref={scrollerRef} className={`grid density-${density}`}>
        {filtered.length === 0 && (
          <div className="empty">
            <div className="empty-mono mono">// SIN RESULTADOS</div>
            <div className="empty-title">No encontramos referencias</div>
            <div className="empty-sub">Intenta con otra palabra o cambia la categoría.</div>
            <button className="btn ghost small" onClick={() => { setQ(''); setCat('all'); }}>Reiniciar filtros</button>
          </div>
        )}
        {filtered.map(p => (
          <ProductCard
            key={p.id}
            product={p}
            density={density}
            showPrice={showPrice}
            onOpen={onOpen}
            onAddQuote={onAddQuote}
            inQuote={qIds.has(p.id)}
          />
        ))}
      </div>
    </div>
  );
};

window.Catalog = Catalog;
