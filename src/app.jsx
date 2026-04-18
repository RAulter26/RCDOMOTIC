// App shell — routing, estado global, header, tweaks, persistencia

const useLocal = (key, initial) => {
  const [val, setVal] = React.useState(() => {
    try {
      const v = localStorage.getItem(key);
      return v != null ? JSON.parse(v) : initial;
    } catch { return initial; }
  });
  React.useEffect(() => {
    try { localStorage.setItem(key, JSON.stringify(val)); } catch {}
  }, [key, val]);
  return [val, setVal];
};

const App = () => {
  const [route, setRoute] = useLocal('rc.route', { name: 'home' });
  const [showPrice, setShowPrice] = useLocal('rc.showPrice', false);
  const [density, setDensity] = useLocal('rc.density', 'medium');
  const [detailProduct, setDetailProduct] = React.useState(null);
  const [settingsOpen, setSettingsOpen] = React.useState(false);
  const [quoteOpen, setQuoteOpen] = React.useState(false);
  const [quoteItems, setQuoteItems] = useLocal('rc.quote', []);
  const [flash, setFlash] = React.useState(null);

  const goHome = () => setRoute({ name: 'home' });
  const goCatalog = (category) => setRoute({ name: 'catalog', category: category || 'all' });

  const addToQuote = (product) => {
    const exists = quoteItems.find(i => i.id === product.id);
    if (exists) {
      setQuoteItems(quoteItems.filter(i => i.id !== product.id));
      showFlash(`Quitado de cotización`);
    } else {
      setQuoteItems([...quoteItems, { ...product, qty: 1 }]);
      showFlash(`Agregado a cotización`);
    }
  };
  const showFlash = (msg) => {
    setFlash(msg);
    clearTimeout(window.__flashT);
    window.__flashT = setTimeout(() => setFlash(null), 1800);
  };

  // Tweaks bridge
  React.useEffect(() => {
    const handler = (e) => {
      if (e.data?.type === '__activate_edit_mode') setTweaks(true);
      if (e.data?.type === '__deactivate_edit_mode') setTweaks(false);
    };
    window.addEventListener('message', handler);
    window.parent.postMessage({ type: '__edit_mode_available' }, '*');
    return () => window.removeEventListener('message', handler);
  }, []);
  const [tweaks, setTweaks] = React.useState(false);

  return (
    <div className="app">
      {/* HEADER */}
      <header className="top">
        <button className="icon-btn" onClick={() => setSettingsOpen(true)} aria-label="Ajustes">
          <IconMenu size={18}/>
        </button>
        <button className="brand" onClick={goHome}>
          <img src="assets/mark.svg" alt="" className="brand-logo"/>
          <div className="brand-stack">
            <div className="brand-name">RC DOMOTIC</div>
            <div className="brand-sub mono">CATÁLOGO · SHOWROOM</div>
          </div>
        </button>
        <div className="top-right">
          {showPrice && <div className="price-indicator mono">$ ON</div>}
          <button className="icon-btn quote-toggle" onClick={() => setQuoteOpen(true)} aria-label="Cotización">
            <IconCart size={18}/>
            {quoteItems.length > 0 && <span className="badge mono">{quoteItems.length}</span>}
          </button>
        </div>
      </header>

      {/* MAIN */}
      <main className="main">
        {route.name === 'home' && (
          <Home onGoCatalog={() => goCatalog('all')} onPickCategory={goCatalog}/>
        )}
        {route.name === 'catalog' && (
          <>
            <div className="subnav">
              <button className="link" onClick={goHome}><IconBack size={14}/> Inicio</button>
              <span className="sep mono">/</span>
              <span className="mono">CATÁLOGO</span>
            </div>
            <Catalog
              initialCategory={route.category}
              onOpen={setDetailProduct}
              onAddQuote={addToQuote}
              quoteItems={quoteItems}
              showPrice={showPrice}
              density={density}
              onBack={goHome}
            />
          </>
        )}
      </main>

      {/* SHEETS & DRAWERS */}
      <DetailSheet
        product={detailProduct}
        onClose={() => setDetailProduct(null)}
        onAddQuote={addToQuote}
        inQuote={!!quoteItems.find(i => i.id === detailProduct?.id)}
        showPrice={showPrice}
      />
      <SettingsDrawer
        open={settingsOpen} onClose={() => setSettingsOpen(false)}
        showPrice={showPrice} setShowPrice={setShowPrice}
        density={density} setDensity={setDensity}
      />
      <QuoteDrawer
        open={quoteOpen} onClose={() => setQuoteOpen(false)}
        items={quoteItems} setItems={setQuoteItems}
        showPrice={showPrice}
      />

      {/* FAB cotización flotante mobile (solo si hay items) */}
      {quoteItems.length > 0 && !quoteOpen && !detailProduct && (
        <button className="fab" onClick={() => setQuoteOpen(true)}>
          <IconCart size={18}/>
          <span>Ver cotización</span>
          <span className="mono">· {quoteItems.length}</span>
        </button>
      )}

      {/* Flash toast */}
      {flash && <div className="flash mono">{flash}</div>}

      {/* Tweaks panel */}
      {tweaks && (
        <div className="tweaks">
          <div className="tweaks-hdr">
            <div className="mono">TWEAKS</div>
          </div>
          <div className="tweaks-block">
            <div className="tweaks-label mono">DENSIDAD</div>
            <div className="seg">
              {['large','medium','list'].map(d => (
                <button key={d} className={`seg-btn ${density===d?'on':''}`} onClick={() => setDensity(d)}>
                  {d === 'large' ? 'Grande' : d === 'medium' ? 'Media' : 'Lista'}
                </button>
              ))}
            </div>
          </div>
          <div className="tweaks-block">
            <div className="tweaks-label mono">PRECIOS</div>
            <button className={`switch ${showPrice?'on':''}`} onClick={() => setShowPrice(!showPrice)}>
              <span className="switch-dot"/>
            </button>
          </div>
          <div className="tweaks-hint mono">
            Cambia la densidad de las tarjetas y el modo precio para ver las variaciones.
          </div>
        </div>
      )}
    </div>
  );
};

ReactDOM.createRoot(document.getElementById('root')).render(<App/>);
