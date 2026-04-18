// Home — hero grande + grid categorías

const WHATSAPP = '573123042156';
const waLink = (msg) => `https://wa.me/${WHATSAPP}?text=${encodeURIComponent(msg)}`;

const Home = ({ onGoCatalog, onPickCategory }) => {
  const featured = PRODUCTS.filter(p => ['av-013','cek-003','w01','cam-003','dom-004','av-001'].includes(p.id)).slice(0, 4);
  if (featured.length < 4) {
    // fallback: take first product from 4 different cats
    const picks = [];
    const seen = new Set();
    for (const p of PRODUCTS) { if (!seen.has(p.cat)) { picks.push(p); seen.add(p.cat); } if (picks.length >= 4) break; }
    featured.splice(0, featured.length, ...picks);
  }
  return (
    <div className="home">
      {/* HERO */}
      <section className="hero">
        <div className="hero-grid">
          <div className="hero-row"></div><div className="hero-row"></div>
          <div className="hero-row"></div><div className="hero-row"></div>
        </div>
        <div className="hero-content">
          <div className="hero-eyebrow mono">
            <span className="pulse"/> CATÁLOGO 2026 · SHOWROOM
          </div>
          <h1 className="hero-title">
            Hogares <em>inteligentes.</em><br/>
            Espacios <em>premium.</em>
          </h1>
          <p className="hero-sub">
            Domótica, CCTV, audio de referencia y conectividad profesional.
            Diseño, instalación y mantenimiento.
          </p>
          <div className="hero-ctas">
            <button className="btn primary" onClick={onGoCatalog}>
              Ver catálogo completo <IconArrow size={16} />
            </button>
            <a className="btn ghost" href={waLink('Hola RC Domotic, quiero asesoría.')} target="_blank" rel="noreferrer">
              <IconWhatsapp size={16}/> Asesoría directa
            </a>
          </div>
        </div>
        <div className="hero-meta">
          <div><span className="mono num">{CATEGORIES.length}</span><span>líneas</span></div>
          <div><span className="mono num">{PRODUCTS.length}</span><span>referencias</span></div>
          <div><span className="mono num">24/7</span><span>soporte</span></div>
        </div>
      </section>

      {/* CATEGORÍAS */}
      <section className="cats">
        <div className="section-head">
          <div className="section-kicker mono">/ 01 — LÍNEAS</div>
          <h2 className="section-title">Nuestras <em>líneas</em> de producto</h2>
        </div>
        <div className="cats-grid">
          {CATEGORIES.map((c, i) => {
            const Glyph = CAT_ICON[c.id];
            return (
              <button key={c.id} className="cat-card" onClick={() => onPickCategory(c.id)}>
                <div className="cat-num mono">/ {String(i+1).padStart(2,'0')}</div>
                <div className="cat-glyph"><Glyph size={36}/></div>
                <div className="cat-name">{c.name}</div>
                <div className="cat-meta mono">{c.count} REFERENCIAS →</div>
              </button>
            );
          })}
        </div>
      </section>

      {/* DESTACADOS */}
      <section className="featured">
        <div className="section-head">
          <div className="section-kicker mono">/ 02 — DESTACADOS</div>
          <h2 className="section-title">Piezas de <em>referencia</em></h2>
        </div>
        <div className="featured-grid">
          {featured.map(p => {
            const cat = CATEGORIES.find(c => c.id === p.cat);
            return (
              <button key={p.id} className="feat-card" onClick={() => onPickCategory(p.cat)}>
                <div className="feat-img">
                  {p.img && p.img.startsWith('http')
                    ? <img src={p.img} alt={p.name} style={{width:'100%',height:'100%',objectFit:'cover',background:'#fff'}}/>
                    : <ProductPlaceholder label={p.name} sub={cat.short} tall/>}
                </div>
                <div className="feat-over">
                  <div className="feat-cat mono">{cat.short.toUpperCase()}</div>
                  <div className="feat-name">{p.name}</div>
                </div>
              </button>
            );
          })}
        </div>
      </section>

      <footer className="home-foot">
        <div className="foot-line"/>
        <div className="foot-row">
          <div>
            <div className="mono muted tiny">RC DOMOTIC · {new Date().getFullYear()}</div>
            <div className="foot-tag">Integración · Diseño · Instalación</div>
          </div>
          <a className="btn ghost small" href={waLink('Hola, quiero coordinar una visita.')} target="_blank" rel="noreferrer">
            <IconWhatsapp size={14}/> Agendar visita
          </a>
        </div>
      </footer>
    </div>
  );
};

window.Home = Home;
window.WHATSAPP = WHATSAPP;
window.waLink = waLink;
