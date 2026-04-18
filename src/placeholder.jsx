// Placeholder SVG premium — rayado sutil + etiqueta monospace.
// Se usa como imagen de producto hasta tener fotos reales.
const ProductPlaceholder = ({ label, sub, tall = false, compact = false }) => {
  const h = tall ? 420 : (compact ? 120 : 200);
  const id = React.useMemo(() => `p-${Math.random().toString(36).slice(2, 9)}`, []);
  return (
    <svg viewBox={`0 0 400 ${h}`} preserveAspectRatio="xMidYMid slice"
         style={{ width: '100%', height: '100%', display: 'block' }}>
      <defs>
        <pattern id={id} width="14" height="14" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
          <rect width="14" height="14" fill="#0f0f10"/>
          <line x1="0" y1="0" x2="0" y2="14" stroke="#1a1a1c" strokeWidth="6"/>
        </pattern>
        <radialGradient id={`${id}-g`} cx="50%" cy="35%" r="70%">
          <stop offset="0%" stopColor="rgba(57,255,140,0.08)"/>
          <stop offset="60%" stopColor="rgba(57,255,140,0)"/>
        </radialGradient>
      </defs>
      <rect width="100%" height="100%" fill={`url(#${id})`}/>
      <rect width="100%" height="100%" fill={`url(#${id}-g)`}/>
      {/* Etiqueta */}
      {!compact && <>
        <rect x="14" y={h - 38} width="8" height="8" fill="#39ff8c"/>
        <text x="30" y={h - 30} fill="#8a8a8c" fontFamily="'JetBrains Mono', monospace"
              fontSize="10" letterSpacing="0.5">
          IMG / {label.toUpperCase().slice(0, 24)}
        </text>
        {sub && <text x="30" y={h - 16} fill="#4a4a4c" fontFamily="'JetBrains Mono', monospace"
                      fontSize="9" letterSpacing="0.3">
          {sub.toUpperCase().slice(0, 32)}
        </text>}
      </>}
      {compact && <>
        <text x="50%" y="50%" textAnchor="middle" dominantBaseline="middle"
              fill="#5a5a5c" fontFamily="'JetBrains Mono', monospace" fontSize="9" letterSpacing="0.5">
          {label.toUpperCase().slice(0, 20)}
        </text>
      </>}
    </svg>
  );
};

window.ProductPlaceholder = ProductPlaceholder;
