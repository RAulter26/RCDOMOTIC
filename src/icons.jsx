// Iconos minimalistas stroke — hechos para el set RC Domotic.
const Icon = ({ path, size = 20, stroke = 1.6 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
       stroke="currentColor" strokeWidth={stroke} strokeLinecap="round" strokeLinejoin="round">
    {path}
  </svg>
);

const IconSearch   = (p) => <Icon {...p} path={<><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></>}/>;
const IconClose    = (p) => <Icon {...p} path={<><path d="M6 6l12 12M18 6 6 18"/></>}/>;
const IconMenu     = (p) => <Icon {...p} path={<><path d="M4 6h16M4 12h16M4 18h16"/></>}/>;
const IconFilter   = (p) => <Icon {...p} path={<><path d="M3 6h18M6 12h12M10 18h4"/></>}/>;
const IconArrow    = (p) => <Icon {...p} path={<><path d="M5 12h14M13 6l6 6-6 6"/></>}/>;
const IconBack     = (p) => <Icon {...p} path={<><path d="M19 12H5M11 6l-6 6 6 6"/></>}/>;
const IconPlus     = (p) => <Icon {...p} path={<><path d="M12 5v14M5 12h14"/></>}/>;
const IconMinus    = (p) => <Icon {...p} path={<><path d="M5 12h14"/></>}/>;
const IconCheck    = (p) => <Icon {...p} path={<><path d="M5 12l5 5L20 7"/></>}/>;
const IconCart     = (p) => <Icon {...p} path={<><path d="M3 4h2l2.5 12h12L22 7H7"/><circle cx="10" cy="20" r="1.4"/><circle cx="18" cy="20" r="1.4"/></>}/>;
const IconSettings = (p) => <Icon {...p} path={<><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.87l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.7 1.7 0 0 0-1.87-.34 1.7 1.7 0 0 0-1.05 1.57V21a2 2 0 1 1-4 0v-.08a1.7 1.7 0 0 0-1.11-1.57 1.7 1.7 0 0 0-1.87.34l-.06.06A2 2 0 1 1 4.12 16.9l.06-.06A1.7 1.7 0 0 0 4.52 15a1.7 1.7 0 0 0-1.57-1.05H3a2 2 0 1 1 0-4h.08A1.7 1.7 0 0 0 4.52 9 1.7 1.7 0 0 0 4.18 7.13l-.06-.06A2 2 0 1 1 6.95 4.24l.06.06A1.7 1.7 0 0 0 8.88 4.64h.02A1.7 1.7 0 0 0 9.95 3H10a2 2 0 1 1 4 0v.08a1.7 1.7 0 0 0 1.05 1.57 1.7 1.7 0 0 0 1.87-.34l.06-.06A2 2 0 1 1 19.76 7.1l-.06.06A1.7 1.7 0 0 0 19.36 9v.02a1.7 1.7 0 0 0 1.57 1.05H21a2 2 0 1 1 0 4h-.08a1.7 1.7 0 0 0-1.52 1.05z"/></>}/>;
const IconWhatsapp = ({ size = 20 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor">
    <path d="M17.5 14.4c-.3-.15-1.77-.87-2.04-.97-.27-.1-.47-.15-.67.15-.2.3-.77.97-.95 1.17-.17.2-.35.22-.65.07-.3-.15-1.26-.47-2.4-1.48-.89-.79-1.49-1.77-1.66-2.07-.17-.3-.02-.46.13-.61.14-.13.3-.35.45-.52.15-.17.2-.3.3-.5.1-.2.05-.37-.02-.52-.07-.15-.67-1.62-.92-2.22-.24-.58-.49-.5-.67-.51l-.57-.01c-.2 0-.52.07-.79.37-.27.3-1.04 1.02-1.04 2.48s1.07 2.88 1.22 3.08c.15.2 2.1 3.2 5.08 4.49.71.31 1.26.49 1.7.63.71.23 1.36.2 1.87.12.57-.09 1.77-.72 2.02-1.42.25-.7.25-1.29.17-1.42-.07-.13-.27-.2-.57-.35zM12.05 21.5h-.04c-1.8 0-3.57-.48-5.11-1.4l-.37-.22-3.8 1 1.02-3.71-.24-.38a9.45 9.45 0 0 1-1.46-5.08c0-5.23 4.27-9.5 9.52-9.5 2.54 0 4.93.99 6.72 2.78a9.44 9.44 0 0 1 2.78 6.73c-.01 5.24-4.27 9.5-9.52 9.5zm8.1-17.6A11.43 11.43 0 0 0 12.05 1C5.7 1 .56 6.14.56 12.49c0 2.03.53 4.01 1.54 5.76L.5 24.09l5.98-1.57a11.43 11.43 0 0 0 5.48 1.4h.01c6.34 0 11.49-5.15 11.49-11.5 0-3.07-1.2-5.96-3.36-8.13z"/>
  </svg>
);
const IconShare    = (p) => <Icon {...p} path={<><path d="M4 12v7a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-7M16 6l-4-4-4 4M12 2v13"/></>}/>;
const IconTrash    = (p) => <Icon {...p} path={<><path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></>}/>;
const IconDot      = (p) => <Icon {...p} path={<><circle cx="12" cy="12" r="3"/></>} stroke={0}/>;

// Category glyphs — abstract, one shape each
const IconDomotica = ({ size = 28 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round">
    <path d="M4 11 12 4l8 7v8a1 1 0 0 1-1 1h-4v-6h-6v6H5a1 1 0 0 1-1-1z"/>
    <circle cx="12" cy="13" r="1.3" fill="currentColor"/>
  </svg>
);
const IconCCTV = ({ size = 28 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round">
    <rect x="3" y="7" width="14" height="7" rx="1"/>
    <path d="M17 9l4-1.5v8L17 14M8 14v4h5"/>
    <circle cx="6.5" cy="10.5" r="1" fill="currentColor"/>
  </svg>
);
const IconAudioVideo = ({ size = 28 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round">
    <rect x="3" y="5" width="18" height="11" rx="1.5"/>
    <path d="M8 20h8M12 16v4"/>
    <circle cx="12" cy="10.5" r="2" fill="currentColor" opacity=".35"/>
  </svg>
);
const IconTeatro = ({ size = 28 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round">
    <path d="M3 6h18l-1 3H4z"/>
    <path d="M5 9v10h3v-4h8v4h3V9"/>
  </svg>
);
const IconCerradura = ({ size = 28 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round">
    <rect x="5" y="10" width="14" height="10" rx="1.5"/>
    <path d="M8 10V7a4 4 0 0 1 8 0v3"/>
    <circle cx="12" cy="15" r="1.2" fill="currentColor"/>
  </svg>
);
const IconPortero = ({ size = 28 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round">
    <rect x="6" y="3" width="12" height="18" rx="1.5"/>
    <circle cx="12" cy="9" r="2"/>
    <path d="M10 14h4M9.5 17h5"/>
  </svg>
);
const IconRedes = ({ size = 28 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round">
    <path d="M3 12a14 14 0 0 1 18 0M6 15.5a9 9 0 0 1 12 0M9 19a4 4 0 0 1 6 0"/>
    <circle cx="12" cy="21" r="1.2" fill="currentColor"/>
  </svg>
);
const IconServicios = ({ size = 28 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round">
    <path d="M14 6l4 4M4 20l6-2 9-9-4-4-9 9-2 6z"/>
    <path d="M13 7l4 4"/>
  </svg>
);

const CAT_ICON = {
  domotica: IconDomotica, cctv: IconCCTV, audiovideo: IconAudioVideo,
  teatro: IconTeatro, cerraduras: IconCerradura, videoporteros: IconPortero,
  redes: IconRedes, servicios: IconServicios,
};

Object.assign(window, {
  IconSearch, IconClose, IconMenu, IconFilter, IconArrow, IconBack, IconPlus,
  IconMinus, IconCheck, IconCart, IconSettings, IconWhatsapp, IconShare, IconTrash,
  IconDot, CAT_ICON,
});
