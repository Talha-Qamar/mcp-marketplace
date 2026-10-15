/* =============================================================
   MCP Marketplace — Premium UI Components
   ============================================================= */

/* ---- SVG Icon Library (Lucide-style) ---- */
const ICONS = {
  server: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="8" x="2" y="2" rx="2" ry="2"/><rect width="20" height="8" x="2" y="14" rx="2" ry="2"/><line x1="6" x2="6.01" y1="6" y2="6"/><line x1="6" x2="6.01" y1="18" y2="18"/></svg>`,
  database: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5V19A9 3 0 0 0 21 19V5"/><path d="M3 12A9 3 0 0 0 21 12"/></svg>`,
  code: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>`,
  globe: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" x2="22" y1="12" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>`,
  shield: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
  sparkles: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m12 3-1.912 5.813a2 2 0 0 1-1.275 1.275L3 12l5.813 1.912a2 2 0 0 1 1.275 1.275L12 21l1.912-5.813a2 2 0 0 1 1.275-1.275L21 12l-5.813-1.912a2 2 0 0 1-1.275-1.275L12 3Z"/><path d="M5 3v4"/><path d="M19 17v4"/><path d="M3 5h4"/><path d="M17 19h4"/></svg>`,
  zap: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>`,
  cloud: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z"/></svg>`,
  'message-circle': `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M7.9 20A9 9 0 1 0 4 16.1L2 22Z"/></svg>`,
  'message-square': `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>`,
  terminal: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" x2="20" y1="19" y2="19"/></svg>`,
  search: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>`,
  star: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>`,
  download: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" x2="12" y1="15" y2="3"/></svg>`,
  copy: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>`,
  check: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`,
  'check-circle': `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="currentColor" stroke="none"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 14.5-4-4 1.41-1.41L10 13.67l6.59-6.59L18 8.5l-8 8z"/></svg>`,
  'arrow-right': `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></svg>`,
  'external-link': `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" x2="21" y1="14" y2="3"/></svg>`,
  package: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m7.5 4.27 9 5.15"/><path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z"/><path d="m3.3 7 8.7 5 8.7-5"/><path d="M12 22V12"/></svg>`,
  users: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>`,
  activity: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>`,
  puzzle: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19.439 7.85c-.049.322.059.648.289.878l1.568 1.568c.47.47.706 1.087.706 1.704s-.235 1.233-.706 1.704l-1.611 1.611a.98.98 0 0 1-.837.276c-.47-.07-.802-.48-.968-.925a2.501 2.501 0 1 0-3.214 3.214c.446.166.855.497.925.968a.979.979 0 0 1-.276.837l-1.61 1.61a2.404 2.404 0 0 1-1.705.707 2.402 2.402 0 0 1-1.704-.706l-1.568-1.568a1.026 1.026 0 0 0-.877-.29c-.493.074-.84.504-1.02.968a2.5 2.5 0 1 1-3.237-3.237c.464-.18.894-.527.967-1.02a1.026 1.026 0 0 0-.289-.877l-1.568-1.568A2.402 2.402 0 0 1 1.998 12c0-.617.236-1.234.706-1.704L4.23 8.77c.24-.24.581-.353.917-.303.515.077.877.528 1.073 1.01a2.5 2.5 0 1 0 3.259-3.259c-.482-.196-.933-.558-1.01-1.073-.05-.336.062-.676.303-.917l1.525-1.525A2.402 2.402 0 0 1 12 1.998c.617 0 1.234.236 1.704.706l1.568 1.568c.23.23.556.338.877.29.493-.074.84-.504 1.02-.968a2.5 2.5 0 1 1 3.237 3.237c-.464.18-.894.527-.967 1.02Z"/></svg>`,
  inbox: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/></svg>`,
  plus: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" x2="12" y1="5" y2="19"/><line x1="5" x2="19" y1="12" y2="12"/></svg>`,
  trash: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg>`,
  chevronDown: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></svg>`,
  'log-out': `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/></svg>`,
  user: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>`,
  box: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z"/><path d="m3.3 7 8.7 5 8.7-5"/><path d="M12 22V12"/></svg>`,
  'file-text': `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/><path d="M10 9H8"/><path d="M16 13H8"/><path d="M16 17H8"/></svg>`,
  cpu: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M15 2v2"/><path d="M15 20v2"/><path d="M2 15h2"/><path d="M2 9h2"/><path d="M20 15h2"/><path d="M20 9h2"/><path d="M9 2v2"/><path d="M9 20v2"/></svg>`,
  wrench: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>`,
  sun: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/></svg>`,
  moon: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg>`,
};

/* ---- Helper: render icon by name ---- */
function icon(name, size = 16) {
  const svg = ICONS[name] || ICONS.server;
  return svg.replace(/width="24" height="24"/, `width="${size}" height="${size}"`);
}

/* ---- Brand Avatar Registry ---- */
const BRAND_LOGOS = {
  github: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0 1 12 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z"/></svg>`,
  anthropic: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M13.827 3.52h3.603L24 20.48h-3.603l-6.57-16.96zm-7.258 0H10.17L16.744 20.48H13.14L11.89 17.09H5.083l-1.25 3.39H0L6.57 3.52zm4.132 10.422-2.287-6.235-2.288 6.235h4.575z"/></svg>`,
  claude: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M13.827 3.52h3.603L24 20.48h-3.603l-6.57-16.96zm-7.258 0H10.17L16.744 20.48H13.14L11.89 17.09H5.083l-1.25 3.39H0L6.57 3.52zm4.132 10.422-2.287-6.235-2.288 6.235h4.575z"/></svg>`,
  cursor: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4l7.07 17 2.51-7.39L21 11.07z"/></svg>`,
  asana: `<svg viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="5.25" r="4.25"/><circle cx="5.25" cy="15.75" r="4.25"/><circle cx="18.75" cy="15.75" r="4.25"/></svg>`,
  vscode: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M23.15 2.587L18.21.21a1.494 1.494 0 0 0-1.705.29l-9.46 8.63-4.12-3.128a.999.999 0 0 0-1.276.057L.327 7.261A1 1 0 0 0 .326 8.74L3.899 12 .326 15.26a1 1 0 0 0 .001 1.479L1.65 17.94a.999.999 0 0 0 1.276.057l4.12-3.128 9.46 8.63a1.492 1.492 0 0 0 1.704.29l4.942-2.377A1.5 1.5 0 0 0 24 20.06V3.939a1.5 1.5 0 0 0-.85-1.352zm-5.146 14.861L10.826 12l7.178-5.448v10.896z"/></svg>`,
  brave: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M22.449 7.532l.037.204-.93 5.212s-1.22 7.056-1.386 7.95c-.163.896-1.01 2.42-2.29 2.852C16.776 24.206 14.226 24 12 24s-4.776.206-5.88-.25c-1.28-.431-2.127-1.956-2.29-2.852C3.665 19.998 2.445 12.942 2.445 12.942L1.515 7.73l.037-.204L3.75 5.46l.7 1.152c.095.154.235.186.344.066l1.745-1.913.81 1.173c.085.118.225.15.34.046L9.36 4.296l.81.765c.085.085.225.085.33 0l1.5-1.435 1.5 1.435c.105.085.245.085.33 0l.81-.765 1.671 1.688c.115.104.255.072.34-.046l.81-1.173 1.745 1.913c.11.12.25.088.344-.066l.7-1.152 2.199 2.072z"/></svg>`,
  openai: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M22.282 9.821a5.985 5.985 0 0 0-.516-4.91 6.046 6.046 0 0 0-6.51-2.9A6.065 6.065 0 0 0 4.981 4.18a5.985 5.985 0 0 0-3.998 2.9 6.046 6.046 0 0 0 .743 7.097 5.98 5.98 0 0 0 .51 4.911 6.051 6.051 0 0 0 6.515 2.9A5.985 5.985 0 0 0 13.26 24a6.056 6.056 0 0 0 5.772-4.206 5.99 5.99 0 0 0 3.997-2.9 6.056 6.056 0 0 0-.747-7.073zM13.26 22.43a4.476 4.476 0 0 1-2.876-1.04l.141-.081 4.779-2.758a.795.795 0 0 0 .392-.681v-6.737l2.02 1.168a.071.071 0 0 1 .038.052v5.583a4.504 4.504 0 0 1-4.494 4.494zM3.6 18.304a4.47 4.47 0 0 1-.535-3.014l.142.085 4.783 2.759a.771.771 0 0 0 .78 0l5.843-3.369v2.332a.08.08 0 0 1-.032.067L9.832 19.53a4.496 4.496 0 0 1-6.232-1.227zm-1.569-9.994a4.486 4.486 0 0 1 2.341-1.975V11.5a.83.83 0 0 0 .389.68l5.819 3.357-2.02 1.168a.076.076 0 0 1-.071 0L4.152 13.78A4.501 4.501 0 0 1 2.03 8.31zm16.373 3.866L12.56 8.807l2.02-1.168a.075.075 0 0 1 .071 0l4.335 2.503a4.496 4.496 0 0 1-.677 8.116V13.1a.83.83 0 0 0-.39-.68zm2.01-3.055l-.141-.085-4.774-2.782a.776.776 0 0 0-.785 0L9.87 9.19V6.857a.071.071 0 0 1 .028-.061l4.334-2.5a4.495 4.495 0 0 1 6.68 4.66zm-12.64 4.135l-2.02-1.164a.08.08 0 0 1-.038-.057V7.43a4.492 4.492 0 0 1 7.37-3.453l-.142.08L8.154 6.82a.795.795 0 0 0-.393.681zm1.097-2.365l2.602-1.5 2.607 1.5v2.999l-2.597 1.5-2.607-1.5z"/></svg>`,
  postgresql: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M23.5 11.977c-.27-1.566-1.238-2.815-2.518-3.577-.46-.271-.948-.461-1.447-.585.043-.43.054-.863.035-1.295-.028-.644-.131-1.29-.325-1.91-.427-1.38-1.282-2.555-2.394-3.449-1.102-.886-2.446-1.448-3.85-1.598-.18-.018-.36-.027-.54-.036a8.174 8.174 0 0 0-1.017.001c-.198.013-.396.033-.593.064-1.388.22-2.677.862-3.7 1.802-1.032.945-1.793 2.153-2.2 3.487-.186.605-.297 1.228-.348 1.858-.035.427-.043.857-.02 1.287a8.29 8.29 0 0 0-1.456.59C2.23 9.16 1.268 10.407 1 11.97c-.198 1.147.028 2.37.633 3.37.613 1.015 1.548 1.783 2.637 2.188l.027.01c-.095.368-.163.742-.196 1.118-.102 1.117.054 2.251.497 3.263.444 1.013 1.171 1.897 2.115 2.487a5.315 5.315 0 0 0 2.926.865c.72 0 1.44-.149 2.115-.449.667-.296 1.276-.738 1.782-1.298.506.56 1.115 1.002 1.782 1.298a5.29 5.29 0 0 0 2.115.449 5.315 5.315 0 0 0 2.926-.865c.944-.59 1.671-1.474 2.115-2.487.443-1.012.599-2.146.497-3.263a8.36 8.36 0 0 0-.196-1.118l.027-.01c1.09-.405 2.024-1.173 2.637-2.188.605-1 .831-2.223.633-3.37z"/></svg>`,
  slack: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M5.042 15.165a2.528 2.528 0 0 1-2.52 2.523A2.528 2.528 0 0 1 0 15.165a2.527 2.527 0 0 1 2.522-2.52h2.52v2.52zM6.313 15.165a2.527 2.527 0 0 1 2.521-2.52 2.527 2.527 0 0 1 2.521 2.52v6.313A2.528 2.528 0 0 1 8.834 24a2.528 2.528 0 0 1-2.521-2.522v-6.313zM8.834 5.042a2.528 2.528 0 0 1-2.521-2.52A2.528 2.528 0 0 1 8.834 0a2.528 2.528 0 0 1 2.521 2.522v2.52H8.834zM8.834 6.313a2.528 2.528 0 0 1 2.521 2.521 2.528 2.528 0 0 1-2.521 2.521H2.522A2.528 2.528 0 0 1 0 8.834a2.528 2.528 0 0 1 2.522-2.521h6.312zM18.956 8.834a2.528 2.528 0 0 1 2.522-2.521A2.528 2.528 0 0 1 24 8.834a2.528 2.528 0 0 1-2.522 2.521h-2.522V8.834zM17.688 8.834a2.528 2.528 0 0 1-2.523 2.521 2.527 2.527 0 0 1-2.52-2.521V2.522A2.527 2.527 0 0 1 15.165 0a2.528 2.528 0 0 1 2.523 2.522v6.312zM15.165 18.956a2.528 2.528 0 0 1 2.523 2.522A2.528 2.528 0 0 1 15.165 24a2.527 2.527 0 0 1-2.52-2.522v-2.522h2.52zM15.165 17.688a2.527 2.527 0 0 1-2.52-2.523 2.526 2.526 0 0 1 2.52-2.52h6.313A2.527 2.527 0 0 1 24 15.165a2.528 2.528 0 0 1-2.522 2.523h-6.313z"/></svg>`,
  zed: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="20" rx="4"/><path d="M7 17V9l4 4 4-8"/></svg>`,
};

/* ---- Mesh gradient avatar ---- */
const MESH_PALETTES = [
  ['#10b981','#06b6d4','#6366f1'],
  ['#8b5cf6','#6366f1','#06b6d4'],
  ['#f59e0b','#10b981','#6366f1'],
  ['#ef4444','#f59e0b','#6366f1'],
  ['#06b6d4','#3b82f6','#8b5cf6'],
];

function meshGradientAvatar(text, sizeClass = 'avatar-sm') {
  const idx = Math.abs((text || 'U').charCodeAt(0)) % MESH_PALETTES.length;
  const [c1, c2, c3] = MESH_PALETTES[idx];
  const letter = (text || 'U').charAt(0).toUpperCase();
  const style = `background: conic-gradient(from 90deg at 40% 40%, ${c1} 0deg, ${c2} 120deg, ${c3} 240deg, ${c1} 360deg);`;
  return `<div class="avatar ${sizeClass}" style="${style}">${letter}</div>`;
}

function brandAvatar(slug, name, sizeClass = 'avatar-sm') {
  const key = (slug || name || '').toLowerCase().replace(/[^a-z]/g, '');
  const logoKeys = Object.keys(BRAND_LOGOS);
  const match = logoKeys.find(k => key.includes(k) || k.includes(key.slice(0, 4)));
  if (match) {
    const color = match === 'github' ? '#fff' : match === 'openai' ? '#fff' : '#fff';
    return `<div class="avatar ${sizeClass} avatar-brand" style="background:#161b22; color:${color}; padding:4px;">${BRAND_LOGOS[match]}</div>`;
  }
  return meshGradientAvatar(name, sizeClass);
}

/* ---- Language/tag color helpers ---- */
/**
 * Listing data is attacker-controlled (publishers write names, descriptions,
 * tags; tool names come from scanned code). Templates build HTML strings, so
 * every server record is escaped once, here, before any template sees it.
 */
function escapeHtmlText(v) {
  return String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function escapeServer(value) {
  if (typeof value === 'string') return escapeHtmlText(value);
  if (Array.isArray(value)) return value.map(escapeServer);
  if (value && typeof value === 'object') {
    if (value.__escaped) return value;
    const out = { __escaped: true };
    for (const [k, v] of Object.entries(value)) out[k] = escapeServer(v);
    return out;
  }
  return value;
}

function tagBadge(tag) {
  const t = (tag || '').toLowerCase();
  if (t.includes('typescript') || t === 'ts') return `<span class="badge tag-typescript">${tag}</span>`;
  if (t.includes('python') || t === 'py')     return `<span class="badge tag-python">${tag}</span>`;
  if (t.includes('go') && t.length <= 3)       return `<span class="badge tag-go">${tag}</span>`;
  if (t.includes('rust'))                       return `<span class="badge tag-rust">${tag}</span>`;
  if (t === 'local' || t === 'stdio')           return `<span class="badge tag-local">${tag}</span>`;
  if (t === 'remote' || t === 'sse' || t === 'http') return `<span class="badge tag-remote">${tag}</span>`;
  if (t === 'hybrid')                           return `<span class="badge tag-hybrid">${tag}</span>`;
  return `<span class="badge badge-default">${tag}</span>`;
}

function langBadge(lang) {
  const l = (lang || 'Hybrid').toLowerCase();
  if (l.includes('typescript')) return `<span class="badge tag-typescript">${lang}</span>`;
  if (l.includes('python'))     return `<span class="badge tag-python">${lang}</span>`;
  if (l.includes('go'))         return `<span class="badge tag-go">${lang}</span>`;
  if (l.includes('rust'))       return `<span class="badge tag-rust">${lang}</span>`;
  return `<span class="badge badge-cyan">${lang}</span>`;
}

/* ---- Category icon/color map ---- */
const CATEGORY_STYLES = {
  'developer-tools':  { icon: 'code',            bg: 'rgba(99,102,241,0.15)',  color: '#a5b4fc' },
  'devtools':         { icon: 'code',            bg: 'rgba(99,102,241,0.15)',  color: '#a5b4fc' },
  'code':             { icon: 'code',            bg: 'rgba(99,102,241,0.15)',  color: '#a5b4fc' },
  'database':         { icon: 'database',        bg: 'rgba(245,158,11,0.15)',  color: '#fcd34d' },
  'data':             { icon: 'database',        bg: 'rgba(245,158,11,0.15)',  color: '#fcd34d' },
  'cloud':            { icon: 'cloud',           bg: 'rgba(59,130,246,0.15)',  color: '#93c5fd' },
  'cloud-services':   { icon: 'cloud',           bg: 'rgba(59,130,246,0.15)',  color: '#93c5fd' },
  'communication':    { icon: 'message-circle',  bg: 'rgba(16,185,129,0.15)',  color: '#34d399' },
  'messaging':        { icon: 'message-square',  bg: 'rgba(16,185,129,0.15)',  color: '#34d399' },
  'ai':               { icon: 'sparkles',        bg: 'rgba(139,92,246,0.15)', color: '#c4b5fd' },
  'ai-tools':         { icon: 'sparkles',        bg: 'rgba(139,92,246,0.15)', color: '#c4b5fd' },
  'automation':       { icon: 'zap',             bg: 'rgba(249,115,22,0.15)',  color: '#fdba74' },
  'productivity':     { icon: 'zap',             bg: 'rgba(249,115,22,0.15)',  color: '#fdba74' },
  'security':         { icon: 'shield',          bg: 'rgba(239,68,68,0.15)',   color: '#fca5a5' },
  'search':           { icon: 'search',          bg: 'rgba(6,182,212,0.15)',   color: '#67e8f9' },
  'browser':          { icon: 'globe',           bg: 'rgba(59,130,246,0.15)',  color: '#93c5fd' },
  'web':              { icon: 'globe',           bg: 'rgba(59,130,246,0.15)',  color: '#93c5fd' },
  'system':           { icon: 'cpu',             bg: 'rgba(99,102,241,0.15)',  color: '#a5b4fc' },
  'file':             { icon: 'file-text',       bg: 'rgba(245,158,11,0.15)',  color: '#fcd34d' },
  'filesystem':       { icon: 'file-text',       bg: 'rgba(245,158,11,0.15)',  color: '#fcd34d' },
  'monitoring':       { icon: 'activity',        bg: 'rgba(16,185,129,0.15)',  color: '#34d399' },
  'default':          { icon: 'puzzle',          bg: 'rgba(99,102,241,0.15)',  color: '#a5b4fc' },
};

function getCategoryStyle(category) {
  const slug     = (category.slug || '').toLowerCase().replace(/\s+/g, '-');
  const iconName = (category.icon || '').toLowerCase();

  // 1. Icon field is a direct key in CATEGORY_STYLES
  if (iconName && CATEGORY_STYLES[iconName]) return CATEGORY_STYLES[iconName];

  // 2. Icon field is a valid Lucide icon name — build a generic style around it
  if (iconName && ICONS[iconName]) {
    const fallbackColors = [
      { bg: 'rgba(16,185,129,0.15)',  color: '#34d399' },
      { bg: 'rgba(99,102,241,0.15)', color: '#a5b4fc' },
      { bg: 'rgba(6,182,212,0.15)',   color: '#67e8f9' },
      { bg: 'rgba(245,158,11,0.15)',  color: '#fcd34d' },
      { bg: 'rgba(139,92,246,0.15)', color: '#c4b5fd' },
    ];
    const fb = fallbackColors[Math.abs(iconName.charCodeAt(0)) % fallbackColors.length];
    return { icon: iconName, ...fb };
  }

  // 3. Exact slug match in CATEGORY_STYLES
  if (CATEGORY_STYLES[slug]) return CATEGORY_STYLES[slug];

  // 4. Partial slug match
  for (const key of Object.keys(CATEGORY_STYLES)) {
    if (key === 'default') continue;
    if (slug.includes(key) || key.includes(slug.slice(0, 5))) return CATEGORY_STYLES[key];
  }

  return CATEGORY_STYLES.default;
}

/* ================================================================
   COMPONENT FACTORY
   ================================================================ */
const Components = {

  /* ---- Navbar ---- */
  createNavbar(currentUser) {
    const path = window.location.pathname;
    const isActive = (href) => path.includes(href.replace('.html','').replace('/','')) ? 'active' : '';

    const authArea = currentUser
      ? `<a href="/profile.html" class="nav-user-pill">
           ${meshGradientAvatar(currentUser.username || currentUser.displayName, 'avatar-sm')}
           <span>${currentUser.displayName || currentUser.username || 'My Profile'}</span>
         </a>
         <button onclick="App.logout()" class="btn btn-ghost btn-sm">${icon('log-out',15)} Logout</button>`
      : `<a href="/login.html" class="btn btn-ghost btn-sm">Log In</a>
         <a href="/register.html" class="btn btn-primary btn-sm">Sign Up</a>`;

    return `
      <nav class="nav">
        <div class="container nav-container">
          <a href="/index.html" class="nav-logo">
            <div class="logo-icon">${icon('server', 18)}</div>
            MCP<span style="color:var(--accent)">Market</span>
          </a>

          <div class="nav-links">
            <a href="/servers.html"    class="nav-link ${isActive('servers')}">Servers</a>
            <a href="/categories.html" class="nav-link ${isActive('categories')}">Categories</a>
            <a href="/clients.html"    class="nav-link ${isActive('clients')}">Clients</a>
            <a href="/publish.html"    class="nav-link ${isActive('publish')}">Publish</a>

            <div style="width:1px;height:16px;background:var(--border);margin:0 0.25rem;flex-shrink:0;"></div>
            <a href="/verify.html"  class="nav-link nav-mcs-highlight ${isActive('verify')}">Verify MCP</a>
            <a href="/admin.html"   class="nav-link nav-mcs-highlight ${isActive('admin')}">Admin</a>

            <div class="nav-search-wrap">
              <span class="search-icon">${icon('search', 15)}</span>
              <input type="text" id="nav-search" class="nav-search-input" placeholder="Search…" autocomplete="off">
              <span class="nav-search-kbd">⌘K</span>
            </div>

            <button id="theme-toggle-btn" class="theme-toggle-btn" onclick="App.toggleTheme()" title="Toggle Dark / Light Mode" aria-label="Toggle theme">
              <span id="theme-toggle-icon"></span>
            </button>

            <div class="flex gap-2 items-center" style="margin-left:0.25rem;">
              ${authArea}
            </div>
          </div>
        </div>
      </nav>
    `;
  },

  /* ---- Server Card ---- */
  createServerCard(server) {
    server = escapeServer(server);
    const author = server.author_display_name || server.author_username || server.author || 'Publisher';
    const name   = server.name || 'Unnamed Server';
    const slug   = server.slug || name.toLowerCase().replace(/\s+/g,'-');
    const tags   = (server.tags || []).slice(0,4).map(t => typeof t === 'object' ? (t.name || t.slug) : t);
    const stars  = (server.stars || 0).toLocaleString();
    const installs = (server.install_count || server.installs || 0).toLocaleString();
    const lang   = server.language || 'TypeScript';

    const avatarEl = brandAvatar(slug, name, 'avatar-sm');

    return `
      <a href="/server-detail.html?slug=${slug}" class="card hoverable server-card">
        <div>
          <div class="server-card-header">
            <div class="server-card-identity">
              ${avatarEl}
              <div class="server-card-names">
                <h3 class="server-title">${name}</h3>
                <div class="server-author">
                  ${author}
                  <span class="verified-badge" title="Verified Publisher">
                    ${icon('check-circle', 13)}
                  </span>
                </div>
              </div>
            </div>
            <span class="badge badge-success" style="flex-shrink:0;">
              ${icon('check',10)} Verified
            </span>
          </div>

          <p class="server-desc">${server.description || 'No description provided.'}</p>

          <div class="server-tags">
            ${tags.map(t => tagBadge(t)).join('')}
            ${langBadge(lang)}
          </div>

          <div class="server-clients">
            <span class="client-chip">${icon('check',10)} Claude</span>
            <span class="client-chip">${icon('check',10)} Cursor</span>
            <span class="client-chip">${icon('check',10)} VS Code</span>
          </div>
        </div>

        <div class="server-meta">
          <div class="server-meta-stats">
            <span class="server-stat stars">${icon('star',13)} ${stars}</span>
            <span class="server-stat downloads">${icon('download',13)} ${installs}</span>
          </div>
          <span class="text-muted" style="font-size:0.75rem;">${server.hosting || 'Local'}</span>
        </div>
      </a>
    `;
  },

  /* ---- Category Card ---- */
  createCategoryCard(category) {
    const style = getCategoryStyle(category);
    const count = category.server_count || category.count || 0;
    return `
      <a href="/servers.html?category=${category.slug}" class="card hoverable category-card">
        <div class="category-icon-wrap" style="background:${style.bg}; color:${style.color};">
          ${icon(style.icon, 28)}
        </div>
        <div>
          <div class="category-name">${category.name}</div>
          <div class="category-count">${count} server${count !== 1 ? 's' : ''}</div>
        </div>
      </a>
    `;
  },

  /* ---- Client Card ---- */
  createClientCard(client) {
    const name = client.name || 'MCP Client';
    const features = client.features || (client.transport ? [client.transport] : ['stdio', 'HTTP']);
    const serverCount = client.server_count || client.servers_supported || '500+';
    const logo = brandAvatar(name, name, 'avatar-lg');

    return `
      <div class="card hoverable client-card">
        <div class="client-header">
          ${logo}
          <div class="client-info">
            <h3>${name}</h3>
            <span class="badge ${client.type === 'editor' ? 'badge-indigo' : 'badge-cyan'}">${client.type || 'AI Client'}</span>
          </div>
        </div>
        <p class="client-desc">${client.description || 'An MCP-compatible client.'}</p>
        <div class="client-features">
          ${features.map(f => `<span class="badge badge-default">${f}</span>`).join('')}
          <span class="badge badge-success">${icon('server',11)} ${serverCount} servers</span>
        </div>
        <div class="client-actions" style="margin-top:1.25rem;">
          <a href="${client.website || '#'}" target="_blank" class="btn btn-outline" style="width:100%;">
            Visit Website ${icon('external-link', 14)}
          </a>
        </div>
      </div>
    `;
  },

  /* ---- Stat Card ---- */
  createStatCard(label, value, iconName = 'server') {
    const statIcons = {
      'Total Servers': 'server',
      'Publishers':    'users',
      'Total Installs':'download',
      'Client Integrations': 'puzzle',
    };
    const ic = statIcons[label] || iconName;
    return `
      <div class="stat-card animate-fadeInUp">
        <div class="stat-icon">${icon(ic, 18)}</div>
        <div class="stat-value">${value}</div>
        <div class="stat-label">${label}</div>
      </div>
    `;
  },

  /* ---- Filter Sidebar ---- */
  createFilterSidebar(categories = [], activeFilters = {}) {
    return `
      <div class="filter-sidebar">
        <div class="filter-group">
          <p class="filter-title">Language</p>
          ${['TypeScript', 'Python', 'Go', 'Rust'].map(lang => `
            <label class="filter-label">
              <input type="checkbox" name="language" value="${lang.toLowerCase()}"
                ${activeFilters.language?.includes(lang.toLowerCase()) ? 'checked' : ''}>
              ${lang}
            </label>
          `).join('')}
        </div>
        <div class="filter-group">
          <p class="filter-title">Hosting</p>
          ${['Local', 'Remote', 'Hybrid'].map(h => `
            <label class="filter-label">
              <input type="checkbox" name="hosting" value="${h.toLowerCase()}"
                ${activeFilters.hosting?.includes(h.toLowerCase()) ? 'checked' : ''}>
              ${h}
            </label>
          `).join('')}
        </div>
        ${categories.length ? `
        <div class="filter-group">
          <p class="filter-title">Categories</p>
          ${categories.map(cat => `
            <label class="filter-label">
              <input type="checkbox" name="category" value="${cat.slug}"
                ${activeFilters.category?.includes(cat.slug) ? 'checked' : ''}>
              ${cat.name}
            </label>
          `).join('')}
        </div>` : ''}
      </div>
    `;
  },

  /* ---- Pagination ---- */
  createPagination(currentPage, totalPages) {
    if (totalPages <= 1) return '';
    let btns = `<button class="page-btn" ${currentPage===1?'disabled':''} onclick="App.changePage(${currentPage-1})">←</button>`;
    for (let i = 1; i <= totalPages; i++) {
      btns += `<button class="page-btn ${i === currentPage ? 'active' : ''}" onclick="App.changePage(${i})">${i}</button>`;
    }
    btns += `<button class="page-btn" ${currentPage===totalPages?'disabled':''} onclick="App.changePage(${currentPage+1})">→</button>`;
    return `<div class="pagination">${btns}</div>`;
  },

  /* ---- Empty State ---- */
  createEmptyState(title = 'Nothing here yet', desc = 'No results match your criteria.', cta = null) {
    return `
      <div class="empty-state">
        <div class="empty-state-icon">${icon('inbox', 28)}</div>
        <h3>${title}</h3>
        <p>${desc}</p>
        ${cta ? `<a href="${cta.href}" class="btn btn-primary">${icon('plus',15)} ${cta.label}</a>` : ''}
      </div>
    `;
  },

  /* ---- Skeleton ---- */
  createSkeletonCard(height = 220) {
    return `<div class="skeleton" style="height:${height}px;"></div>`;
  },

  /* ---- FAQ Item ---- */
  createFaqItem(question, answer) {
    return `
      <div class="faq-item" onclick="this.classList.toggle('active')">
        <div class="faq-question">
          <span>${question}</span>
          <span class="faq-icon">${icon('chevronDown', 18)}</span>
        </div>
        <div class="faq-answer">${answer}</div>
      </div>
    `;
  },

  /* ---- Install Config Block ---- */
  createInstallConfig(server) {
    server = escapeServer(server);
    const slug    = server.slug || 'server';
    const lang    = (server.language || '').toLowerCase();
    const isPy    = lang.includes('python');
    const npmPkg  = server.npm_package || (isPy ? `mcp-server-${slug}` : `@modelcontextprotocol/server-${slug}`);
    const runCmd  = isPy ? `uvx ${npmPkg}` : `npx -y ${npmPkg}`;

    if (server.transport === 'Streamable HTTP') {
      const httpCmd = server.npm_package || `claude mcp add ${slug} --transport http ${server.github_url || `https://example.com/mcp/${slug}`}`;
      return `
        <div class="install-block">
          <div class="install-block-header">
            <span class="install-block-label">Terminal — Streamable HTTP</span>
            <button class="btn btn-sm btn-outline install-copy-btn" onclick="Components._copyInstall('install-http-${slug}')">
              ${icon('copy',13)} Copy
            </button>
          </div>
          <div class="install-block-body">
            <pre id="install-http-${slug}"><code><span class="tok-keyword">claude</span> mcp add ${slug} --transport http ${server.github_url || 'https://…'}</code></pre>
          </div>
        </div>
      `;
    }

    const claudeConfig = JSON.stringify({
      mcpServers: {
        [slug]: {
          command: isPy ? 'uvx' : 'npx',
          args: [npmPkg],
          ...(server.env_vars ? { env: server.env_vars } : {})
        }
      }
    }, null, 2);

    const cursorConfig = JSON.stringify({
      [slug]: {
        command: isPy ? 'uvx' : 'npx',
        args: [npmPkg]
      }
    }, null, 2);

    const blockId = `install-${slug}`;
    return `
      <div class="doc-box" style="padding:0; overflow:hidden;">
        <div style="padding:1.25rem 1.5rem 0.75rem; border-bottom:1px solid var(--border);">
          <h3 style="border:none; padding:0; margin:0; font-size:1rem;">Install & Configure</h3>
          <p style="margin:0.5rem 0 0; font-size:0.875rem;">Choose your client and copy the configuration.</p>
        </div>
        <div style="padding:1.25rem 1.5rem;">
          <div class="install-block">
            <div class="install-block-header">
              <div class="install-block-tabs">
                <button class="install-tab active" onclick="Components._switchTab('${blockId}','npx',this)">npx</button>
                <button class="install-tab" onclick="Components._switchTab('${blockId}','claude',this)">Claude Desktop</button>
                <button class="install-tab" onclick="Components._switchTab('${blockId}','cursor',this)">Cursor</button>
              </div>
              <button class="btn btn-sm btn-outline install-copy-btn" onclick="Components._copyInstall('${blockId}-active')">
                ${icon('copy',13)} Copy
              </button>
            </div>
            <div class="install-block-body">
              <pre id="${blockId}-npx" data-panel="${blockId}" class="install-panel" style="display:block;"><code><span class="tok-keyword">${isPy?'uvx':'npx -y'}</span> <span class="tok-string">${npmPkg}</span></code></pre>
              <pre id="${blockId}-claude" data-panel="${blockId}" class="install-panel" style="display:none;"><code>${Components._colorizeJson(claudeConfig)}</code></pre>
              <pre id="${blockId}-cursor" data-panel="${blockId}" class="install-panel" style="display:none;"><code>${Components._colorizeJson(cursorConfig)}</code></pre>
              <pre id="${blockId}-active" style="display:none;">${runCmd}</pre>
            </div>
          </div>
          <div class="callout-box" style="margin-top:1rem; font-size:0.85rem;">
            <strong>NPM Package:</strong> <code>${npmPkg}</code><br>
            <strong>Environment:</strong> Set required environment variables before running (see <a href="${server.github_url||'#'}" style="color:var(--accent)">README</a>).
          </div>
        </div>
      </div>
    `;
  },

  _switchTab(blockId, tab, btn) {
    // Hide all panels for this block
    document.querySelectorAll(`[data-panel="${blockId}"]`).forEach(p => p.style.display = 'none');
    // Show selected
    const target = document.getElementById(`${blockId}-${tab}`);
    if (target) {
      target.style.display = 'block';
      // Update active text for copy
      const activeEl = document.getElementById(`${blockId}-active`);
      if (activeEl) activeEl.textContent = target.textContent;
    }
    // Update tab buttons
    if (btn) {
      btn.closest('.install-block-tabs').querySelectorAll('.install-tab').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
    }
  },

  _copyInstall(id) {
    const el = document.getElementById(id);
    if (!el) return;
    navigator.clipboard.writeText(el.textContent.trim()).then(() => {
      App.showToast('Copied to clipboard!', 'success');
    });
  },

  _colorizeJson(jsonStr) {
    // Schemas come from scanned repositories: escape before adding markup.
    return jsonStr.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/("[\w\s\-@\/]+")\s*:/g, '<span class="tok-key">$1</span>:')
      .replace(/:\s*(".*?")/g, ': <span class="tok-string">$1</span>')
      .replace(/:\s*(\d+\.?\d*)/g, ': <span class="tok-number">$1</span>');
  },

  /* ---- Tool Card ---- */
  createToolCard(tool) {
    let schemaObj = {};
    try {
      schemaObj = typeof tool.input_schema === 'string'
        ? JSON.parse(tool.input_schema)
        : (tool.input_schema || tool.inputSchema || {});
    } catch (e) {
      schemaObj = { error: 'Invalid schema', raw: String(tool.input_schema || '') };
    }

    const esc = v => String(v == null ? '' : v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

    return `
      <div class="tool-card-box">
        <div class="tool-header">
          <div style="display:flex;align-items:center;gap:0.75rem;">
            <span class="tool-name">${icon('wrench',16)} ${esc(tool.name)}</span>
          </div>
        </div>
        <div class="tool-desc">${esc(tool.description || 'No description provided.')}</div>
        <p class="filter-title" style="margin-bottom:0.5rem;">Input Schema (JSON)</p>
        <pre class="tool-schema"><code>${this._colorizeJson(JSON.stringify(schemaObj, null, 2))}</code></pre>
      </div>
    `;
  },

  /* ---- Footer ---- */
  createFooter() {
    return `
      <footer class="footer">
        <div class="container">
          <div class="footer-grid">
            <div class="footer-brand">
              <a href="/index.html" class="nav-logo" style="font-size:1.125rem;">
                <div class="logo-icon" style="width:28px;height:28px;border-radius:7px;">${icon('server',15)}</div>
                MCP<span style="color:var(--accent)">Market</span>
              </a>
              <p>The premier registry and discovery platform for Model Context Protocol servers, tools, and AI clients.</p>
            </div>
            <div>
              <h4>Resources</h4>
              <ul>
                <li><a href="/servers.html">Browse Servers</a></li>
                <li><a href="/clients.html">MCP Clients</a></li>
                <li><a href="/categories.html">Categories</a></li>
              </ul>
            </div>
            <div>
              <h4>Developers</h4>
              <ul>
                <li><a href="/publish.html">Publish a Server</a></li>
                <li><a href="#">Documentation</a></li>
                <li><a href="#">API Reference</a></li>
              </ul>
            </div>
            <div>
              <h4>Company</h4>
              <ul>
                <li><a href="#">Privacy Policy</a></li>
                <li><a href="#">Terms of Service</a></li>
                <li><a href="#">Code of Conduct</a></li>
              </ul>
            </div>
          </div>
          <div class="footer-bottom">
            <span>© ${new Date().getFullYear()} MCP Marketplace. Built for the AI community.</span>
            <span>Open Standard · MIT License</span>
          </div>
        </div>
      </footer>
    `;
  },
};

window.Components = Components;

// Expose helpers globally so app.js can call them directly
window.brandAvatar      = brandAvatar;
window.meshGradientAvatar = meshGradientAvatar;
window.tagBadge         = tagBadge;
window.langBadge        = langBadge;
window.icon             = icon;
