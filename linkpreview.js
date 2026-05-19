// =============================================================================
// DownloadGuard - linkpreview.js
// Shows real destination URL on link hover + flags suspicious domains
// Runs on Gmail, Outlook, and all web pages
// =============================================================================

// ---------------------------------------------------------------------------
// SUSPICIOUS DOMAIN CHECKS (lightweight version for inline use)
// ---------------------------------------------------------------------------
const PREVIEW_BRANDS = [
  { name:'Google',    official:['google.com','gmail.com','youtube.com','googleapis.com'] },
  { name:'Microsoft', official:['microsoft.com','outlook.com','live.com','office.com','office365.com','microsoftonline.com'] },
  { name:'Apple',     official:['apple.com','icloud.com'] },
  { name:'PayPal',    official:['paypal.com','paypal.co.uk'] },
  { name:'Amazon',    official:['amazon.com','amazon.co.uk','amazonaws.com'] },
  { name:'Netflix',   official:['netflix.com'] },
  { name:'Facebook',  official:['facebook.com','fb.com','meta.com','instagram.com'] },
  { name:'HMRC',      official:['hmrc.gov.uk','gov.uk'] },
  { name:'IRS',       official:['irs.gov'] },
  { name:'Barclays',  official:['barclays.com','barclays.co.uk'] },
  { name:'HSBC',      official:['hsbc.com','hsbc.co.uk'] },
  { name:'NatWest',   official:['natwest.com'] },
  { name:'Lloyds',    official:['lloydsbank.com'] },
  { name:'DHL',       official:['dhl.com','dhl.co.uk'] },
  { name:'FedEx',     official:['fedex.com'] },
  { name:'UPS',       official:['ups.com'] },
  { name:'Royal Mail',official:['royalmail.com'] },
];

function lev(a, b) {
  const m = a.length, n = b.length;
  const d = Array.from({length:m+1},(_,i)=>Array.from({length:n+1},(_,j)=>i===0?j:j===0?i:0));
  for(let i=1;i<=m;i++) for(let j=1;j<=n;j++)
    d[i][j]=a[i-1]===b[j-1]?d[i-1][j-1]:1+Math.min(d[i-1][j],d[i][j-1],d[i-1][j-1]);
  return d[m][n];
}

function normDomain(s) {
  return s.toLowerCase().replace(/rn/g,'m').replace(/cl/g,'d')
           .replace(/[@413057$96]/g,c=>({'@':'a',4:'a',3:'e',1:'i',0:'o',5:'s',7:'t',9:'g',6:'b'}[c]||c));
}

function assessUrl(href) {
  if (!href || href.startsWith('mailto:') || href.startsWith('#') || href.startsWith('javascript:')) {
    return { safe: true, reason: null, domain: null };
  }

  let domain, fullDomain;
  try {
    const u = new URL(href);
    fullDomain = u.hostname.toLowerCase();
    domain     = fullDomain.replace(/^www\./, '');
  } catch(e) {
    return { safe: false, reason: 'Invalid or obfuscated URL', domain: href };
  }

  const normBase = normDomain(domain.split('.')[0]);

  for (const brand of PREVIEW_BRANDS) {
    const isOfficial = brand.official.some(d => domain === d || domain.endsWith('.' + d));
    if (isOfficial) continue;

    for (const off of brand.official) {
      const offBase = off.split('.')[0];
      const dist    = lev(normBase, offBase);

      // Edit distance spoof
      if (dist > 0 && dist <= 2 && normBase.length >= 4) {
        return {
          safe: false,
          level: 'CRITICAL',
          reason: `Domain "${fullDomain}" appears to spoof ${brand.name} (official: ${off})`,
          domain: fullDomain
        };
      }

      // Homoglyph match
      if (normBase === offBase && domain.split('.')[0] !== offBase) {
        return {
          safe: false,
          level: 'CRITICAL',
          reason: `Domain uses look-alike characters to impersonate ${brand.name}`,
          domain: fullDomain
        };
      }

      // Brand name in non-official domain
      if ((domain.includes(offBase) || domain.includes(brand.name.toLowerCase().replace(/\s/g,'')))
          && !isOfficial) {
        return {
          safe: false,
          level: 'HIGH',
          reason: `Contains "${brand.name}" brand name but is NOT an official ${brand.name} domain`,
          domain: fullDomain
        };
      }
    }
  }

  // URL shorteners
  const shorteners = ['bit.ly','tinyurl.com','ow.ly','short.link','is.gd','t.co','buff.ly','rebrand.ly','tiny.cc'];
  if (shorteners.some(s => domain === s)) {
    return {
      safe: false,
      level: 'MEDIUM',
      reason: 'URL shortener hides the real destination',
      domain: fullDomain
    };
  }

  // Suspicious patterns
  if (/[-_](secure|login|verify|account|update|confirm|bank|wallet)/.test(domain)) {
    return {
      safe: false,
      level: 'MEDIUM',
      reason: `Domain contains suspicious keyword pattern`,
      domain: fullDomain
    };
  }

  return { safe: true, reason: null, domain: fullDomain };
}

// ---------------------------------------------------------------------------
// TOOLTIP
// ---------------------------------------------------------------------------
let tooltip = null;
let hideTimer = null;

function createTooltip() {
  if (document.getElementById('dg-link-tooltip')) return;
  const el = document.createElement('div');
  el.id = 'dg-link-tooltip';
  Object.assign(el.style, {
    position:      'fixed',
    zIndex:        '2147483647',
    maxWidth:      '480px',
    pointerEvents: 'none',
    display:       'none',
    fontFamily:    'monospace',
    fontSize:      '12px',
    lineHeight:    '1.5',
    borderRadius:  '8px',
    padding:       '10px 14px',
    boxShadow:     '0 4px 20px rgba(0,0,0,0.3)',
    transition:    'opacity 0.15s',
    wordBreak:     'break-all',
  });
  document.body.appendChild(el);
  tooltip = el;
}

function showTooltip(link, mouseX, mouseY) {
  if (!tooltip) createTooltip();
  clearTimeout(hideTimer);

  const href        = link.href || '';
  const displayText = link.textContent?.trim() || '';
  const assessment  = assessUrl(href);

  // Colors based on risk
  const colors = {
    CRITICAL: { bg:'#1a0000', border:'#ff4444', text:'#ffaaaa', label:'#ff4444' },
    HIGH:     { bg:'#1a0f00', border:'#f97316', text:'#ffd0aa', label:'#f97316' },
    MEDIUM:   { bg:'#1a1a00', border:'#eab308', text:'#ffeaaa', label:'#eab308' },
    SAFE:     { bg:'#001a0a', border:'#22c55e', text:'#aaffcc', label:'#22c55e' }
  };

  const level  = assessment.safe ? 'SAFE' : (assessment.level || 'MEDIUM');
  const c      = colors[level];
  const icon   = { CRITICAL:'🚨', HIGH:'⚠️', MEDIUM:'🔶', SAFE:'✅' }[level];
  const isMismatch = displayText && displayText.length > 4 &&
                     displayText.startsWith('http') &&
                     !href.includes(displayText.replace(/^https?:\/\//, '').split('/')[0]);

  tooltip.style.cssText += `
    background: ${c.bg};
    border: 1px solid ${c.border};
    color: ${c.text};
    display: block;
  `;

  let html = `<div style="display:flex;align-items:center;gap:6px;margin-bottom:6px">
    <span>${icon}</span>
    <span style="font-weight:700;color:${c.label}">DownloadGuard · ${level}</span>
  </div>`;

  html += `<div style="color:#aaa;font-size:10px;margin-bottom:2px">REAL URL</div>`;
  html += `<div style="color:${c.text};margin-bottom:6px">${href || '(no href)'}</div>`;

  if (displayText && displayText !== href && displayText.length < 80) {
    html += `<div style="color:#aaa;font-size:10px;margin-bottom:2px">DISPLAY TEXT</div>`;
    html += `<div style="color:#ccc;margin-bottom:6px">${displayText}</div>`;
  }

  if (isMismatch) {
    html += `<div style="color:#f97316;font-size:11px">⚠️ Display text doesn't match destination URL</div>`;
  }

  if (!assessment.safe && assessment.reason) {
    html += `<div style="color:${c.label};font-size:11px;margin-top:4px;border-top:1px solid ${c.border};padding-top:6px">🛡️ ${assessment.reason}</div>`;
  }

  tooltip.innerHTML = html;

  // Position tooltip near mouse but keep on screen
  const tw = 480, th = 120;
  let left = mouseX + 12;
  let top  = mouseY + 16;
  if (left + tw > window.innerWidth - 10)  left = mouseX - tw - 12;
  if (top  + th > window.innerHeight - 10) top  = mouseY - th - 12;

  tooltip.style.left = `${Math.max(8, left)}px`;
  tooltip.style.top  = `${Math.max(8, top)}px`;
}

function hideTooltip() {
  hideTimer = setTimeout(() => {
    if (tooltip) tooltip.style.display = 'none';
  }, 200);
}

// ---------------------------------------------------------------------------
// EVENT LISTENERS
// ---------------------------------------------------------------------------
document.addEventListener('mouseover', (e) => {
  const link = e.target.closest('a[href]');
  if (!link) { hideTooltip(); return; }

  const href = link.href || '';
  if (!href || href.startsWith('mailto:') || href === '#') { hideTooltip(); return; }

  showTooltip(link, e.clientX, e.clientY);
}, { passive: true });

document.addEventListener('mousemove', (e) => {
  if (tooltip && tooltip.style.display !== 'none') {
    const tw = 480, th = tooltip.offsetHeight || 120;
    let left = e.clientX + 12;
    let top  = e.clientY + 16;
    if (left + tw > window.innerWidth - 10)  left = e.clientX - tw - 12;
    if (top  + th > window.innerHeight - 10) top  = e.clientY - th - 12;
    tooltip.style.left = `${Math.max(8, left)}px`;
    tooltip.style.top  = `${Math.max(8, top)}px`;
  }
}, { passive: true });

document.addEventListener('mouseout', (e) => {
  if (!e.target.closest('a[href]')) hideTooltip();
}, { passive: true });

document.addEventListener('click', () => hideTooltip(), { passive: true });

console.log('[DownloadGuard] Link preview active');
