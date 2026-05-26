// =============================================================================
// DownloadGuard - linkpreview.js v2.0
// - Link hover tooltip with real URL reveal
// - Fake download button detection for pirate/ad-heavy sites
// - Tooltip persists until user moves away (no more disappearing instantly)
// =============================================================================

// ---------------------------------------------------------------------------
// BRAND SPOOF CHECK (lightweight, inline)
// ---------------------------------------------------------------------------
const PREVIEW_BRANDS = [
  { name:'Google',     official:['google.com','gmail.com','youtube.com','googleapis.com'] },
  { name:'Microsoft',  official:['microsoft.com','outlook.com','live.com','office.com','office365.com','microsoftonline.com'] },
  { name:'Apple',      official:['apple.com','icloud.com'] },
  { name:'PayPal',     official:['paypal.com','paypal.co.uk'] },
  { name:'Amazon',     official:['amazon.com','amazon.co.uk','amazonaws.com'] },
  { name:'Netflix',    official:['netflix.com'] },
  { name:'Facebook',   official:['facebook.com','fb.com','meta.com','instagram.com'] },
  { name:'HMRC',       official:['hmrc.gov.uk','gov.uk'] },
  { name:'IRS',        official:['irs.gov'] },
  { name:'Barclays',   official:['barclays.com','barclays.co.uk'] },
  { name:'HSBC',       official:['hsbc.com','hsbc.co.uk'] },
  { name:'NatWest',    official:['natwest.com'] },
  { name:'Lloyds',     official:['lloydsbank.com'] },
  { name:'DHL',        official:['dhl.com','dhl.co.uk'] },
  { name:'FedEx',      official:['fedex.com'] },
  { name:'UPS',        official:['ups.com'] },
  { name:'Royal Mail', official:['royalmail.com'] },
];

// Known ad/redirect networks used as fake download buttons on pirate sites
const AD_NETWORKS = [
  'adf.ly','linkvertise.com','lnkfly.com','ouo.io','exe.io','bc.vc',
  'shrink.pe','gplinks.in','popads.net','adsterra.com','hilltopads.net',
  'trafficjunky.com','juicyads.com','exoclick.com','traffichunt.com',
  'ero-advertising.com','adnium.com','propellerads.com','clickadu.com',
  'popcash.net','adcash.com','bidvertiser.com','yllix.com','admaven.com',
  'cutwin.com','exe.app','fc.lc','za.gl','short.pe','inshorturl.com',
  'shorte.st','adfoc.us','adfly.xyz','clik.pw','linkbucks.com',
  'shortnesia.com','link1s.com','1ink.cc','atominik.com','vipurl.in'
];

// URL shorteners that hide true destinations
const SHORTENERS = [
  'bit.ly','tinyurl.com','ow.ly','short.link','is.gd','t.co',
  'buff.ly','rebrand.ly','tiny.cc','cutt.ly','rb.gy','shorturl.at'
];

// Words in image src/alt/class that signal a fake download button
const FAKE_DL_IMAGE_SIGNALS = [
  'download','descargar','télécharger','downloaden','herunterladen',
  'btn','button','click','free','gratis','get-it','getit','dl-','-dl',
  'arrow','install','setup','start'
];

// Words in link text / surrounding text that signal fake download context
const FAKE_DL_TEXT_SIGNALS = [
  'download','free download','click here','get file','direct link',
  'start download','download now','get it free','install now'
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

// ---------------------------------------------------------------------------
// URL RISK ASSESSMENT
// ---------------------------------------------------------------------------
function assessUrl(href) {
  if (!href || href.startsWith('mailto:') || href.startsWith('#') || href.startsWith('javascript:')) {
    return { safe: true, reason: null, domain: null };
  }

  let domain, fullDomain;
  try {
    const u   = new URL(href);
    fullDomain = u.hostname.toLowerCase();
    domain     = fullDomain.replace(/^www\./, '');
  } catch(e) {
    return { safe: false, level: 'HIGH', reason: 'Invalid or obfuscated URL', domain: href };
  }

  const normBase = normDomain(domain.split('.')[0]);

  // Known ad networks
  if (AD_NETWORKS.some(n => domain === n || domain.endsWith('.' + n))) {
    return { safe: false, level: 'HIGH', reason: `Known ad/redirect network — not a real download link`, domain: fullDomain };
  }

  // URL shorteners
  if (SHORTENERS.some(s => domain === s || domain.endsWith('.' + s))) {
    return { safe: false, level: 'MEDIUM', reason: 'URL shortener hides the real destination', domain: fullDomain };
  }

  // Brand spoofing
  for (const brand of PREVIEW_BRANDS) {
    const isOfficial = brand.official.some(d => domain === d || domain.endsWith('.' + d));
    if (isOfficial) continue;
    for (const off of brand.official) {
      const offBase = off.split('.')[0];
      // Skip bases shorter than 4 chars — prevents "ing" matching "kingston",
      // "ups" matching "cups", "sky" matching "disney" etc.
      if (offBase.length < 4) continue;
      const dist    = lev(normBase, offBase);
      if (dist > 0 && dist <= 2 && normBase.length >= 4) {
        return { safe: false, level: 'CRITICAL', reason: `Domain "${fullDomain}" appears to spoof ${brand.name} (official: ${off})`, domain: fullDomain };
      }
      if (normBase === offBase && domain.split('.')[0] !== offBase) {
        return { safe: false, level: 'CRITICAL', reason: `Domain uses look-alike characters to impersonate ${brand.name}`, domain: fullDomain };
      }
      // Only match brand name in domain if the brand name itself is 4+ chars
      const brandKeyword = brand.name.toLowerCase().replace(/\s/g,'');
      if (brandKeyword.length >= 4 && (domain.includes(offBase) || domain.includes(brandKeyword)) && !isOfficial) {
        return { safe: false, level: 'HIGH', reason: `Contains "${brand.name}" brand name but is NOT an official ${brand.name} domain`, domain: fullDomain };
      }
    }
  }

  // Suspicious patterns
  if (/[-_](secure|login|verify|account|update|confirm|bank|wallet)/.test(domain)) {
    return { safe: false, level: 'MEDIUM', reason: 'Domain contains suspicious keyword pattern', domain: fullDomain };
  }

  return { safe: true, reason: null, domain: fullDomain };
}

// ---------------------------------------------------------------------------
// FAKE DOWNLOAD BUTTON DETECTION
// Checks whether a link is visually presented as a download button
// but actually routes through ads or suspicious domains
// ---------------------------------------------------------------------------
function detectFakeDownloadButton(link) {
  const href    = link.href || '';
  const linkText = link.textContent?.toLowerCase().trim() || '';
  const linkClass = (link.className || '').toLowerCase();
  const linkId    = (link.id || '').toLowerCase();

  // Gather all images inside this link
  const images    = [...link.querySelectorAll('img')];
  const hasImage  = images.length > 0;

  // Check image signals
  let imageScore  = 0;
  let imageReason = '';
  for (const img of images) {
    const alt   = (img.alt   || '').toLowerCase();
    const src   = (img.src   || '').toLowerCase();
    const cls   = (img.className || '').toLowerCase();
    const title = (img.title || '').toLowerCase();
    const combined = `${alt} ${src} ${cls} ${title}`;

    const matched = FAKE_DL_IMAGE_SIGNALS.filter(s => combined.includes(s));
    if (matched.length > 0) {
      imageScore += matched.length * 2;
      imageReason = `Image signals: ${matched.slice(0,3).join(', ')}`;
    }

    // Large image inside a link = classic fake download banner
    const w = img.naturalWidth  || img.width  || 0;
    const h = img.naturalHeight || img.height || 0;
    if (w >= 200 && h >= 40) imageScore += 3;
  }

  // Check link text and class signals
  let textScore  = 0;
  let textReason = '';
  const linkCombined = `${linkText} ${linkClass} ${linkId}`;
  const textMatches  = FAKE_DL_TEXT_SIGNALS.filter(s => linkCombined.includes(s));
  if (textMatches.length > 0) {
    textScore  = textMatches.length * 2;
    textReason = `Link text signals: "${textMatches[0]}"`;
  }

  // Check for styled button/div descendants (not actual <a> but fake button divs)
  const btnDescendants = link.querySelectorAll('[class*="download"],[class*="btn"],[class*="button"],[id*="download"]');
  if (btnDescendants.length > 0) textScore += 2;

  const totalScore = imageScore + textScore;
  if (totalScore < 3) return null; // not suspicious enough

  // Now check if the destination is actually suspicious
  const urlAssessment = assessUrl(href);
  const isSuspiciousDest = !urlAssessment.safe;

  // Even if URL looks safe, a large image "download button" going to a non-obvious domain is worth flagging
  let domain = '';
  try { domain = new URL(href).hostname.replace(/^www\./, ''); } catch(e) {}
  const isObviousFileDomain = domain.includes('github') || domain.includes('sourceforge') ||
                               domain.includes('mega.nz') || domain.includes('drive.google') ||
                               domain.includes('dropbox');

  if (!isSuspiciousDest && isObviousFileDomain) return null;

  const reason = [imageReason, textReason].filter(Boolean).join(' · ');
  return {
    isFakeDlButton: true,
    score:          totalScore,
    reason,
    urlAssessment,
    destinationDomain: domain
  };
}

// ---------------------------------------------------------------------------
// TOOLTIP
// ---------------------------------------------------------------------------
let tooltip   = null;
let hideTimer = null;
let activeLink = null;

const HIDE_DELAY = 1200; // ms — tooltip stays this long after mouse leaves

function createTooltip() {
  if (document.getElementById('dg-link-tooltip')) {
    tooltip = document.getElementById('dg-link-tooltip');
    return;
  }
  const el = document.createElement('div');
  el.id = 'dg-link-tooltip';
  Object.assign(el.style, {
    position:      'fixed',
    zIndex:        '2147483647',
    maxWidth:      '500px',
    minWidth:      '200px',
    pointerEvents: 'none',
    display:       'none',
    fontFamily:    'monospace',
    fontSize:      '12px',
    lineHeight:    '1.5',
    borderRadius:  '8px',
    padding:       '10px 14px',
    boxShadow:     '0 4px 24px rgba(0,0,0,0.5)',
    transition:    'opacity 0.1s',
    wordBreak:     'break-all',
  });
  document.body.appendChild(el);
  tooltip = el;
}

function showTooltip(link, mouseX, mouseY) {
  if (!tooltip) createTooltip();
  clearTimeout(hideTimer);
  activeLink = link;

  const href         = link.href || '';
  const displayText  = link.textContent?.trim() || '';
  const urlAssessment = assessUrl(href);
  const fakeDl       = detectFakeDownloadButton(link);

  // Determine final risk level — fake download detection can escalate
  let level, reason;
  if (fakeDl && (fakeDl.score >= 5 || !urlAssessment.safe)) {
    // Fake download button — use HIGH or escalate to CRITICAL if URL is also bad
    level  = (!urlAssessment.safe && urlAssessment.level === 'CRITICAL') ? 'CRITICAL' : 'HIGH';
    reason = `⬇️ Fake download button detected (${fakeDl.reason})`;
    if (!urlAssessment.safe) reason += ` · ${urlAssessment.reason}`;
  } else if (!urlAssessment.safe) {
    level  = urlAssessment.level || 'MEDIUM';
    reason = urlAssessment.reason;
  } else {
    level  = 'SAFE';
    reason = null;
  }

  const colors = {
    CRITICAL: { bg:'#1a0000', border:'#ff4444', text:'#ffaaaa', label:'#ff4444' },
    HIGH:     { bg:'#1a0f00', border:'#f97316', text:'#ffd0aa', label:'#f97316' },
    MEDIUM:   { bg:'#1a1a00', border:'#eab308', text:'#ffeaaa', label:'#eab308' },
    SAFE:     { bg:'#001a0a', border:'#22c55e', text:'#aaffcc', label:'#22c55e' }
  };

  const c    = colors[level];
  const icon = { CRITICAL:'🚨', HIGH:'⚠️', MEDIUM:'🔶', SAFE:'✅' }[level];

  const isMismatch = displayText && displayText.length > 4 &&
                     displayText.startsWith('http') &&
                     !href.includes(displayText.replace(/^https?:\/\//, '').split('/')[0]);

  tooltip.style.background  = c.bg;
  tooltip.style.border      = `1px solid ${c.border}`;
  tooltip.style.color       = c.text;
  tooltip.style.display     = 'block';

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

  if (fakeDl?.isFakeDlButton) {
    const dlBorderColor = level === 'CRITICAL' ? '#ff4444' : '#f97316';
    html += `
      <div style="margin-top:6px;padding:6px 8px;background:rgba(249,115,22,0.12);border-left:3px solid ${dlBorderColor};border-radius:4px;font-size:11px">
        ⬇️ <strong>Fake download button</strong> — this looks like a download link but routes through an ad/redirect network.<br>
        <span style="color:#aaa">True destination: ${fakeDl.destinationDomain || 'unknown'}</span>
      </div>`;
  }

  if (reason && !fakeDl?.isFakeDlButton) {
    html += `<div style="color:${c.label};font-size:11px;margin-top:4px;border-top:1px solid ${c.border};padding-top:6px">🛡️ ${reason}</div>`;
  }

  tooltip.innerHTML = html;
  positionTooltip(mouseX, mouseY);
}

function positionTooltip(x, y) {
  if (!tooltip || tooltip.style.display === 'none') return;
  const tw = tooltip.offsetWidth  || 500;
  const th = tooltip.offsetHeight || 120;
  let left  = x + 14;
  let top   = y + 18;
  if (left + tw > window.innerWidth  - 10) left = x - tw - 14;
  if (top  + th > window.innerHeight - 10) top  = y - th - 14;
  tooltip.style.left = `${Math.max(8, left)}px`;
  tooltip.style.top  = `${Math.max(8, top)}px`;
}

function hideTooltip(immediate = false) {
  clearTimeout(hideTimer);
  if (immediate) {
    if (tooltip) tooltip.style.display = 'none';
    activeLink = null;
  } else {
    hideTimer = setTimeout(() => {
      if (tooltip) tooltip.style.display = 'none';
      activeLink = null;
    }, HIDE_DELAY);
  }
}

// ---------------------------------------------------------------------------
// EVENT LISTENERS
// ---------------------------------------------------------------------------
document.addEventListener('mouseover', (e) => {
  // Match both <a> directly and elements inside <a>
  const link = e.target.closest('a[href]');

  if (!link) {
    // Not hovering any link — start hide timer if tooltip is visible
    if (tooltip && tooltip.style.display !== 'none') hideTooltip();
    return;
  }

  const href = link.href || '';
  if (!href || href.startsWith('mailto:') || href === '#') {
    hideTooltip();
    return;
  }

  // Same link as already shown — just cancel any pending hide
  if (link === activeLink) {
    clearTimeout(hideTimer);
    return;
  }

  showTooltip(link, e.clientX, e.clientY);
}, { passive: true });

document.addEventListener('mousemove', (e) => {
  if (tooltip && tooltip.style.display !== 'none') {
    positionTooltip(e.clientX, e.clientY);
  }
}, { passive: true });

document.addEventListener('mouseout', (e) => {
  // Only hide if moving away from the link entirely (not to a child element)
  const link = e.target.closest('a[href]');
  const relatedLink = e.relatedTarget?.closest?.('a[href]');
  if (link && link === relatedLink) return; // still inside same link
  if (!relatedLink) hideTooltip(); // left all links
}, { passive: true });

// Hide immediately on click or scroll
document.addEventListener('click',  () => hideTooltip(true),  { passive: true });
document.addEventListener('scroll', () => hideTooltip(true),  { passive: true, capture: true });

console.log('[DownloadGuard] Link preview + fake download detection active');
