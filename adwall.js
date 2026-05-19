// =============================================================================
// DownloadGuard - adwall.js
// Ad-wall bypasser and link de-obfuscator
// Detects known ad-wall/link shortener URLs and resolves the final destination
// without rendering the intermediary page or executing its malicious scripts
// =============================================================================

// ---------------------------------------------------------------------------
// KNOWN AD-WALL AND LINK SHORTENER DOMAINS
// These sites intercept users with countdown timers, fake captchas, and
// drive-by download attempts before revealing the actual file URL
// ---------------------------------------------------------------------------
const ADWALL_DOMAINS = new Set([
  // Major link shorteners used in piracy ecosystems
  'linkvertise.com', 'linkvertise.net',
  'lnkfly.com', 'lnkfly.net',
  'adf.ly', 'j.gs', 'q.gs',
  'bc.vc',
  'ouo.io', 'ouo.press',
  'exe.io', 'exe.app',
  'shrink.pe', 'shrinkme.io',
  'droplink.co',
  'gplinks.in', 'gplinks.co',
  'safelinku.com',
  'earn4clicks.com',
  'za.gl', 'fc.lc',
  'cut-urls.com',
  'cutt.ly',
  'shrinkearn.com',
  'shorte.st',
  'linkbucks.com',
  'adfly.com',
  'sh.st',
  'adfoc.us',
  'link-to.net',
  'clk.sh',
  'coinsurl.com',
  'dl.free.fr',
  'filesim.com',
  'getlink.store',
  'oke.io',
  'dl-protect.net',
  'lnk2.com',
  'lnk3.com',
  'fastdl.io',
  'earnload.com',
  'short.pe',
  'ity.im',
  'bit.do',
  'url.ie',
  'krurl.net',
  'link1s.com',
  'linkshrink.net',
  'shorte.me',
  'cloak.to',
  'cloak.me',
  'urlcash.net',
  'mgcash.com',
  'adrinolinks.in',
  'bdshort.com',
  'short.livetl.app',
  'fileup.link',
  'directlink.io',
]);

// Ad-wall detection patterns in URL path/query
const ADWALL_URL_PATTERNS = [
  /\/(?:go|out|redirect|redir|click|track|link)\//i,
  /[?&](?:url|u|dest|destination|redirect|target|go|goto|link)=/i,
  /\/countdown\//i,
  /\/generate\//i,
  /\/bypass\//i,
];

function isAdWallUrl(url) {
  try {
    const u = new URL(url);
    if (ADWALL_DOMAINS.has(u.hostname.replace(/^www\./, ''))) return true;
    return ADWALL_URL_PATTERNS.some(p => p.test(u.pathname + u.search));
  } catch(e) { return false; }
}

// ---------------------------------------------------------------------------
// RESOLUTION CACHE — avoid repeated requests for the same URL
// ---------------------------------------------------------------------------
const resolvedCache = new Map();

// ---------------------------------------------------------------------------
// RESOLVE ADWALL URL
// Sends to background service worker which does the actual fetch
// (Content scripts can't follow cross-origin redirects directly)
// ---------------------------------------------------------------------------
async function resolveAdWallUrl(url) {
  if (resolvedCache.has(url)) return resolvedCache.get(url);

  return new Promise((resolve) => {
    const timeout = setTimeout(() => resolve({ success: false, error: 'Timeout' }), 10000);
    chrome.runtime.sendMessage({ action: 'RESOLVE_ADWALL', url }, (res) => {
      clearTimeout(timeout);
      if (chrome.runtime.lastError) {
        resolve({ success: false, error: chrome.runtime.lastError.message });
        return;
      }
      if (res?.success) {
        resolvedCache.set(url, res);
      }
      resolve(res || { success: false, error: 'No response' });
    });
  });
}

// ---------------------------------------------------------------------------
// HOOK INTO LINKPREVIEW
// This runs after linkpreview.js — patches the showTooltip function
// to add ad-wall resolution when a known adwall URL is detected
// ---------------------------------------------------------------------------
function patchLinkPreviewForAdwall() {
  // We intercept mouseover on links that are adwall URLs
  // and augment the tooltip with the resolved final URL
  document.addEventListener('mouseover', async (e) => {
    const link = e.target.closest('a[href]');
    if (!link || !link.href) return;

    if (!isAdWallUrl(link.href)) return;

    // Update the existing tooltip with loading state
    const tooltip = document.getElementById('dg-link-tooltip');
    if (tooltip) {
      const existing = tooltip.innerHTML;
      const loadingDiv = document.createElement('div');
      loadingDiv.id = 'dg-adwall-status';
      loadingDiv.style.cssText = 'margin-top:8px;padding-top:8px;border-top:1px solid #333;font-size:11px;color:#58a6ff';
      loadingDiv.textContent = '⏳ Resolving ad-wall destination...';

      // Remove old adwall status if present
      tooltip.querySelector('#dg-adwall-status')?.remove();
      tooltip.appendChild(loadingDiv);
    }

    // Resolve in background
    const result = await resolveAdWallUrl(link.href);
    const statusEl = document.getElementById('dg-adwall-status');
    if (!statusEl) return;

    if (result.success && result.finalUrl && result.finalUrl !== link.href) {
      statusEl.innerHTML = `
        <div style="color:#22c55e;font-weight:700;margin-bottom:4px">✅ Ad-wall bypassed</div>
        <div style="color:#aaa;font-size:10px;margin-bottom:2px">FINAL DESTINATION</div>
        <div style="color:#22c55e;font-size:11px;margin-bottom:6px;word-break:break-all">${escHtml(result.finalUrl)}</div>
        ${result.hops > 1 ? `<div style="color:#666;font-size:10px">${result.hops} redirect${result.hops>1?'s':''} followed</div>` : ''}
        <button id="dg-copy-final" style="margin-top:6px;background:#21262d;color:#22c55e;border:1px solid #22c55e;border-radius:4px;padding:3px 8px;font-size:10px;cursor:pointer;font-family:monospace;pointer-events:all">
          Copy final URL
        </button>
      `;
      document.getElementById('dg-copy-final')?.addEventListener('click', (ev) => {
        ev.stopPropagation();
        ev.preventDefault();
        navigator.clipboard.writeText(result.finalUrl);
        ev.target.textContent = 'Copied!';
        setTimeout(() => { if(ev.target) ev.target.textContent = 'Copy final URL'; }, 1500);
      });
    } else if (result.success && result.finalUrl === link.href) {
      statusEl.innerHTML = `<div style="color:#8b949e;font-size:11px">ℹ️ No redirect detected — URL may use JavaScript countdown</div>`;
    } else {
      statusEl.innerHTML = `<div style="color:#f97316;font-size:11px">⚠️ Could not resolve: ${escHtml(result.error || 'Unknown error')}</div>`;
    }
  }, { passive: true });
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ---------------------------------------------------------------------------
// VISUAL AD-WALL BADGE ON LINKS
// Add a small "🔗 Ad-wall" badge to links we know are ad-wall URLs
// so users can see them before hovering
// ---------------------------------------------------------------------------
function badgeAdWallLinks() {
  const links = document.querySelectorAll('a[href]:not([data-dg-adwall-badged])');
  links.forEach(link => {
    if (!link.href || !isAdWallUrl(link.href)) return;
    link.dataset.dgAdwallBadged = '1';

    const badge = document.createElement('span');
    badge.textContent = '🔗';
    badge.title = 'DownloadGuard: This is an ad-wall link — hover to resolve final URL';
    Object.assign(badge.style, {
      fontSize:       '11px',
      marginLeft:     '4px',
      cursor:         'help',
      verticalAlign:  'middle',
      display:        'inline',
    });
    link.insertAdjacentElement('afterend', badge);
  });
}

// Run on DOM changes
let badgeDebounce = null;
new MutationObserver(() => {
  clearTimeout(badgeDebounce);
  badgeDebounce = setTimeout(badgeAdWallLinks, 1500);
}).observe(document.body, { childList: true, subtree: true });

setTimeout(() => {
  badgeAdWallLinks();
  patchLinkPreviewForAdwall();
}, 1000);

console.log('[DownloadGuard] Ad-wall bypasser active');
