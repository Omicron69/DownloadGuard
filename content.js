// =============================================================================
// DownloadGuard - content.js v3.2
// Robust Gmail/Outlook email detection — does not rely on specific class names
// =============================================================================

const _host = window.location.hostname;
const PLATFORM = _host.includes('google') ? 'GMAIL' : 'OUTLOOK';
console.log(`[DownloadGuard] ✅ Content script running on ${PLATFORM}`);

// ---------------------------------------------------------------------------
// GMAIL EMAIL EXTRACTION
// Instead of fragile class-name selectors, we find email content by:
// 1. Looking for [role="main"] — stable Gmail attribute
// 2. Finding the largest text block inside it — always the email body
// 3. Finding elements with [email] attribute — always the sender
// 4. Finding the first <h2> in the reading area — always the subject
// ---------------------------------------------------------------------------
function extractGmailEmail() {
  // Find the main reading pane — [role="main"] is stable across Gmail updates
  const main = document.querySelector('[role="main"]');
  if (!main) {
    console.log('[DownloadGuard] No [role="main"] found — inbox may not be loaded yet');
    return null;
  }

  // SUBJECT: First h2 in the main area is always the email subject in Gmail
  const subjectEl = main.querySelector('h2');
  const subject   = subjectEl?.textContent?.trim() || '';

  // SENDER: Elements with [email] attribute are always sender/recipient chips
  const senderEl    = main.querySelector('[email]');
  const senderEmail = senderEl?.getAttribute('email') || '';
  const senderName  = senderEl?.textContent?.trim() || '';

  // BODY: Find the largest text-containing div — this is the email body
  // Gmail wraps email content in deeply nested divs; the one with the most
  // text content is reliably the email body regardless of class names
  const bodyEl = findLargestTextBlock(main);
  const body   = bodyEl?.innerText?.trim() || '';

  // LINKS: All anchor tags inside the body
  const links = bodyEl
    ? [...new Set(
        Array.from(bodyEl.querySelectorAll('a[href]'))
          .map(a => a.href)
          .filter(h => h?.startsWith('http'))
          .slice(0, 30)
      )]
    : [];

  console.log(`[DownloadGuard] Extracted — Subject: "${subject}" | Sender: ${senderEmail} | Body: ${body.length} chars | Links: ${links.length}`);

  if (!body || body.length < 20) {
    console.log('[DownloadGuard] Body too short — email may not be fully rendered yet');
    return null;
  }

  const id = `${subject}_${senderEmail}_${body.substring(0, 60)}`;
  return { subject, senderName, senderEmail, body, links, id };
}

// ---------------------------------------------------------------------------
// FIND LARGEST TEXT BLOCK
// Walks the DOM and returns the element with the most innerText content.
// This is more reliable than any class-name selector for Gmail.
// ---------------------------------------------------------------------------
function findLargestTextBlock(root) {
  let best = null;
  let bestLen = 0;

  // Only look at div and article elements — skips nav, header, sidebar etc.
  const candidates = root.querySelectorAll('div, article');

  for (const el of candidates) {
    // Skip elements that are too small or likely UI chrome
    if (el.children.length > 20) continue; // complex containers, not text blocks
    if (el.offsetHeight < 50)    continue; // tiny elements

    const text = el.innerText?.trim() || '';

    // Skip if this element's text is mostly the same as its parent
    // (we want the innermost meaningful block)
    const parentText = el.parentElement?.innerText?.trim() || '';
    if (parentText.length > 0 && text.length / parentText.length > 0.95 && text.length > 100) continue;

    if (text.length > bestLen && text.length > 50) {
      bestLen = text.length;
      best    = el;
    }
  }

  return best;
}

// ---------------------------------------------------------------------------
// OUTLOOK EMAIL EXTRACTION
// Outlook uses data-testid attributes which are more stable than Gmail's classes
// ---------------------------------------------------------------------------
function extractOutlookEmail() {
  const trySelectors = (selectors) => {
    for (const s of selectors) {
      try { const el = document.querySelector(s); if (el) return el; } catch(e) {}
    }
    return null;
  };

  const subjectEl = trySelectors(['[data-testid="subject"]', '[class*="Subject"]', 'div[role="heading"]']);
  const senderEl  = trySelectors(['[data-testid="sender-persona"]', '[class*="personaName"]', '[class*="SenderName"]']);
  const bodyEl    = trySelectors(['[data-testid="message-body"]', '.allowTextSelection', '[class*="ReadingPane"] [class*="body"]']);

  if (!bodyEl) {
    // Fallback: find largest text block same as Gmail
    const pane = trySelectors(['[data-app-section="ReadingPane"]', '[class*="readingPane"]']);
    if (!pane) return null;
    const fallbackBody = findLargestTextBlock(pane);
    if (!fallbackBody) return null;

    const body = fallbackBody.innerText?.trim() || '';
    if (body.length < 20) return null;
    return {
      subject:     subjectEl?.textContent?.trim() || '',
      senderName:  senderEl?.textContent?.trim() || '',
      senderEmail: senderEl?.getAttribute('data-email') || '',
      body,
      links: [],
      id: `outlook_${body.substring(0, 60)}`
    };
  }

  const body = bodyEl.innerText?.trim() || '';
  if (body.length < 20) return null;

  const links = [...new Set(
    Array.from(bodyEl.querySelectorAll('a[href]'))
      .map(a => a.href).filter(h => h?.startsWith('http')).slice(0, 30)
  )];

  return {
    subject:     subjectEl?.textContent?.trim() || '',
    senderName:  senderEl?.textContent?.trim() || '',
    senderEmail: senderEl?.getAttribute('data-email') || senderEl?.getAttribute('email') || '',
    body, links,
    id: `outlook_${subjectEl?.textContent?.trim()}_${body.substring(0, 60)}`
  };
}

// ---------------------------------------------------------------------------
// IS EMAIL OPEN?
// ---------------------------------------------------------------------------
function emailIsOpen() {
  if (PLATFORM === 'GMAIL') {
    // Gmail URL changes to /#folder/MessageID when email is open
    // On inbox list: just /#inbox with no message ID
    const hash = window.location.hash;
    if (!/^#[a-zA-Z0-9_]+\/[A-Za-z0-9]{6,}/.test(hash)) {
      console.log(`[DownloadGuard] URL hash "${hash}" doesn't match email pattern — inbox list view`);
      return false;
    }
    return true;
  }
  if (PLATFORM === 'OUTLOOK') {
    const pane = document.querySelector('[data-app-section="ReadingPane"], .allowTextSelection, [data-testid="message-body"]');
    return !!(pane && pane.innerText?.trim().length > 20);
  }
  return false;
}

// ---------------------------------------------------------------------------
// EXTRACT EMAIL (platform router)
// ---------------------------------------------------------------------------
function extractEmail() {
  return PLATFORM === 'GMAIL' ? extractGmailEmail() : extractOutlookEmail();
}

// ---------------------------------------------------------------------------
// BANNER INJECTION
// ---------------------------------------------------------------------------
function showBanner(emailData, result) {
  document.getElementById('dg-banner')?.remove();
  if (result.riskLevel === 'LOW') {
    console.log(`[DownloadGuard] LOW risk (${result.riskScore}/100) — no banner shown`);
    return;
  }

  const palette = {
    MEDIUM:   { bg:'#fef9e7', border:'#f39c12', text:'#e67e22', icon:'⚠️' },
    HIGH:     { bg:'#fef3e2', border:'#e67e22', text:'#d35400', icon:'🔶' },
    CRITICAL: { bg:'#fdecea', border:'#e74c3c', text:'#c0392b', icon:'🚨' }
  };
  const c = palette[result.riskLevel] || palette.MEDIUM;
  const threatLabel = result.threatType || 'THREAT';

  const banner = document.createElement('div');
  banner.id = 'dg-banner';
  banner.innerHTML = `
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px">
      <div style="display:flex;align-items:flex-start;gap:10px;flex:1">
        <span style="font-size:22px;flex-shrink:0">${c.icon}</span>
        <div>
          <div style="font-weight:700;font-size:13px;color:${c.text};display:flex;align-items:center;gap:8px;flex-wrap:wrap">
            🛡️ DownloadGuard · ${threatLabel} detected
            <span style="background:${c.border};color:#fff;font-size:11px;padding:2px 8px;border-radius:10px;font-weight:700">${result.riskLevel} · ${result.riskScore}/100</span>
          </div>
          <div style="font-size:12px;color:#444;margin-top:3px">${result.verdict}</div>
        </div>
      </div>
      <div style="display:flex;gap:6px;flex-shrink:0">
        <button id="dg-details-btn" style="border:none;background:rgba(0,0,0,0.08);color:#333;padding:4px 10px;border-radius:6px;font-size:12px;cursor:pointer">Details ▾</button>
        <button id="dg-close-btn"   style="border:none;background:rgba(0,0,0,0.08);color:#333;padding:4px 8px; border-radius:6px;font-size:12px;cursor:pointer">✕</button>
      </div>
    </div>
    <div id="dg-detail-panel" style="display:none;margin-top:10px;padding-top:10px;border-top:1px solid rgba(0,0,0,0.1)">
      <div style="font-weight:700;font-size:12px;color:#555;margin-bottom:6px">Indicators found:</div>
      ${(result.indicators||[]).map(i => `<div style="font-size:12px;padding:2px 0;color:#333">⚬ ${i}</div>`).join('')}
      <div style="margin-top:8px;font-size:12px;background:rgba(0,0,0,0.05);padding:8px;border-radius:6px">
        <strong>Recommendation:</strong> ${result.recommendation}
      </div>
      <div style="margin-top:6px;font-size:12px;color:${c.text};font-weight:600">
        ⚠️ Any files downloaded from this email will be flagged as coming from a ${result.riskLevel} risk source.
      </div>
    </div>
  `;

  Object.assign(banner.style, {
    background: c.bg, border: `2px solid ${c.border}`,
    borderRadius: '8px', margin: '8px 16px 0', padding: '14px 16px',
    fontFamily: 'Arial,sans-serif', fontSize: '13px',
    zIndex: '9999', boxShadow: '0 2px 8px rgba(0,0,0,0.12)'
  });

  // Insert into page
  const insertionPoints = PLATFORM === 'GMAIL'
    ? ['[role="main"] h2', '[role="main"]']
    : ['[data-app-section="ReadingPane"]', '[data-testid="message-body"]'];

  let inserted = false;
  for (const sel of insertionPoints) {
    try {
      const el = document.querySelector(sel);
      if (el) {
        el.insertAdjacentElement('beforebegin', banner);
        inserted = true;
        break;
      }
    } catch(e) {}
  }

  if (!inserted) {
    // Fixed position fallback — always visible
    Object.assign(banner.style, {
      position:'fixed', top:'60px', left:'50%',
      transform:'translateX(-50%)',
      width:'600px', maxWidth:'92vw', margin:'0'
    });
    document.body.appendChild(banner);
  }

  // Attach button listeners (no onclick in injected HTML)
  document.getElementById('dg-details-btn')?.addEventListener('click', () => {
    const panel = document.getElementById('dg-detail-panel');
    if (panel) panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
  });
  document.getElementById('dg-close-btn')?.addEventListener('click', () => {
    document.getElementById('dg-banner')?.remove();
  });

  console.log(`[DownloadGuard] Banner injected — ${result.riskLevel} (${result.riskScore}/100)`);
}

// ---------------------------------------------------------------------------
// BADGE while analysing
// ---------------------------------------------------------------------------
function showBadge() {
  document.getElementById('dg-badge')?.remove();
  const b = document.createElement('div');
  b.id = 'dg-badge';
  b.textContent = `🛡️ DownloadGuard scanning email...`;
  Object.assign(b.style, {
    position:'fixed', bottom:'20px', right:'20px',
    background:'#1a2340', color:'#fff',
    padding:'10px 18px', borderRadius:'20px',
    fontSize:'13px', fontFamily:'Arial,sans-serif',
    zIndex:'99999', boxShadow:'0 2px 12px rgba(0,0,0,0.3)',
    pointerEvents:'none'
  });
  document.body.appendChild(b);
}
const removeBadge = () => document.getElementById('dg-badge')?.remove();

// ---------------------------------------------------------------------------
// STATE
// ---------------------------------------------------------------------------
let lastId      = null;
let analysing   = false;
let triggeredForUrl = false;
let lastUrl     = location.href;

// ---------------------------------------------------------------------------
// MAIN ANALYSIS TRIGGER
// ---------------------------------------------------------------------------
function analyse() {
  if (analysing || triggeredForUrl) return;
  if (!emailIsOpen()) return;

  const email = extractEmail();
  if (!email) {
    // Email not rendered yet — retry once more after 2s
    console.log('[DownloadGuard] Email not ready, retrying in 2s...');
    setTimeout(() => {
      if (!analysing && !triggeredForUrl) {
        const retry = extractEmail();
        if (retry) triggerAnalysis(retry);
      }
    }, 2000);
    return;
  }

  triggerAnalysis(email);
}

function triggerAnalysis(email) {
  if (email.id === lastId) {
    console.log('[DownloadGuard] Same email — skipping re-analysis');
    return;
  }

  analysing       = true;
  triggeredForUrl = true;
  lastId          = email.id;

  console.log(`[DownloadGuard] Sending to Gemini — subject: "${email.subject}", body: ${email.body.length} chars`);
  showBadge();

  chrome.runtime.sendMessage(
    {
      action: 'ANALYSE_PHISHING',
      emailData: {
        subject:     email.subject,
        senderName:  email.senderName,
        senderEmail: email.senderEmail,
        body:        email.body.substring(0, 3000),
        links:       email.links
      }
    },
    (res) => {
      removeBadge();
      analysing = false;

      if (chrome.runtime.lastError) {
        console.warn('[DownloadGuard] sendMessage error:', chrome.runtime.lastError.message);
        return;
      }
      if (!res) {
        console.warn('[DownloadGuard] No response from background');
        return;
      }
      if (res.success) {
        console.log('[DownloadGuard] Gemini result:', res.result);
        showBanner(email, res.result);
      } else {
        console.warn('[DownloadGuard] Gemini error:', res.error);
        // Show error badge so user knows something went wrong
        const b = document.createElement('div');
        b.textContent = `⚠️ DownloadGuard: ${res.error}`;
        Object.assign(b.style, {
          position:'fixed', bottom:'20px', right:'20px',
          background:'#e74c3c', color:'#fff',
          padding:'10px 18px', borderRadius:'10px',
          fontSize:'12px', zIndex:'99999',
          maxWidth:'320px', cursor:'pointer'
        });
        b.addEventListener('click', () => b.remove());
        document.body.appendChild(b);
        setTimeout(() => b.remove(), 8000);
      }
    }
  );
}

// ---------------------------------------------------------------------------
// URL CHANGE — fires when user opens a different email
// ---------------------------------------------------------------------------
function onUrlChange() {
  const current = location.href;
  if (current === lastUrl) return;
  lastUrl = current;

  console.log(`[DownloadGuard] URL changed → ${current}`);

  document.getElementById('dg-banner')?.remove();
  triggeredForUrl = false;
  analysing       = false;

  // Wait for Gmail to render the new email
  setTimeout(analyse, 2500);
}

// ---------------------------------------------------------------------------
// MUTATION OBSERVER — catches email render after URL change
// ---------------------------------------------------------------------------
let debounce = null;
new MutationObserver(() => {
  if (location.href !== lastUrl) { onUrlChange(); return; }
  if (triggeredForUrl || analysing) return;
  clearTimeout(debounce);
  debounce = setTimeout(() => {
    if (emailIsOpen()) analyse();
  }, 2500);
}).observe(document.body, { childList: true, subtree: true });

// ---------------------------------------------------------------------------
// PATCH HISTORY API — Gmail uses pushState for navigation
// ---------------------------------------------------------------------------
const _orig = history.pushState.bind(history);
history.pushState = (...a) => {
  _orig(...a);
  triggeredForUrl = false;
  setTimeout(onUrlChange, 200);
};
window.addEventListener('popstate', () => {
  triggeredForUrl = false;
  setTimeout(onUrlChange, 200);
});

console.log('[DownloadGuard] Monitor active. Open an email to begin scanning.');
