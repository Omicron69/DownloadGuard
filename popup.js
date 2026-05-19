// popup.js v3.3 — with manual Scan Now button as primary trigger

let currentTabId = null;

document.addEventListener('DOMContentLoaded', () => {
  loadStats();
  checkSavedKeys();
  loadTabInfo();

  // Wire up all buttons via addEventListener — never onclick in HTML
  document.getElementById('geminiSaveBtn')  ?.addEventListener('click', () => saveAndTest('gemini'));
  document.getElementById('geminiRetestBtn')?.addEventListener('click', () => retestKey('gemini'));
  document.getElementById('vtSaveBtn')      ?.addEventListener('click', () => saveAndTest('vt'));
  document.getElementById('vtRetestBtn')    ?.addEventListener('click', () => retestKey('vt'));
  document.getElementById('scanNowBtn')     ?.addEventListener('click', scanCurrentEmail);
});

// ---------------------------------------------------------------------------
// TAB INFO + ALLOW + SCAN NOW
// ---------------------------------------------------------------------------
function loadTabInfo() {
  chrome.runtime.sendMessage({ action: 'GET_TAB_INFO' }, (res) => {
    if (chrome.runtime.lastError || !res?.data) return;
    const { hostname, isEmail, isAllowed, tabId } = res.data;
    currentTabId = tabId;
    const container = document.getElementById('emailSiteContent');

    if (!isEmail) {
      container.innerHTML = `<div class="not-email">Open Gmail or Outlook in this tab to enable email scanning.</div>`;
      return;
    }

    const icon  = hostname.includes('google') ? '📨' : '📧';
    const label = hostname.includes('google') ? 'Gmail' : 'Outlook';

    container.innerHTML = `
      <div class="site-row">
        <div class="site-left">
          <span class="site-icon">${icon}</span>
          <div>
            <div class="site-name">${label}</div>
            <div class="site-url">${hostname}</div>
          </div>
        </div>
        <button class="btn ${isAllowed ? 'btn-green' : 'btn-navy'}" id="allowBtn">
          ${isAllowed ? '✓ Allowed' : 'Allow'}
        </button>
      </div>
      <div id="allowMsg" style="font-size:11px;color:${isAllowed ? '#27ae60' : '#8892a4'};margin-top:8px;text-align:center">
        ${isAllowed ? '✅ Scanner injected — use Scan Now below' : 'Click Allow then use Scan Now to analyse an open email'}
      </div>
    `;

    // Show the Scan Now button on email sites
    const scanBtn = document.getElementById('scanNowBtn');
    if (scanBtn) scanBtn.style.display = 'block';

    // Wire Allow button
    document.getElementById('allowBtn')?.addEventListener('click', () => allowAndInject(label));
  });
}

// ---------------------------------------------------------------------------
// ALLOW — inject content script into the Gmail/Outlook tab
// ---------------------------------------------------------------------------
function allowAndInject(label) {
  const btn = document.getElementById('allowBtn');
  const msg = document.getElementById('allowMsg');
  if (btn) btn.textContent = '⏳...';

  chrome.runtime.sendMessage({ action: 'INJECT_CONTENT_SCRIPT' }, (res) => {
    if (chrome.runtime.lastError) {
      if (btn) btn.textContent = 'Allow';
      if (msg) { msg.style.color = '#e74c3c'; msg.textContent = '❌ ' + chrome.runtime.lastError.message; }
      return;
    }
    if (!res?.success) {
      if (btn) btn.textContent = 'Allow';
      if (msg) { msg.style.color = '#e74c3c'; msg.textContent = '❌ ' + (res?.error || 'Injection failed'); }
      return;
    }
    if (btn) { btn.className = 'btn btn-green'; btn.textContent = '✓ Allowed'; }
    if (msg) { msg.style.color = '#27ae60'; msg.textContent = `✅ Scanner injected into ${label} — open an email then click Scan Now`; }
  });
}

// ---------------------------------------------------------------------------
// SCAN NOW — manually trigger analysis of the current email
// The most reliable approach: runs the extraction directly in the tab
// ---------------------------------------------------------------------------
function scanCurrentEmail() {
  const btn    = document.getElementById('scanNowBtn');
  const status = document.getElementById('scanStatus');

  if (btn)    { btn.textContent = '⏳ Scanning...'; btn.disabled = true; }
  if (status) { status.style.display = 'block'; status.style.color = '#004085'; status.textContent = 'Injecting scanner and extracting email content...'; }

  // Step 1: Ensure content script is injected
  chrome.runtime.sendMessage({ action: 'INJECT_CONTENT_SCRIPT' }, (injectRes) => {
    if (chrome.runtime.lastError) {
      showScanStatus('error', '❌ Injection error: ' + chrome.runtime.lastError.message);
      resetScanBtn();
      return;
    }

    // Step 2: Wait for script to initialise then run extraction in the tab
    setTimeout(() => {
      if (!currentTabId) {
        showScanStatus('error', '❌ No tab ID — close and reopen this popup');
        resetScanBtn();
        return;
      }

      // Run email extraction directly in the page context
      chrome.scripting.executeScript({
        target: { tabId: currentTabId },
        func: extractEmailInPage
      }, (results) => {
        if (chrome.runtime.lastError) {
          showScanStatus('error', '❌ Script error: ' + chrome.runtime.lastError.message);
          resetScanBtn();
          return;
        }

        const emailData = results?.[0]?.result;

        if (!emailData) {
          showScanStatus('error', '❌ No email detected — make sure an email is open and fully loaded in Gmail');
          resetScanBtn();
          return;
        }

        showScanStatus('info', `📧 Found email: "${emailData.subject || '(no subject)'}" (${emailData.body.length} chars) — sending to Gemini...`);

        // Step 3: Send to Gemini via background
        chrome.runtime.sendMessage({ action: 'ANALYSE_PHISHING', emailData }, (res) => {
          resetScanBtn();

          if (chrome.runtime.lastError) {
            showScanStatus('error', '❌ ' + chrome.runtime.lastError.message);
            return;
          }
          if (!res?.success) {
            showScanStatus('error', '❌ Gemini error: ' + (res?.error || 'Unknown error'));
            return;
          }

          const r = res.result;
          const emoji = { LOW:'✅', MEDIUM:'⚠️', HIGH:'🔶', CRITICAL:'🚨' }[r.riskLevel] || '⚠️';
          showScanStatus(
            r.riskLevel === 'LOW' ? 'success' : 'warn',
            `${emoji} ${r.riskLevel} (${r.riskScore}/100) — ${r.verdict}`
          );

          // Inject the banner into the page
          chrome.scripting.executeScript({
            target: { tabId: currentTabId },
            func: injectBannerInPage,
            args: [emailData, r]
          });
        });
      });
    }, 800); // Give content script time to initialise
  });
}

// ---------------------------------------------------------------------------
// RUNS INSIDE THE GMAIL TAB — extracts email content
// This function is serialised and sent to the tab via chrome.scripting
// It CANNOT reference any variables outside itself
// ---------------------------------------------------------------------------
function extractEmailInPage() {
  const main = document.querySelector('[role="main"]');
  if (!main) return null;

  // Subject: first h2 in main area
  const subject = main.querySelector('h2')?.textContent?.trim() || '';

  // Sender: element with [email] attribute
  const senderEl    = main.querySelector('[email]');
  const senderEmail = senderEl?.getAttribute('email') || '';
  const senderName  = senderEl?.textContent?.trim() || '';

  // Body: find largest text block
  let best = null, bestLen = 0;
  for (const el of main.querySelectorAll('div')) {
    if (el.children.length > 25 || el.offsetHeight < 30) continue;
    const text   = el.innerText?.trim() || '';
    const parent = el.parentElement?.innerText?.trim() || '';
    if (parent.length > 0 && text.length > 100 && text.length / parent.length > 0.95) continue;
    if (text.length > bestLen && text.length > 30) { bestLen = text.length; best = el; }
  }

  const body  = best?.innerText?.trim() || main.innerText?.trim() || '';
  const links = best
    ? [...new Set(Array.from(best.querySelectorAll('a[href]')).map(a => a.href).filter(h => h?.startsWith('http')).slice(0, 20))]
    : [];

  if (!body || body.length < 15) return null;
  return { subject, senderName, senderEmail, body: body.substring(0, 3000), links };
}

// ---------------------------------------------------------------------------
// RUNS INSIDE THE GMAIL TAB — injects the result banner
// ---------------------------------------------------------------------------
function injectBannerInPage(emailData, result) {
  document.getElementById('dg-banner')?.remove();
  if (result.riskLevel === 'LOW') return;

  const palette = {
    MEDIUM:   { bg:'#fef9e7', border:'#f39c12', text:'#e67e22', icon:'⚠️' },
    HIGH:     { bg:'#fef3e2', border:'#e67e22', text:'#d35400', icon:'🔶' },
    CRITICAL: { bg:'#fdecea', border:'#e74c3c', text:'#c0392b', icon:'🚨' }
  };
  const c = palette[result.riskLevel] || palette.MEDIUM;

  const banner = document.createElement('div');
  banner.id = 'dg-banner';
  banner.innerHTML = `
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px">
      <div style="display:flex;align-items:flex-start;gap:10px;flex:1">
        <span style="font-size:22px">${c.icon}</span>
        <div>
          <div style="font-weight:700;font-size:13px;color:${c.text}">
            🛡️ DownloadGuard · ${result.threatType || 'THREAT'} — ${result.riskLevel}
            <span style="background:${c.border};color:#fff;font-size:11px;padding:2px 8px;border-radius:10px;margin-left:4px">${result.riskScore}/100</span>
          </div>
          <div style="font-size:12px;color:#444;margin-top:3px">${result.verdict}</div>
          <div style="margin-top:8px">
            ${(result.indicators||[]).map(i=>`<div style="font-size:11px;color:#555;padding:1px 0">⚬ ${i}</div>`).join('')}
          </div>
          <div style="margin-top:8px;font-size:11px;background:rgba(0,0,0,0.05);padding:6px 8px;border-radius:6px">
            <strong>Recommendation:</strong> ${result.recommendation}
          </div>
        </div>
      </div>
      <button id="dg-close" style="border:none;background:rgba(0,0,0,0.08);color:#333;padding:4px 8px;border-radius:6px;font-size:13px;cursor:pointer;flex-shrink:0">✕</button>
    </div>
  `;
  Object.assign(banner.style, {
    position:'fixed', top:'60px', left:'50%', transform:'translateX(-50%)',
    width:'620px', maxWidth:'92vw',
    background:c.bg, border:`2px solid ${c.border}`,
    borderRadius:'10px', padding:'16px 18px',
    fontFamily:'Arial,sans-serif', fontSize:'13px',
    zIndex:'2147483647', boxShadow:'0 4px 24px rgba(0,0,0,0.18)'
  });
  document.body.appendChild(banner);
  document.getElementById('dg-close')?.addEventListener('click', () => banner.remove());
}

// ---------------------------------------------------------------------------
// HELPERS
// ---------------------------------------------------------------------------
function resetScanBtn() {
  const btn = document.getElementById('scanNowBtn');
  if (btn) { btn.textContent = '🔍 Scan Current Email Now'; btn.disabled = false; }
}

function showScanStatus(type, message) {
  const el = document.getElementById('scanStatus');
  if (!el) return;
  const colors = {
    success: '#155724', error: '#721c24',
    warn: '#856404',    info:  '#004085'
  };
  el.style.display = 'block';
  el.style.color   = colors[type] || '#555';
  el.textContent   = message;
}

// ---------------------------------------------------------------------------
// STATS
// ---------------------------------------------------------------------------
function loadStats() {
  chrome.runtime.sendMessage({ action: 'GET_STATS' }, (res) => {
    if (chrome.runtime.lastError || !res) return;
    document.getElementById('statThreats').textContent = res.threats    || 0;
    document.getElementById('statMasq').textContent    = res.masquerade || 0;
    document.getElementById('statPhish').textContent   = res.phishing   || 0;
  });
}

// ---------------------------------------------------------------------------
// KEY MANAGEMENT
// ---------------------------------------------------------------------------
function checkSavedKeys() {
  chrome.storage.local.get(['dg_gemini_key', 'dg_vt_key'], (stored) => {
    if (chrome.runtime.lastError) return;
    const g = stored['dg_gemini_key'];
    const v = stored['dg_vt_key'];
    if (g) setStatus('geminiStatus', 'saved', `✅ Key saved: ${g.slice(0,6)}••••••••${g.slice(-4)} (${g.length} chars)`);
    else   setStatus('geminiStatus', 'none',  '⬜ No Gemini key saved yet');
    if (v) setStatus('vtStatus',     'saved', `✅ Key saved: ${v.slice(0,6)}••••••••${v.slice(-4)} (${v.length} chars)`);
    else   setStatus('vtStatus',     'none',  '⬜ No VirusTotal key saved yet');
  });
}

function saveAndTest(service) {
  const key = document.getElementById(service === 'gemini' ? 'geminiInput' : 'vtInput')?.value?.trim();
  if (!key) { setStatus(`${service}Status`, 'error', '❌ Paste a key first'); return; }
  setStatus(`${service}Status`, 'testing', `⏳ Saving ${key.length} chars...`);
  const storageKey = service === 'gemini' ? 'dg_gemini_key' : 'dg_vt_key';
  chrome.storage.local.set({ [storageKey]: key }, () => {
    if (chrome.runtime.lastError) { setStatus(`${service}Status`, 'error', '❌ Save failed'); return; }
    document.getElementById(service === 'gemini' ? 'geminiInput' : 'vtInput').value = '';
    setStatus(`${service}Status`, 'testing', `💾 Saved — testing API...`);
    runTest(service, key);
  });
}

function retestKey(service) {
  const storageKey = service === 'gemini' ? 'dg_gemini_key' : 'dg_vt_key';
  chrome.storage.local.get(storageKey, (stored) => {
    const key = stored[storageKey];
    if (!key) { setStatus(`${service}Status`, 'error', '❌ No key saved — paste one above'); return; }
    setStatus(`${service}Status`, 'testing', `⏳ Testing ${key.slice(0,6)}...${key.slice(-4)}...`);
    runTest(service, key);
  });
}

function runTest(service, key) {
  chrome.runtime.sendMessage({ action: service === 'gemini' ? 'TEST_GEMINI_KEY' : 'TEST_VT_KEY', key }, (res) => {
    if (chrome.runtime.lastError) { setStatus(`${service}Status`, 'error', '❌ ' + chrome.runtime.lastError.message); return; }
    if (!res) { setStatus(`${service}Status`, 'error', '❌ No response — reload extension'); return; }
    if (service === 'gemini') {
      res.success
        ? setStatus('geminiStatus', 'success', `✅ Working — Gemini replied: "${res.reply}"`)
        : setStatus('geminiStatus', 'error',   `❌ ${res.error}`);
    } else {
      res.success
        ? setStatus('vtStatus', res.rateLimited ? 'warn' : 'success',
            res.rateLimited ? `⚠️ Valid but rate limited` : `✅ Working — ${res.used}/${res.quota} used today`)
        : setStatus('vtStatus', 'error', `❌ ${res.error}`);
    }
  });
}

function setStatus(id, type, message) {
  const el = document.getElementById(id);
  if (!el) return;
  const s = { success:{c:'#155724',bg:'#d4edda',b:'#c3e6cb'}, error:{c:'#721c24',bg:'#f8d7da',b:'#f5c6cb'}, warn:{c:'#856404',bg:'#fff3cd',b:'#ffeeba'}, testing:{c:'#004085',bg:'#cce5ff',b:'#b8daff'}, saved:{c:'#155724',bg:'#d4edda',b:'#c3e6cb'}, none:{c:'#383d41',bg:'#e2e3e5',b:'#d6d8db'} }[type] || {c:'#555',bg:'#eee',b:'#ccc'};
  el.textContent = message;
  el.style.cssText = `display:block!important;color:${s.c};background:${s.bg};border:1px solid ${s.b};border-radius:6px;padding:6px 10px;margin-top:6px;font-size:11px;line-height:1.4;word-break:break-word;`;
}
