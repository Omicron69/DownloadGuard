// =============================================================================
// DownloadGuard - qrscanner.js
// Scans images on the page for QR codes and checks where they lead
// Defends against "quishing" — QR code phishing attacks
// =============================================================================

// jsQR is loaded via manifest content_scripts before this file runs

// ---------------------------------------------------------------------------
// SCAN AN IMAGE ELEMENT FOR QR CODE
// ---------------------------------------------------------------------------
function scanImageForQR(img) {
  if (img.dataset.dgScanned) return;   // Already checked
  img.dataset.dgScanned = '1';

  // Skip tiny images — QR codes need to be a reasonable size
  if (img.naturalWidth < 50 || img.naturalHeight < 50) return;
  // Skip very wide/thin images — unlikely to be QR codes (banners, logos)
  const ratio = img.naturalWidth / img.naturalHeight;
  if (ratio > 3 || ratio < 0.33) return;

  const canvas  = document.createElement('canvas');
  const ctx     = canvas.getContext('2d');
  canvas.width  = img.naturalWidth;
  canvas.height = img.naturalHeight;

  try {
    ctx.drawImage(img, 0, 0);
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

    if (typeof jsQR === 'undefined') {
      console.warn('[DG QR] jsQR not loaded');
      return;
    }

    const code = jsQR(imageData.data, imageData.width, imageData.height, {
      inversionAttempts: 'dontInvert'
    });

    if (code?.data) {
      console.log('[DG QR] QR code found:', code.data);
      injectQRWarning(img, code.data);
    }
  } catch (e) {
    // CORS-blocked images can't be read via canvas — skip silently
    if (!e.message?.includes('cross-origin') && !e.message?.includes('tainted')) {
      console.warn('[DG QR] Canvas error:', e.message);
    }
  }
}

// ---------------------------------------------------------------------------
// INJECT WARNING BADGE ON QR IMAGE
// ---------------------------------------------------------------------------
function injectQRWarning(img, qrData) {
  // Assess the URL in the QR code
  const assessment = assessQRUrl(qrData);

  const colors = {
    CRITICAL: { bg:'#ff4444', text:'#fff', icon:'🚨' },
    HIGH:     { bg:'#f97316', text:'#fff', icon:'⚠️' },
    MEDIUM:   { bg:'#eab308', text:'#000', icon:'🔶' },
    INFO:     { bg:'#3b82f6', text:'#fff', icon:'📱' }
  };

  const level  = assessment.level;
  const c      = colors[level] || colors.INFO;

  // Create overlay container — positioned relative to the image
  const wrapper = document.createElement('div');
  wrapper.setAttribute('data-dg-qr', '1');
  Object.assign(wrapper.style, {
    position:   'relative',
    display:    'inline-block',
    maxWidth:   '100%'
  });

  // Badge button
  const badge = document.createElement('button');
  badge.innerHTML = `${c.icon} QR ${level}`;
  Object.assign(badge.style, {
    position:      'absolute',
    top:           '6px',
    left:          '6px',
    zIndex:        '9999',
    background:    c.bg,
    color:         c.text,
    border:        'none',
    borderRadius:  '6px',
    padding:       '4px 10px',
    fontSize:      '11px',
    fontWeight:    '700',
    fontFamily:    'Arial, sans-serif',
    cursor:        'pointer',
    boxShadow:     '0 2px 8px rgba(0,0,0,0.3)',
    whiteSpace:    'nowrap'
  });

  // Panel (shown on click)
  const panel = document.createElement('div');
  Object.assign(panel.style, {
    display:     'none',
    position:    'absolute',
    top:         '34px',
    left:        '6px',
    zIndex:      '9999',
    background:  '#0d1117',
    border:      `2px solid ${c.bg}`,
    borderRadius:'8px',
    padding:     '12px 14px',
    fontSize:    '12px',
    fontFamily:  'monospace',
    color:       '#e6edf3',
    maxWidth:    '360px',
    width:       'max-content',
    boxShadow:   '0 4px 20px rgba(0,0,0,0.5)',
    lineHeight:  '1.6',
    wordBreak:   'break-all'
  });

  panel.innerHTML = `
    <div style="font-weight:700;color:${c.bg};margin-bottom:8px;font-size:13px">
      ${c.icon} QR Code Scanned by DownloadGuard
    </div>
    <div style="color:#8b949e;font-size:10px;margin-bottom:2px">QR DESTINATION</div>
    <div style="color:#58a6ff;margin-bottom:8px;font-size:11px">${escHtml(qrData)}</div>
    ${assessment.reason ? `
      <div style="background:rgba(255,68,68,0.1);border:1px solid ${c.bg};border-radius:6px;padding:8px;margin-bottom:8px;font-size:11px;color:${c.bg}">
        🛡️ ${escHtml(assessment.reason)}
      </div>
    ` : ''}
    <div style="color:#8b949e;font-size:10px;margin-bottom:4px">RECOMMENDATION</div>
    <div style="color:#e6edf3;font-size:11px">${escHtml(assessment.recommendation)}</div>
    <div style="display:flex;gap:8px;margin-top:10px">
      ${qrData.startsWith('http') ? `
        <button onclick="navigator.clipboard.writeText('${escHtml(qrData)}');this.textContent='Copied!';setTimeout(()=>this.textContent='Copy URL',1500)"
          style="background:#21262d;color:#e6edf3;border:1px solid #30363d;border-radius:6px;padding:4px 10px;font-size:11px;cursor:pointer;font-family:monospace">
          Copy URL
        </button>
      ` : ''}
      <button onclick="this.closest('[data-dg-qr-panel]').style.display='none'"
        style="background:#21262d;color:#8b949e;border:1px solid #30363d;border-radius:6px;padding:4px 10px;font-size:11px;cursor:pointer;font-family:monospace">
        Close
      </button>
    </div>
  `;
  panel.setAttribute('data-dg-qr-panel', '1');

  badge.addEventListener('click', (e) => {
    e.stopPropagation();
    panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
  });

  document.addEventListener('click', () => { panel.style.display = 'none'; }, { once: false });

  // Wrap the image
  img.parentNode.insertBefore(wrapper, img);
  wrapper.appendChild(img);
  wrapper.appendChild(badge);
  wrapper.appendChild(panel);
}

// ---------------------------------------------------------------------------
// ASSESS QR URL for phishing/spam
// ---------------------------------------------------------------------------
function assessQRUrl(data) {
  // Non-URL QR codes (vCard, WiFi, text etc.)
  if (!data.startsWith('http://') && !data.startsWith('https://')) {
    return {
      level: 'INFO',
      reason: null,
      recommendation: `This QR code contains non-URL data: "${data.substring(0, 80)}"`
    };
  }

  let domain;
  try {
    domain = new URL(data).hostname.toLowerCase().replace(/^www\./,'');
  } catch(e) {
    return { level: 'HIGH', reason: 'QR code contains an invalid URL', recommendation: 'Do not scan this QR code with your phone.' };
  }

  // HTTP (not HTTPS) is always suspicious
  if (data.startsWith('http://')) {
    return {
      level: 'HIGH',
      reason: 'QR code leads to an unencrypted HTTP page — credentials could be intercepted',
      recommendation: 'Do not enter any personal information on HTTP pages. Verify this link before visiting.'
    };
  }

  // Check against known brand spoofing
  const BRANDS = [
    { name:'Google',    official:['google.com','gmail.com','youtube.com'] },
    { name:'Microsoft', official:['microsoft.com','outlook.com','live.com','office.com'] },
    { name:'Apple',     official:['apple.com','icloud.com'] },
    { name:'PayPal',    official:['paypal.com','paypal.co.uk'] },
    { name:'Amazon',    official:['amazon.com','amazon.co.uk'] },
    { name:'Netflix',   official:['netflix.com'] },
    { name:'HMRC',      official:['hmrc.gov.uk','gov.uk'] },
    { name:'IRS',       official:['irs.gov'] },
    { name:'Barclays',  official:['barclays.com','barclays.co.uk'] },
    { name:'HSBC',      official:['hsbc.com','hsbc.co.uk'] },
  ];

  const normBase = domain.split('.')[0].replace(/[@413057$96]/g,c=>({'@':'a',4:'a',3:'e',1:'i',0:'o',5:'s',7:'t',9:'g',6:'b'}[c]||c));

  for (const brand of BRANDS) {
    const isOfficial = brand.official.some(d => domain === d || domain.endsWith('.'+d));
    if (isOfficial) continue;

    for (const off of brand.official) {
      const offBase = off.split('.')[0];
      // Edit distance
      const m=normBase.length,n=offBase.length;
      const dp=Array.from({length:m+1},(_,i)=>Array.from({length:n+1},(_,j)=>i===0?j:j===0?i:0));
      for(let i=1;i<=m;i++)for(let j=1;j<=n;j++)dp[i][j]=normBase[i-1]===offBase[j-1]?dp[i-1][j-1]:1+Math.min(dp[i-1][j],dp[i][j-1],dp[i-1][j-1]);
      const dist=dp[m][n];

      if (dist<=2 && normBase.length>=4 && dist>0) {
        return {
          level: 'CRITICAL',
          reason: `QR code leads to "${domain}" — appears to spoof ${brand.name} (official: ${off}). This is a QUISHING attack.`,
          recommendation: 'Do NOT scan this QR code with your phone. Report this email as phishing immediately.'
        };
      }
      if (domain.includes(offBase) || domain.includes(brand.name.toLowerCase().replace(/\s/g,''))) {
        return {
          level: 'HIGH',
          reason: `QR code domain "${domain}" uses the ${brand.name} brand name but is not an official ${brand.name} domain`,
          recommendation: 'Verify this QR code destination carefully before scanning with your phone.'
        };
      }
    }
  }

  // Suspicious patterns
  if (/[-_](secure|login|verify|account|update|confirm|auth|sign.?in)/.test(domain)) {
    return {
      level: 'MEDIUM',
      reason: `QR code destination "${domain}" contains suspicious keywords commonly used in phishing`,
      recommendation: 'Be cautious. Verify this destination before scanning with your phone.'
    };
  }

  // Newly registered / short domains with numbers (common in phishing)
  if (/[a-z]+[0-9]{2,}[a-z]*\.[a-z]{2,4}$/.test(domain)) {
    return {
      level: 'MEDIUM',
      reason: `Domain "${domain}" uses a pattern common in freshly registered phishing domains`,
      recommendation: 'Treat with caution. Verify the sender before scanning.'
    };
  }

  return {
    level: 'INFO',
    reason: null,
    recommendation: 'Always verify QR code destinations before entering personal information.'
  };
}

function escHtml(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ---------------------------------------------------------------------------
// SCAN ALL IMAGES ON PAGE
// ---------------------------------------------------------------------------
function scanAllImages() {
  const images = document.querySelectorAll('img:not([data-dg-scanned])');
  images.forEach(img => {
    if (img.complete && img.naturalWidth > 0) {
      scanImageForQR(img);
    } else {
      img.addEventListener('load', () => scanImageForQR(img), { once: true });
    }
  });
}

// ---------------------------------------------------------------------------
// OBSERVE DOM FOR NEW IMAGES (Gmail/Outlook load images dynamically)
// ---------------------------------------------------------------------------
let scanDebounce = null;
const imageObserver = new MutationObserver(() => {
  clearTimeout(scanDebounce);
  scanDebounce = setTimeout(scanAllImages, 1000);
});

imageObserver.observe(document.body, { childList: true, subtree: true });

// Initial scan after page settles
setTimeout(scanAllImages, 2000);

console.log('[DownloadGuard] QR scanner active');
