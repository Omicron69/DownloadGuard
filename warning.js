// =============================================================================
// DownloadGuard - warning.js
// Handles the warning page UI, user decisions, and VirusTotal scan results.
// =============================================================================

let currentData = null;

// ---------------------------------------------------------------------------
// INIT: Load threat data when page opens
// ---------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', async () => {
  const params = new URLSearchParams(window.location.search);
  const downloadId = parseInt(params.get('id'));

  if (!downloadId) {
    showError('Invalid warning page — no download ID found.');
    return;
  }

  // Request the threat data from the background service worker
  chrome.runtime.sendMessage(
    { action: 'GET_WARNING_DATA', downloadId },
    (response) => {
      if (chrome.runtime.lastError || !response?.data) {
        showError('Could not load threat data. The download may have already completed.');
        return;
      }
      renderWarning(response.data);
    }
  );

  // Restore saved API key if user entered one before
  const saved = await chrome.storage.local.get('dg_vt_api_key');
  if (saved.dg_vt_api_key) {
    document.getElementById('apiKeyInput').value = saved.dg_vt_api_key;
  }
});

// ---------------------------------------------------------------------------
// RENDER: Populate the warning page with threat intelligence
// ---------------------------------------------------------------------------
function renderWarning(data) {
  currentData = data;
  document.getElementById('loadingState').style.display = 'none';
  document.getElementById('mainContent').style.display = 'block';

  // Configure the alert banner based on threat level
  const banner = document.getElementById('alertBanner');
  const icon = document.getElementById('alertIcon');
  const title = document.getElementById('alertTitle');
  const subtitle = document.getElementById('alertSubtitle');

  if (data.isMasquerading) {
    banner.className = 'alert-banner';
    icon.textContent = '🚨';
    title.textContent = 'STOP — This file is disguising itself';
    subtitle.textContent = 'The link promised one file type but delivered a potentially malicious executable. This is a known attack technique called file masquerading.';
  } else if (data.threatLevel === 'HIGH') {
    banner.className = 'alert-banner HIGH';
    icon.textContent = '⚠️';
    title.textContent = 'Warning — Dangerous File Type Detected';
    subtitle.textContent = `This download is a ${data.actualExt} file — an executable that can run code on your computer.`;
  } else {
    banner.className = 'alert-banner MEDIUM';
    icon.textContent = '⚠️';
    title.textContent = 'Caution — Potentially Dangerous File';
    subtitle.textContent = `This file type (${data.actualExt}) can execute code on your system.`;
  }

  // Show masquerading details if applicable
  if (data.isMasquerading && data.impliedExt) {
    document.getElementById('masqBox').style.display = 'block';
    document.getElementById('impliedExt').textContent = data.impliedExt.toUpperCase() + ' (e.g., a video/document)';
    document.getElementById('actualExt').textContent = data.actualExt.toUpperCase() + ' (executable file)';
  }

  // Populate info grid
  document.getElementById('infoFilename').textContent = data.filename || 'Unknown';
  document.getElementById('infoExt').textContent =
    data.actualExt.toUpperCase() + ' — ' + describeExtension(data.actualExt);
  document.getElementById('infoUrl').textContent = truncateUrl(data.url, 80);
}

// ---------------------------------------------------------------------------
// VIRUSTOTAL: Initiate scan
// ---------------------------------------------------------------------------
async function startVTScan() {
  const apiKey = document.getElementById('apiKeyInput').value.trim();
  if (!apiKey) {
    showVTError('Please enter your VirusTotal API key to scan.');
    return;
  }

  // Save key locally for convenience
  await chrome.storage.local.set({ dg_vt_api_key: apiKey });

  document.getElementById('scanBtn').disabled = true;
  document.getElementById('vtSpinner').style.display = 'block';
  document.getElementById('vtError').style.display = 'none';
  document.getElementById('vtResults').style.display = 'none';

  chrome.runtime.sendMessage(
    { action: 'SCAN_VIRUSTOTAL', url: currentData.url, apiKey },
    (response) => {
      document.getElementById('vtSpinner').style.display = 'none';
      document.getElementById('scanBtn').disabled = false;

      if (chrome.runtime.lastError || !response?.success) {
        showVTError(response?.error || 'Scan failed. Please check your API key and try again.');
        return;
      }

      renderVTResults(response.result);
    }
  );
}

// ---------------------------------------------------------------------------
// VIRUSTOTAL: Render scan results
// ---------------------------------------------------------------------------
function renderVTResults(result) {
  const container = document.getElementById('vtResults');
  container.style.display = 'block';

  const isMalicious = result.malicious > 0;
  const isSuspicious = result.suspicious > 0;

  let scoreClass = 'safe';
  if (result.malicious > 5) scoreClass = 'danger';
  else if (result.malicious > 0 || result.suspicious > 0) scoreClass = 'warn';

  let html = `
    <div class="vt-score-row">
      <div class="vt-score-big ${scoreClass}">${result.malicious}/${result.total}</div>
      <div>
        <div class="vt-score-label">
          <strong>Security engines flagged this URL as malicious</strong>
        </div>
        <div class="vt-score-label">
          Out of ${result.total} engines scanned
        </div>
      </div>
    </div>

    <div class="stat-pills">
      <span class="stat-pill pill-red">🔴 Malicious: ${result.malicious}</span>
      <span class="stat-pill pill-orange">🟠 Suspicious: ${result.suspicious}</span>
      <span class="stat-pill pill-green">🟢 Harmless: ${result.harmless}</span>
      <span class="stat-pill pill-grey">⚪ Undetected: ${result.undetected}</span>
    </div>
  `;

  if (isMalicious && result.flaggedBy.length > 0) {
    html += `
      <div class="flagged-list">
        <div class="flagged-list-title">🚨 Flagged by these engines</div>
        ${result.flaggedBy.map(f => `
          <div class="flagged-engine">
            <span>${f.engine}</span>
            <span class="engine-verdict">${f.verdict || 'Malicious'}</span>
          </div>
        `).join('')}
      </div>
    `;
  } else if (!isMalicious && !isSuspicious) {
    html += `
      <div class="vt-clean">
        ✅ No engines flagged this URL as malicious.
        Note: A clean result does not guarantee safety — novel malware may not yet be in databases.
      </div>
    `;
  }

  html += `
    <div style="margin-top:12px; font-size:12px; color:#8892a4;">
      <a href="${result.vtLink}" target="_blank" style="color:#394f9c;">
        🔗 View full report on VirusTotal →
      </a>
    </div>
  `;

  container.innerHTML = html;
}

// ---------------------------------------------------------------------------
// USER DECISIONS
// ---------------------------------------------------------------------------
function cancelDownload() {
  if (!currentData) return;
  chrome.runtime.sendMessage(
    { action: 'CANCEL_DOWNLOAD', downloadId: currentData.downloadId },
    () => {
      document.body.innerHTML = `
        <div style="text-align:center; padding:80px 20px; font-family:Arial,sans-serif;">
          <div style="font-size:48px; margin-bottom:16px;">✅</div>
          <div style="font-size:22px; font-weight:700; color:#1a2340; margin-bottom:8px;">Download Cancelled</div>
          <div style="font-size:14px; color:#8892a4;">DownloadGuard blocked the suspicious file. You can close this tab.</div>
        </div>
      `;
    }
  );
}

function allowDownload() {
  if (!currentData) return;
  const confirmed = confirm(
    `Are you sure you want to proceed?\n\n` +
    `File: ${currentData.filename}\n` +
    `Type: ${currentData.actualExt.toUpperCase()}\n\n` +
    `Only continue if you are certain this file is from a trusted source.`
  );
  if (!confirmed) return;

  chrome.runtime.sendMessage(
    { action: 'RESUME_DOWNLOAD', downloadId: currentData.downloadId },
    () => {
      document.body.innerHTML = `
        <div style="text-align:center; padding:80px 20px; font-family:Arial,sans-serif;">
          <div style="font-size:48px; margin-bottom:16px;">▶️</div>
          <div style="font-size:22px; font-weight:700; color:#1a2340; margin-bottom:8px;">Download Resumed</div>
          <div style="font-size:14px; color:#8892a4;">Proceeding with download. Exercise caution with this file.</div>
        </div>
      `;
    }
  );
}

// ---------------------------------------------------------------------------
// HELPERS
// ---------------------------------------------------------------------------
function describeExtension(ext) {
  const descriptions = {
    '.exe': 'Windows Executable — can run any code on your PC',
    '.dmg': 'macOS Disk Image — can install software',
    '.msi': 'Windows Installer — installs software silently',
    '.bat': 'Batch Script — executes system commands',
    '.cmd': 'Command Script — executes system commands',
    '.ps1': 'PowerShell Script — powerful system access',
    '.vbs': 'VBScript — can modify system settings',
    '.jar': 'Java Archive — executes if Java is installed',
    '.sh':  'Shell Script — executes on Mac/Linux',
    '.scr': 'Screensaver file — runs as executable',
    '.hta': 'HTML Application — elevated privileges',
    '.reg': 'Registry File — modifies Windows settings'
  };
  return descriptions[ext] || 'Executable file type';
}

function truncateUrl(url, maxLen) {
  if (!url) return '—';
  return url.length > maxLen ? url.substring(0, maxLen) + '...' : url;
}

function showError(msg) {
  document.getElementById('loadingState').innerHTML =
    `<div style="color:#e74c3c; font-size:14px;">⚠️ ${msg}</div>`;
}

function showVTError(msg) {
  const el = document.getElementById('vtError');
  el.style.display = 'block';
  el.textContent = '⚠️ ' + msg;
}
