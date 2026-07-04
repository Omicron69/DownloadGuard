# 🛡️ DownloadGuard

**CI7526 — Cyber and Artificial Intelligence (Applications)**  
**Kingston University London | May 2026**  
**Assessment: Agentic AI for Cyber Security**

---

## Overview

DownloadGuard is a Chrome extension built as a security artefact for CI7526. It provides real-time, multi-layer protection against the most common browser-based cyber threats facing everyday users — malicious file downloads, phishing emails, deceptive hyperlinks, and QR code phishing attacks.

The artefact was produced using **agentic AI co-production** (Claude Sonnet 4.6, Anthropic) and integrates two external AI/security APIs alongside a local keyword detection engine.

---

## Features

### 1. 🚨 Malicious Download Detection

Monitors every file download in Chrome in real time. When a dangerous file type is detected the download is **immediately paused** before it reaches the filesystem, giving the user time to investigate.

**Dangerous extensions monitored:**

| Extension | Platform | Risk |
|-----------|----------|------|
| `.exe` | Windows | Standard executable — highest risk |
| `.dmg` | macOS | Disk image — can silently install software |
| `.msi` | Windows | Windows Installer — elevated privilege installation |
| `.bat` / `.cmd` | Windows | Batch/command scripts — executes system commands |
| `.ps1` | Windows | PowerShell — deep system access |
| `.vbs` | Windows | VBScript — system manipulation |
| `.jar` | Cross-platform | Java executable |
| `.sh` | Mac/Linux | Shell script |
| `.scr` | Windows | Screensaver — runs as executable |
| `.hta` | Windows | HTML Application — elevated privileges |
| `.reg` | Windows | Registry file — modifies Windows settings |
| `.pif` / `.com` | Windows | Legacy executables |

---

### 2. 🔴 File Masquerading Detection

Detects the **double extension attack** — where an attacker renames a malicious executable to appear as a harmless file:

```
movie.mp4.exe      → displayed as movie.mp4 by Windows
invoice.pdf.bat    → displayed as invoice.pdf
holiday_photo.jpg.msi → displayed as holiday_photo.jpg
```

DownloadGuard compares:
- The **implied extension** from the filename and download URL (e.g. `.mp4`)
- The **actual extension** of the downloaded file (e.g. `.exe`)

A mismatch triggers a **CRITICAL** warning with explicit explanation of the deception technique.

**This directly mirrors real-world campaigns** including SocGholish/FakeUpdates, COVID-era malware lures, and trojanised media downloads documented by Kaspersky (2020) and Krebs on Security (2021).

---

### 3. 🔬 VirusTotal Integration

When a dangerous download is detected, the user can scan the download URL against **70+ antivirus engines** via the VirusTotal API v3.

**How it works:**
1. User clicks **Scan with VirusTotal** on the warning page
2. Extension submits the URL to `api.virustotal.com/v3/urls`
3. Polls for analysis completion (up to 30 seconds)
4. Displays engine-by-engine results — how many flagged it and what verdict each gave
5. Provides a direct link to the full VirusTotal report

**Limitation acknowledged:** A 0/70 clean result does not guarantee safety — novel malware with no prior database entry will return clean. This reflects a genuine gap in signature-based detection discussed in Section 4 of the accompanying article.

---

### 4. 🤖 Gemini AI Phishing Detection

When the user opens an email in **Gmail or Outlook**, DownloadGuard can analyse the email content using the **Gemini 1.5 Flash API** for deep phishing and social engineering detection.

**What Gemini analyses:**
- Sender domain mismatch vs claimed identity
- Urgency and fear language
- Credential or payment requests
- Brand impersonation
- Suspicious link destinations
- Grammar and legitimacy signals

**Output:** A structured risk assessment with score (0–100), risk level (LOW / MEDIUM / HIGH / CRITICAL), individual indicators, verdict, and recommendation.

**Design decision:** Gemini is only called for MEDIUM/ambiguous emails. CRITICAL and HIGH results from the local keyword scan are returned immediately without an API call, preserving free tier quota.

---

### 5. 🔑 Local Keyword Spam & Phishing Scanner

A fully offline, zero-API-cost scanner that runs **before** Gemini as the first line of defence. Contains **150+ curated phrases** across three severity tiers.

**Coverage:**

| Tier | Example phrases | Score |
|------|----------------|-------|
| CRITICAL | "verify your password", "your account will be deleted", "enable macros to view" | 100 |
| HIGH | "act immediately", "you have won", "click here to verify", "within 24 hours" | 40 each |
| MEDIUM | "limited time offer", "dear friend", "bitcoin investment", "lose weight fast" | 20 each |

**Additional checks:**
- **Domain spoofing:** detects when sender email claims to be a known brand but uses a different domain
- **Character substitution:** flags `g00gle`, `paypa1`, `m1crosoft` style domains
- **Formatting signals:** excessive `!!!`, ALL CAPS sections
- **Suspicious URL patterns:** `-secure`, `-login`, `-verify` in domain names

---

### 6. 🏢 Corporate Brand Spoofing Database

**200+ major corporations** across 10 sectors with their official email domains. Used by both the spam scanner and the link preview feature.

**Sectors covered:**

| Sector | Example brands |
|--------|---------------|
| Technology | Google, Microsoft, Apple, Amazon, Meta, Netflix, PayPal, Adobe, Salesforce, Stripe, Shopify |
| Banking | HSBC, Barclays, NatWest, Lloyds, Chase, Bank of America, Monzo, Revolut, Wise |
| Insurance | Aviva, AXA, Zurich, Allianz, Legal & General, Bupa |
| Retail | Amazon, eBay, ASOS, IKEA, Tesco, Marks & Spencer, John Lewis |
| Delivery | DHL, FedEx, UPS, Royal Mail, Evri, ParcelForce |
| Telecoms | AT&T, Verizon, Vodafone, O2, EE, BT, Sky, Virgin Media |
| Government | HMRC, IRS, DVLA, DWP, NHS, Companies House |
| Travel | British Airways, Ryanair, easyJet, Booking.com, Expedia |
| Streaming | Netflix, Disney+, Spotify, HBO Max, Prime Video |
| Healthcare | NHS, Pfizer, AstraZeneca, GSK, Boots |

**Spoofing detection methods:**

1. **Levenshtein distance** — edit distance ≤ 2 from official domain flags as spoof
2. **Homoglyph normalisation** — converts `0→o`, `1→i`, `3→e`, `@→a` before comparison
3. **Brand keyword injection** — `paypal-security.com` contains PayPal brand but is not official

---

### 7. 🔗 Link Hover Preview

Runs on **all websites** including Gmail and Outlook. Hovering over any hyperlink reveals a tooltip showing the **real destination URL** — not the display text.

**Catches:**
- Display text mismatch: link says `www.paypal.com` but leads to `paypa1-secure.net`
- Brand spoofing in link destinations using the 200-brand database
- URL shorteners (`bit.ly`, `tinyurl.com`) that hide true destinations
- Suspicious domain patterns (`-verify`, `-secure`, `-login`)

**No API calls required** — runs entirely locally with instant response.

**Example tooltip output:**
```
🚨 DownloadGuard · CRITICAL

REAL URL
paypa1-secure.net/login

DISPLAY TEXT
www.paypal.com/login

⚠️ Display text doesn't match destination URL
🛡️ "paypa1-secure.net" appears to spoof PayPal (edit distance 1)
```

---

### 8. 📱 QR Code Scanner (Anti-Quishing)

Automatically scans all images in Gmail and Outlook emails for embedded QR codes. This defends against **quishing** — QR code phishing — a 2024/25 attack vector that bypasses most email security tools because they scan text, not image content.

**How it works:**
1. Detects `<img>` elements in email content
2. Draws each image to an HTML5 Canvas
3. Extracts pixel data and passes it to **jsQR** (open-source QR decoder)
4. If a QR code is found, decodes the embedded URL
5. Runs the URL through the brand spoofing database
6. Injects a colour-coded badge on the image

**Risk levels for QR codes:**
| Level | Trigger |
|-------|---------|
| CRITICAL | QR destination spoofs a known brand (edit distance ≤ 2) |
| HIGH | QR destination uses brand name in non-official domain |
| HIGH | QR leads to `http://` (unencrypted) |
| MEDIUM | Suspicious keyword patterns in destination domain |
| INFO | Non-URL QR content (WiFi, vCard, plain text) |

**Why this matters:** Enterprise email security tools including Proofpoint and Mimecast only added anti-quishing capabilities in 2023–2024. DownloadGuard implements the same core technique — image content inspection — at the browser level.

---

## Installation

### Requirements (Optional)
- Google Chrome (version 88 or later)
- A free **Gemini API key** from [aistudio.google.com](https://aistudio.google.com)
- A free **VirusTotal API key** from [virustotal.com](https://www.virustotal.com)

### Steps

1. Download and unzip `DownloadGuard_v3.zip`
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable **Developer Mode** (toggle in top-right corner)
4. Click **Load unpacked** and select the `downloadguard/` folder
5. The 🛡️ shield icon will appear in the Chrome toolbar
6. Click the icon to open the popup
7. Paste your **Gemini API key** and click **Save & Test**
8. Paste your **VirusTotal API key** and click **Save & Test**
9. Both should show `✅ Working` confirmation

---

## Usage

### Download Protection
- Runs automatically on all downloads — no setup required
- If a dangerous file is detected, a warning page opens automatically
- Choose **Cancel Download** (recommended) or **Proceed Anyway**
- Use the VirusTotal scan button to check the URL against 70+ engines

### Email Phishing Detection (Gmail / Outlook)
1. Navigate to Gmail or Outlook in Chrome
2. Click the 🛡️ icon in the toolbar
3. Click **Allow** next to the detected email site
4. Open any email
5. Click **🔍 Scan Current Email Now** in the popup
6. Results appear as a banner above the email and in the popup

### Link Hover Preview
- Works automatically on all websites once the extension is installed
- Hover over any hyperlink to see the real destination URL
- Tooltip appears automatically — no clicks required
- RED tooltip = suspicious, GREEN = appears safe

### QR Code Scanner
- Works automatically in Gmail and Outlook once Allow is clicked
- Any QR code found in an email image gets a coloured badge
- Click the badge to see the decoded URL and risk assessment

---

## File Structure

```
downloadguard/
├── manifest.json       — Extension configuration (Manifest V3)
├── background.js       — Service worker: download monitoring, API calls,
│                         spam detection engine, VirusTotal, Gemini
├── content.js          — Gmail/Outlook email extraction and analysis trigger
├── content.css         — Styles for Gmail/Outlook phishing banner
├── linkpreview.js      — Link hover preview (runs on all sites)
├── qrscanner.js        — QR code detection and quishing protection
├── jsqr.js             — jsQR library (QR code decoding)
├── spamdetector.js     — Local keyword scanner + 200-brand database
├── popup.html          — Extension toolbar popup UI
├── popup.js            — Popup logic and API key management
├── warning.html        — Download warning page UI
├── warning.js          — Warning page logic and VT result rendering
├── debug.html          — Debug console for testing and diagnostics
└── icons/
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    CHROME BROWSER                        │
│                                                          │
│  ┌─────────────┐    ┌──────────────────────────────┐   │
│  │ background  │    │      CONTENT SCRIPTS          │   │
│  │  .js        │    │                               │   │
│  │             │    │  content.js   → Gmail/Outlook │   │
│  │ Downloads   │    │  linkpreview  → All sites     │   │
│  │ monitoring  │    │  qrscanner    → Gmail/Outlook │   │
│  │             │    │  jsqr         → QR decoding   │   │
│  │ Gemini API  │    └──────────────┬───────────────┘   │
│  │ VT API      │                   │ messages           │
│  │ Spam scan   │◄──────────────────┘                    │
│  └──────┬──────┘                                        │
│         │                                               │
│  ┌──────▼──────┐    ┌──────────────┐                   │
│  │ warning.html│    │  popup.html  │                    │
│  │ (new tab)   │    │  (toolbar)   │                    │
│  └─────────────┘    └──────────────┘                    │
└─────────────────────────────────────────────────────────┘
         │                    │
         ▼                    ▼
  VirusTotal API        Gemini 1.5 Flash API
  (file/URL scanning)  (phishing analysis)
```

---


## Limitations

- **Download detection:** Cannot inspect file content — only filename and URL. A malicious `.pdf` with an embedded exploit will not be caught.
- **Fast downloads:** Very rapid downloads (under 1 second) may complete before the extension can pause them.
- **VirusTotal:** Returns 0/70 for novel malware with no prior database entry — a fundamental limitation of signature-based detection.
- **QR scanner:** Cannot read QR codes from CORS-restricted external images (images served without cross-origin headers).
- **Gemini:** Subject to free tier rate limits (15 requests/minute on Gemini 1.5 Flash). Falls back to local keyword scan automatically.
- **Gmail DOM:** Gmail's class names are dynamically generated and may change with Gmail updates — the extension uses structural detection (`[role="main"]`, `h2`, `[email]` attributes) to mitigate this.
- **Encrypted email content:** Cannot analyse end-to-end encrypted emails where content is not rendered in the DOM.

---

## Future Development

- **Header analysis:** Inspect SPF, DKIM, and DMARC records via a backend proxy to detect email spoofing at the protocol level
- **File content inspection:** Use the File System Access API to scan downloaded files against magic byte signatures before execution
- **WebSocket persistence:** Maintain service worker alive to prevent missed downloads during Chrome's 5-minute service worker sleep
- **Database persistence:** Store threat history across sessions using IndexedDB for longitudinal analysis
- **Real-time QR scanning:** Extend QR detection to all websites, not just email clients

---






*DownloadGuard v3.2 | CI7526 Agentic AI for Cyber Security | Kingston University London 2026*
