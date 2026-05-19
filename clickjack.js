// =============================================================================
// DownloadGuard - clickjack.js
// Invisible Clickjacking Trap Exposer — Active Intrusion Prevention System (IPS)
//
// Security Rationale:
// High-risk piracy and streaming sites routinely inject transparent overlay
// elements (div, iframe, a) positioned above legitimate content. When the user
// clicks what they believe is the video player's play button, their click is
// silently intercepted by the invisible overlay, triggering a pop-under
// redirect to a drive-by download page or malicious ad network.
//
// This IPS actively scans the DOM, identifies elements matching the CSS
// signature of a clickjacking trap, visually exposes them to the user,
// and defuses them by applying `pointer-events: none !important` — allowing
// the user's click to pass through to the legitimate element beneath.
//
// Architecture note: Follows the same modular pattern as adwall.js —
// a detection function, a MutationObserver with debounce, and an initial
// deferred scan after document_idle.
// =============================================================================

// ---------------------------------------------------------------------------
// IPS DETECTION THRESHOLDS
// These values define the CSS signature of a clickjacking trap.
// They are tuned to match real-world piracy site overlay patterns while
// minimising false positives on legitimate UI components (modals, dropdowns).
// ---------------------------------------------------------------------------
const IPS_CONFIG = {
  // z-index floor: legitimate in-page UI rarely exceeds 100.
  // Clickjacking overlays are typically set to 9999 or higher to guarantee
  // they sit above all page content. We use 50 as a conservative floor.
  MIN_Z_INDEX:    50,

  // Minimum clickable area: traps must be large enough to intercept a
  // meaningful click. We require at least 200x100px — small elements
  // like dropdowns or tooltips are excluded by this guard.
  MIN_WIDTH_PX:   200,
  MIN_HEIGHT_PX:  100,

  // The custom data attribute stamped onto processed elements.
  // Matching adwall.js convention of data-dg-* namespace.
  PROCESSED_ATTR: 'data-dg-trap-exposed',

  // Debounce delay for the MutationObserver (ms).
  // Mirrors the 1500ms debounce used in adwall.js's badgeAdWallLinks observer.
  DEBOUNCE_MS:    1500,
};

// ---------------------------------------------------------------------------
// SESSION TELEMETRY
// Tracks how many traps have been exposed this page session.
// Accessible to the debug panel via window.__dgIpsStats().
// ---------------------------------------------------------------------------
let _ipsExposedCount = 0;

// ---------------------------------------------------------------------------
// exposeInvisibleTraps()
//
// Core IPS detection and neutralisation function.
// Queries all div, iframe, and a elements — the three tag types that piracy
// sites use as clickjacking vectors — and tests each against the trap
// CSS signature using window.getComputedStyle() to catch styles applied
// via external stylesheets (which inline-style checks would miss).
// ---------------------------------------------------------------------------
function exposeInvisibleTraps() {

  // Restrict scan to the three element types used as clickjacking vectors.
  // Using a targeted selector is more performant than walking the full DOM
  // tree on heavy piracy site pages that may contain thousands of nodes.
  const candidates = document.querySelectorAll(
    'div:not([' + IPS_CONFIG.PROCESSED_ATTR + ']), ' +
    'iframe:not([' + IPS_CONFIG.PROCESSED_ATTR + ']), ' +
    'a:not([' + IPS_CONFIG.PROCESSED_ATTR + '])'
  );

  candidates.forEach(el => _evaluateElement(el));
}

// ---------------------------------------------------------------------------
// _evaluateElement(el)
//
// Evaluates a single element against the clickjacking trap CSS signature.
// Uses window.getComputedStyle() to resolve styles applied by external
// stylesheets — critical because piracy sites inject overlays via CSS
// classes, not inline styles, to evade naive inline-style checks.
// ---------------------------------------------------------------------------
function _evaluateElement(el) {

  // Guard: skip elements already processed by this IPS in this session.
  if (el.hasAttribute(IPS_CONFIG.PROCESSED_ATTR)) return;

  // Guard: skip DownloadGuard's own UI elements to avoid self-interference.
  if (el.id && el.id.startsWith('dg-')) return;

  // Retrieve the fully resolved computed style for this element.
  // getComputedStyle() resolves styles from all sources: external stylesheets,
  // <style> blocks, and inline styles — giving us the actual rendered values.
  let computed;
  try {
    computed = window.getComputedStyle(el);
  } catch (e) {
    // getComputedStyle can throw for detached or cross-origin elements.
    return;
  }

  // ── CRITERION 1: Positioning ─────────────────────────────────────────────
  // Traps must be positioned absolute or fixed to layer above page content.
  // Relative or static elements cannot intercept clicks from above.
  const position = computed.position;
  if (position !== 'absolute' && position !== 'fixed') return;

  // ── CRITERION 2: High z-index ────────────────────────────────────────────
  // The trap must sit above legitimate page content in the stacking context.
  // We use getComputedStyle to catch z-index values applied via stylesheets.
  const zIndex = parseInt(computed.zIndex, 10);
  if (isNaN(zIndex) || zIndex < IPS_CONFIG.MIN_Z_INDEX) return;

  // ── CRITERION 3: Functional invisibility ─────────────────────────────────
  // The trap must be visually invisible to deceive the user, achieved via:
  //   (a) opacity: 0 or near-zero — element rendered but transparent
  //   (b) rgba() background with alpha 0 — transparent fill, clickable area
  //   (c) visibility: hidden + pointer-events still active (less common)
  const opacity      = parseFloat(computed.opacity);
  const isOpacityInvisible = opacity === 0 || opacity === 0.01;

  const bgColor = computed.backgroundColor;
  // Parse the alpha channel from rgb() or rgba() computed values.
  // rgb() values have implicit alpha 1; rgba() may have alpha 0.
  const rgbaMatch  = bgColor.match(/rgba\(\s*[\d.]+\s*,\s*[\d.]+\s*,\s*[\d.]+\s*,\s*([\d.]+)\s*\)/);
  const bgAlpha    = rgbaMatch ? parseFloat(rgbaMatch[1]) : 1;
  const isBgTransparent = bgColor === 'transparent' || bgAlpha === 0;

  // Either opacity invisibility or transparent background qualifies.
  if (!isOpacityInvisible && !isBgTransparent) return;

  // ── CRITERION 4: Large clickable area ────────────────────────────────────
  // Traps must cover enough area to reliably intercept user interaction.
  // getBoundingClientRect() returns the actual rendered size, accounting for
  // CSS transforms, which getComputedStyle width/height does not.
  let rect;
  try {
    rect = el.getBoundingClientRect();
  } catch (e) {
    return;
  }

  if (rect.width < IPS_CONFIG.MIN_WIDTH_PX) return;
  if (rect.height < IPS_CONFIG.MIN_HEIGHT_PX) return;

  // ── CRITERION 5: Pointer events are active ───────────────────────────────
  // An element with pointer-events: none cannot intercept clicks and is
  // therefore not a threat. This also prevents re-processing our own
  // neutralised elements if the PROCESSED_ATTR guard fails.
  if (computed.pointerEvents === 'none') return;

  // ── All criteria met — this element is a clickjacking trap ───────────────
  _neutraliseTrap(el, zIndex, rect);
}

// ---------------------------------------------------------------------------
// _neutraliseTrap(el, zIndex, rect)
//
// Neutralises a confirmed clickjacking trap and exposes it to the user.
//
// Neutralisation strategy:
//   1. Stamp PROCESSED_ATTR immediately to prevent double-processing.
//   2. Apply pointer-events: none !important — the core defuse action.
//      This allows the user's click to fall through to the element beneath.
//   3. Override visual styles with !important to beat site stylesheet
//      specificity — expose the trap so the user can see what was blocked.
//   4. If the element is a div, inject a centered text warning label.
//   5. Log the event to the session telemetry and browser console.
// ---------------------------------------------------------------------------
function _neutraliseTrap(el, zIndex, rect) {

  // Stamp the element as processed immediately to prevent the MutationObserver
  // from re-queuing it if a style attribute change triggers a mutation event.
  el.setAttribute(IPS_CONFIG.PROCESSED_ATTR, '1');

  // ── Step 1: Defuse — disable click interception ──────────────────────────
  // pointer-events: none causes the element to be ignored for all mouse events.
  // The user's click will now pass through to the legitimate element beneath.
  // We use setAttribute on the style to inject !important, which cannot be
  // set via the el.style property API.
  const currentStyle = el.getAttribute('style') || '';
  el.setAttribute('style',
    currentStyle +
    '; pointer-events: none !important'
  );

  // ── Step 2: Expose — make the trap visible to the user ───────────────────
  // Override all invisibility properties with !important to guarantee our
  // styles win regardless of external stylesheet specificity or !important
  // declarations on the original trap styles.
  el.setAttribute('style',
    el.getAttribute('style') +
    '; background: rgba(255, 0, 0, 0.85) !important' +
    '; opacity: 1 !important' +
    '; border: 4px dashed #ffffff !important' +
    '; box-sizing: border-box !important'
  );

  // ── Step 3: Inject warning label (div elements only) ─────────────────────
  // iframes and anchor tags have content or navigation behaviour that makes
  // child injection unreliable. For divs we inject a centered text warning
  // so the user understands why a red box appeared on the page.
  if (el.tagName.toLowerCase() === 'div') {
    const label = document.createElement('p');

    // Inline all styles — no reliance on external CSS that the page might
    // override. Using !important throughout for the same reason as above.
    label.setAttribute('style', [
      'position: absolute',
      'top: 50%',
      'left: 50%',
      'transform: translate(-50%, -50%)',
      'margin: 0',
      'padding: 8px 12px',
      'background: rgba(0, 0, 0, 0.75)',
      'color: #ffffff',
      'font-family: Arial, sans-serif',
      'font-size: 13px',
      'font-weight: bold',
      'text-align: center',
      'white-space: nowrap',
      'border-radius: 4px',
      'pointer-events: none',
      'z-index: 2147483647',
    ].join(' !important; ') + ' !important');

    label.textContent = '🚨 INVISIBLE CLICK TRAP BLOCKED 🚨';

    // Ensure the parent div is relatively positioned so our absolute label
    // is contained within it. If already absolute/fixed, this is a no-op.
    if (window.getComputedStyle(el).position === 'static') {
      el.style.setProperty('position', 'relative', 'important');
    }

    try {
      el.appendChild(label);
    } catch (e) {
      // appendChild can fail on sandboxed iframes — fail silently.
    }
  }

  // ── Step 4: Telemetry and logging ─────────────────────────────────────────
  _ipsExposedCount++;

  console.log(
    '[DownloadGuard IPS] 🚨 Clickjack trap exposed and defused',
    {
      tag:      el.tagName,
      id:       el.id       || '(none)',
      class:    el.className?.toString?.()?.substring(0, 80) || '(none)',
      zIndex,
      size:     `${Math.round(rect.width)}×${Math.round(rect.height)}px`,
      position: window.getComputedStyle(el).position,
      total:    _ipsExposedCount,
    }
  );
}

// ---------------------------------------------------------------------------
// MutationObserver — Dynamic Injection Detection
//
// Security rationale:
// Piracy sites do not inject clickjacking overlays on page load. They wait
// until the user performs an action (hovers over the player, starts a video,
// scrolls to the content) before dynamically inserting the trap element via
// JavaScript. A one-time DOM scan at document_idle would miss these.
//
// We observe the entire document subtree for newly added nodes. On any
// mutation batch that includes additions, we schedule a re-scan via a
// debounced timer — matching the pattern used in adwall.js to prevent
// main-thread performance degradation on sites that fire hundreds of
// mutation events per second during video playback.
// ---------------------------------------------------------------------------
let _observerDebounce = null;

const _trapObserver = new MutationObserver(function(mutationsList) {

  // Fast-path: skip mutation batches that contain no new nodes.
  // Attribute mutations (class changes, style updates) don't introduce
  // new trap elements — only childList additions do.
  const hasAdditions = mutationsList.some(function(m) {
    return m.addedNodes.length > 0;
  });

  if (!hasAdditions) return;

  // Debounce: coalesce multiple rapid mutations into a single scan.
  // This mirrors adwall.js's 1500ms badgeDebounce pattern exactly.
  clearTimeout(_observerDebounce);
  _observerDebounce = setTimeout(exposeInvisibleTraps, IPS_CONFIG.DEBOUNCE_MS);
});

// Observe the full document subtree for child additions.
// We do not observe attribute changes here — the debounce scan covers
// any style changes because exposeInvisibleTraps re-evaluates computed styles.
_trapObserver.observe(document.documentElement, {
  childList: true,
  subtree:   true,
});

// ---------------------------------------------------------------------------
// Debug API
// Exposes session telemetry to the DownloadGuard debug.html panel.
// Consistent with the __dgClickjackStats convention already in the codebase.
// ---------------------------------------------------------------------------
window.__dgIpsStats = function() {
  return {
    exposedCount: _ipsExposedCount,
    processedAttr: IPS_CONFIG.PROCESSED_ATTR,
  };
};

// ---------------------------------------------------------------------------
// Initial Scan
//
// Deferred 1.5 seconds after document_idle to allow the page's own JavaScript
// to finish injecting initial DOM elements before we scan. A second scan at
// 4 seconds catches overlays injected by lazy-loaded ad scripts.
// Mirrors the timing pattern used in qrscanner.js (setTimeout 2000).
// ---------------------------------------------------------------------------
setTimeout(exposeInvisibleTraps, 1500);
setTimeout(exposeInvisibleTraps, 4000);

console.log('[DownloadGuard] IPS (Clickjack Trap Exposer) active');
