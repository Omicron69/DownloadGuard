// =============================================================================
// DownloadGuard - spamdetector.js v2.0
// Local keyword + corporate brand spoofing detection
// Covers 200+ major corporations across all sectors
// =============================================================================

// ---------------------------------------------------------------------------
// TOP 200 CORPORATE BRANDS + OFFICIAL DOMAINS
// Any email claiming to be from these brands but sent from a different
// domain is immediately flagged as potential phishing
// ---------------------------------------------------------------------------
const KNOWN_BRANDS = [
  // ── Technology ────────────────────────────────────────────────────────────
  { name:'Google',       domains:['google.com','gmail.com','googlemail.com','google.co.uk','google.ca','google.com.au','youtube.com','googleapis.com'] },
  { name:'Microsoft',    domains:['microsoft.com','outlook.com','hotmail.com','live.com','xbox.com','azure.com','office.com','office365.com','microsoftonline.com'] },
  { name:'Apple',        domains:['apple.com','icloud.com','me.com','mac.com'] },
  { name:'Amazon',       domains:['amazon.com','amazon.co.uk','amazon.de','amazon.fr','amazon.es','amazon.it','amazon.ca','amazon.com.au','amazonaws.com','amazonses.com'] },
  { name:'Meta',         domains:['facebook.com','meta.com','fb.com','instagram.com','whatsapp.com','messenger.com'] },
  { name:'Netflix',      domains:['netflix.com'] },
  { name:'Twitter',      domains:['twitter.com','x.com'] },
  { name:'LinkedIn',     domains:['linkedin.com'] },
  { name:'Uber',         domains:['uber.com','ubereats.com'] },
  { name:'Airbnb',       domains:['airbnb.com','airbnb.co.uk'] },
  { name:'Spotify',      domains:['spotify.com'] },
  { name:'Adobe',        domains:['adobe.com','adobecc.com'] },
  { name:'Salesforce',   domains:['salesforce.com','force.com','salesforce.org'] },
  { name:'Oracle',       domains:['oracle.com'] },
  { name:'IBM',          domains:['ibm.com'] },
  { name:'Intel',        domains:['intel.com'] },
  { name:'Samsung',      domains:['samsung.com'] },
  { name:'Sony',         domains:['sony.com'] },
  { name:'HP',           domains:['hp.com','hpe.com'] },
  { name:'Dell',         domains:['dell.com'] },
  { name:'Cisco',        domains:['cisco.com'] },
  { name:'NVIDIA',       domains:['nvidia.com'] },
  { name:'PayPal',       domains:['paypal.com','paypal.co.uk','paypal.de','paypal.fr','paypal.es'] },
  { name:'Stripe',       domains:['stripe.com'] },
  { name:'Square',       domains:['squareup.com','square.com'] },
  { name:'Shopify',      domains:['shopify.com','myshopify.com'] },
  { name:'eBay',         domains:['ebay.com','ebay.co.uk','ebay.de','ebay.fr','ebay.es','ebay.com.au'] },
  { name:'Zoom',         domains:['zoom.us','zoom.com'] },
  { name:'Slack',        domains:['slack.com'] },
  { name:'Dropbox',      domains:['dropbox.com'] },
  { name:'GitHub',       domains:['github.com','github.io'] },
  { name:'GitLab',       domains:['gitlab.com'] },
  { name:'Atlassian',    domains:['atlassian.com','jira.com','confluence.com','bitbucket.org'] },
  { name:'Twilio',       domains:['twilio.com'] },
  { name:'HubSpot',      domains:['hubspot.com'] },
  { name:'Mailchimp',    domains:['mailchimp.com','mandrill.com'] },
  { name:'Okta',         domains:['okta.com'] },
  { name:'Cloudflare',   domains:['cloudflare.com'] },
  { name:'Palo Alto Networks', domains:['paloaltonetworks.com'] },
  { name:'CrowdStrike',  domains:['crowdstrike.com'] },
  { name:'Norton',       domains:['norton.com','nortonlifelock.com'] },
  { name:'McAfee',       domains:['mcafee.com','trellix.com'] },
  { name:'Kaspersky',    domains:['kaspersky.com'] },
  { name:'Avast',        domains:['avast.com'] },
  { name:'TikTok',       domains:['tiktok.com','bytedance.com'] },
  { name:'Snapchat',     domains:['snapchat.com','snap.com'] },
  { name:'Pinterest',    domains:['pinterest.com'] },
  { name:'Reddit',       domains:['reddit.com'] },
  { name:'Discord',      domains:['discord.com','discord.gg'] },
  { name:'Twitch',       domains:['twitch.tv','amazon.com'] },
  { name:'Steam',        domains:['steampowered.com','valvesoftware.com'] },
  { name:'Epic Games',   domains:['epicgames.com'] },
  { name:'PlayStation',  domains:['playstation.com','sie.com'] },
  { name:'Xbox',         domains:['xbox.com','microsoft.com'] },
  { name:'Nintendo',     domains:['nintendo.com'] },
  { name:'Roblox',       domains:['roblox.com'] },
  { name:'WordPress',    domains:['wordpress.com','wordpress.org','automattic.com'] },
  { name:'GoDaddy',      domains:['godaddy.com'] },
  { name:'Namecheap',    domains:['namecheap.com'] },
  { name:'Wix',          domains:['wix.com'] },
  { name:'Squarespace',  domains:['squarespace.com'] },

  // ── Banking & Finance ─────────────────────────────────────────────────────
  { name:'HSBC',         domains:['hsbc.com','hsbc.co.uk','hsbc.ca','hsbc.com.hk'] },
  { name:'Barclays',     domains:['barclays.com','barclays.co.uk','barclaycard.co.uk'] },
  { name:'NatWest',      domains:['natwest.com','rbs.co.uk','ulsterbank.com'] },
  { name:'Lloyds',       domains:['lloydsbank.com','lloydstsl.com'] },
  { name:'Halifax',      domains:['halifax.co.uk'] },
  { name:'Santander',    domains:['santander.com','santander.co.uk','santanderbank.com'] },
  { name:'Chase',        domains:['chase.com','jpmchase.com'] },
  { name:'Bank of America', domains:['bankofamerica.com','bofa.com'] },
  { name:'Wells Fargo',  domains:['wellsfargo.com'] },
  { name:'Citibank',     domains:['citi.com','citibank.com','citigroup.com'] },
  { name:'JPMorgan',     domains:['jpmorgan.com','jpmchase.com'] },
  { name:'Goldman Sachs',domains:['gs.com','goldmansachs.com'] },
  { name:'American Express', domains:['americanexpress.com','aexp.com'] },
  { name:'Visa',         domains:['visa.com'] },
  { name:'Mastercard',   domains:['mastercard.com'] },
  { name:'Capital One',  domains:['capitalone.com'] },
  { name:'Discover',     domains:['discover.com','discovercard.com'] },
  { name:'TD Bank',      domains:['td.com','tdbank.com'] },
  { name:'RBC',          domains:['rbc.com','rbcroyalbank.com'] },
  { name:'Scotiabank',   domains:['scotiabank.com'] },
  { name:'ING',          domains:['ing.com','ing.nl','ing.de'] },
  { name:'Deutsche Bank',domains:['db.com','deutschebank.com'] },
  { name:'BNP Paribas',  domains:['bnpparibas.com'] },
  { name:'UBS',          domains:['ubs.com'] },
  { name:'BBVA',         domains:['bbva.com','bbva.es'] },
  { name:'Monzo',        domains:['monzo.com'] },
  { name:'Revolut',      domains:['revolut.com'] },
  { name:'Wise',         domains:['wise.com','transferwise.com'] },
  { name:'Starling',     domains:['starlingbank.com'] },
  { name:'Cash App',     domains:['cash.app','squareup.com'] },
  { name:'Venmo',        domains:['venmo.com'] },
  { name:'Klarna',       domains:['klarna.com'] },
  { name:'Afterpay',     domains:['afterpay.com'] },

  // ── Insurance ─────────────────────────────────────────────────────────────
  { name:'Aviva',        domains:['aviva.com','aviva.co.uk'] },
  { name:'AXA',          domains:['axa.com','axa.co.uk'] },
  { name:'Zurich',       domains:['zurich.com'] },
  { name:'Allianz',      domains:['allianz.com'] },
  { name:'AIG',          domains:['aig.com'] },
  { name:'MetLife',      domains:['metlife.com'] },
  { name:'Prudential',   domains:['prudential.com','prudential.co.uk'] },
  { name:'Legal & General', domains:['legalandgeneral.com'] },
  { name:'State Farm',   domains:['statefarm.com'] },
  { name:'GEICO',        domains:['geico.com'] },
  { name:'Progressive',  domains:['progressive.com'] },
  { name:'USAA',         domains:['usaa.com'] },
  { name:'Bupa',         domains:['bupa.com','bupa.co.uk'] },
  { name:'Vitality',     domains:['vitality.co.uk'] },

  // ── Retail & eCommerce ────────────────────────────────────────────────────
  { name:'Walmart',      domains:['walmart.com'] },
  { name:'Target',       domains:['target.com'] },
  { name:'Costco',       domains:['costco.com'] },
  { name:'Best Buy',     domains:['bestbuy.com'] },
  { name:'IKEA',         domains:['ikea.com'] },
  { name:'H&M',          domains:['hm.com'] },
  { name:'Zara',         domains:['zara.com','inditex.com'] },
  { name:'Nike',         domains:['nike.com'] },
  { name:'Adidas',       domains:['adidas.com'] },
  { name:'ASOS',         domains:['asos.com'] },
  { name:'Etsy',         domains:['etsy.com'] },
  { name:'Wish',         domains:['wish.com','contextlogic.com'] },
  { name:'AliExpress',   domains:['aliexpress.com','alibaba.com'] },
  { name:'Wayfair',      domains:['wayfair.com'] },
  { name:'Chewy',        domains:['chewy.com'] },
  { name:'Zalando',      domains:['zalando.com','zalando.co.uk'] },
  { name:'John Lewis',   domains:['johnlewis.com'] },
  { name:'Marks & Spencer', domains:['marksandspencer.com'] },
  { name:'Argos',        domains:['argos.co.uk'] },
  { name:'Currys',       domains:['currys.co.uk'] },
  { name:'Boots',        domains:['boots.com'] },
  { name:'Tesco',        domains:['tesco.com','tescobank.com'] },

  // ── Delivery & Logistics ──────────────────────────────────────────────────
  { name:'DHL',          domains:['dhl.com','dhl.de','dhl.co.uk'] },
  { name:'FedEx',        domains:['fedex.com'] },
  { name:'UPS',          domains:['ups.com'] },
  { name:'USPS',         domains:['usps.com','usps.gov'] },
  { name:'Royal Mail',   domains:['royalmail.com'] },
  { name:'Evri',         domains:['evri.com','hermes.world'] },
  { name:'Yodel',        domains:['yodel.co.uk'] },
  { name:'ParcelForce',  domains:['parcelforce.com'] },
  { name:'TNT',          domains:['tnt.com'] },
  { name:'Purolator',    domains:['purolator.com'] },
  { name:'Australia Post', domains:['auspost.com.au'] },

  // ── Telecommunications ────────────────────────────────────────────────────
  { name:'AT&T',         domains:['att.com'] },
  { name:'Verizon',      domains:['verizon.com'] },
  { name:'T-Mobile',     domains:['t-mobile.com'] },
  { name:'Vodafone',     domains:['vodafone.com','vodafone.co.uk'] },
  { name:'O2',           domains:['o2.co.uk','o2.com'] },
  { name:'EE',           domains:['ee.co.uk'] },
  { name:'Three',        domains:['three.co.uk','three.ie'] },
  { name:'BT',           domains:['bt.com'] },
  { name:'Sky',          domains:['sky.com','sky.co.uk'] },
  { name:'Virgin Media', domains:['virginmedia.com'] },
  { name:'Comcast',      domains:['comcast.com','xfinity.com'] },
  { name:'Rogers',       domains:['rogers.com'] },

  // ── Government & Tax ──────────────────────────────────────────────────────
  { name:'HMRC',         domains:['hmrc.gov.uk','gov.uk'] },
  { name:'IRS',          domains:['irs.gov'] },
  { name:'SSA',          domains:['ssa.gov'] },
  { name:'DVLA',         domains:['dvla.gov.uk','gov.uk'] },
  { name:'DWP',          domains:['dwp.gov.uk','gov.uk'] },
  { name:'Companies House', domains:['companieshouse.gov.uk','gov.uk'] },
  { name:'NHS',          domains:['nhs.uk','nhs.net'] },
  { name:'TV Licensing', domains:['tvlicensing.co.uk'] },

  // ── Travel & Hospitality ──────────────────────────────────────────────────
  { name:'British Airways', domains:['britishairways.com','ba.com'] },
  { name:'Ryanair',      domains:['ryanair.com'] },
  { name:'easyJet',      domains:['easyjet.com'] },
  { name:'Lufthansa',    domains:['lufthansa.com'] },
  { name:'Emirates',     domains:['emirates.com'] },
  { name:'Delta',        domains:['delta.com'] },
  { name:'United Airlines', domains:['united.com'] },
  { name:'American Airlines', domains:['aa.com','americanairlines.com'] },
  { name:'Southwest',    domains:['southwest.com'] },
  { name:'Booking.com',  domains:['booking.com'] },
  { name:'Expedia',      domains:['expedia.com','expedia.co.uk'] },
  { name:'Airbnb',       domains:['airbnb.com','airbnb.co.uk'] },
  { name:'TripAdvisor',  domains:['tripadvisor.com'] },
  { name:'Marriott',     domains:['marriott.com'] },
  { name:'Hilton',       domains:['hilton.com'] },
  { name:'Hyatt',        domains:['hyatt.com'] },

  // ── Streaming & Entertainment ─────────────────────────────────────────────
  { name:'Disney+',      domains:['disney.com','disneyplus.com'] },
  { name:'HBO Max',      domains:['hbomax.com','max.com','warnermedia.com'] },
  { name:'Hulu',         domains:['hulu.com'] },
  { name:'Paramount+',   domains:['paramount.com','paramountplus.com'] },
  { name:'Apple TV+',    domains:['apple.com'] },
  { name:'Prime Video',  domains:['primevideo.com','amazon.com'] },
  { name:'Apple Music',  domains:['apple.com'] },
  { name:'YouTube',      domains:['youtube.com','google.com'] },

  // ── Healthcare & Pharma ───────────────────────────────────────────────────
  { name:'Pfizer',       domains:['pfizer.com'] },
  { name:'Johnson & Johnson', domains:['jnj.com','janssen.com'] },
  { name:'Moderna',      domains:['modernatx.com','moderna.com'] },
  { name:'AstraZeneca',  domains:['astrazeneca.com'] },
  { name:'GSK',          domains:['gsk.com','glaxosmithkline.com'] },
  { name:'Roche',        domains:['roche.com'] },
  { name:'Novartis',     domains:['novartis.com'] },
  { name:'Boots',        domains:['boots.com'] },

  // ── Energy ────────────────────────────────────────────────────────────────
  { name:'BP',           domains:['bp.com'] },
  { name:'Shell',        domains:['shell.com'] },
  { name:'ExxonMobil',   domains:['exxonmobil.com'] },
  { name:'British Gas',  domains:['britishgas.co.uk','centrica.com'] },
  { name:'E.ON',         domains:['eon.com','eon.co.uk'] },
  { name:'OVO Energy',   domains:['ovoenergy.com'] },
  { name:'Octopus Energy', domains:['octopus.energy'] },

  // ── Food & Delivery ───────────────────────────────────────────────────────
  { name:'Uber Eats',    domains:['ubereats.com','uber.com'] },
  { name:'Deliveroo',    domains:['deliveroo.com','deliveroo.co.uk'] },
  { name:'Just Eat',     domains:['just-eat.co.uk','just-eat.com'] },
  { name:'DoorDash',     domains:['doordash.com'] },
  { name:'Starbucks',    domains:['starbucks.com'] },
  { name:'McDonald\'s',  domains:['mcdonalds.com'] }
];

// ---------------------------------------------------------------------------
// LEVENSHTEIN DISTANCE — measures how similar two strings are
// Edit distance of 1-2 on domain names = likely spoofing attempt
// e.g. "paypa1.com" vs "paypal.com" = distance 1
// ---------------------------------------------------------------------------
function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i-1] === b[j-1]
        ? dp[i-1][j-1]
        : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
    }
  }
  return dp[m][n];
}

// ---------------------------------------------------------------------------
// HOMOGLYPH MAP — characters that look like other characters
// Attackers swap these to make fake domains look real
// ---------------------------------------------------------------------------
const HOMOGLYPHS = {
  'a': ['@', '4', 'α', 'а'],   // Cyrillic а looks identical to Latin a
  'e': ['3', 'е'],              // Cyrillic е
  'i': ['1', '!', 'l', '|', 'í', 'ì'],
  'o': ['0', 'ο', 'о'],         // Greek/Cyrillic o
  'l': ['1', 'I', '|'],
  's': ['5', '$'],
  't': ['7', '+'],
  'g': ['9', 'q'],
  'b': ['6'],
  'c': ['('],
  'n': ['m'],
  'u': ['v'],
  'v': ['u'],
  'rn': ['m'],                  // "rn" together looks like "m"
  'cl': ['d'],                  // "cl" together looks like "d"
};

// Normalise a domain by replacing common homoglyphs with their real chars
function normaliseDomain(domain) {
  let normalised = domain.toLowerCase();
  // Multi-char substitutions first
  normalised = normalised.replace(/rn/g, 'm').replace(/cl/g, 'd');
  // Single char substitutions
  const map = {'@':'a','4':'a','3':'e','1':'i','0':'o','5':'s','$':'s','7':'t','9':'g','6':'b'};
  return normalised.replace(/[@413057$96]/g, c => map[c] || c);
}

// ---------------------------------------------------------------------------
// DOMAIN SPOOF DETECTION
// For each brand, checks if the sender domain:
// 1. Exactly matches an official domain → legit
// 2. Is within edit distance 1-2 of an official domain → SPOOF
// 3. Contains the brand name but has extra parts → SPOOF
// 4. After homoglyph normalisation, matches → SPOOF
// ---------------------------------------------------------------------------
function detectDomainSpoofing(senderEmail, senderName, subject, body) {
  if (!senderEmail || !senderEmail.includes('@')) return null;

  const senderDomain   = senderEmail.split('@')[1]?.toLowerCase()?.trim() || '';
  const senderDomainNorm = normaliseDomain(senderDomain);
  if (!senderDomain) return null;

  const fullText = `${senderName} ${subject} ${body.substring(0, 800)}`.toLowerCase();

  for (const brand of KNOWN_BRANDS) {
    const brandLower    = brand.name.toLowerCase();
    const brandMentioned = fullText.includes(brandLower) ||
                           fullText.includes(brandLower.replace(/\s+/g,'')) ||
                           senderName.toLowerCase().includes(brandLower);

    // Check if sender is on an official domain
    const isOfficial = brand.domains.some(d => senderDomain === d || senderDomain.endsWith('.' + d));
    if (isOfficial) continue; // Legitimate — skip

    if (!brandMentioned && !senderDomain.includes(brandLower.replace(/\s+/g, ''))) continue;

    // Check each official domain for spoofing
    for (const officialDomain of brand.domains) {
      const officialBase = officialDomain.split('.')[0]; // e.g. "paypal" from "paypal.com"
      const senderBase   = senderDomain.split('.')[0];
      const senderBaseNorm = normaliseDomain(senderBase);

      // Method 1: Edit distance on domain base (catches typos & char swaps)
      const dist = levenshtein(senderBaseNorm, officialBase);
      if (dist > 0 && dist <= 2 && senderBase.length >= 3) {
        return {
          brand:     brand.name,
          spoofed:   senderDomain,
          official:  officialDomain,
          method:    'character substitution',
          indicator: `⚠️ "${senderDomain}" appears to spoof ${brand.name} (official: ${officialDomain}) — ${dist} character difference detected (e.g. "${senderBase}" vs "${officialBase}")`
        };
      }

      // Method 2: Homoglyph normalisation match
      if (senderBaseNorm === officialBase && senderBase !== officialBase) {
        return {
          brand:     brand.name,
          spoofed:   senderDomain,
          official:  officialDomain,
          method:    'homoglyph substitution',
          indicator: `🔴 "${senderDomain}" uses look-alike characters to impersonate ${brand.name} (official domain: ${officialDomain})`
        };
      }

      // Method 3: Brand name + extra words (paypal-security.com, google-accounts.com)
      if ((senderDomain.includes(officialBase) || senderDomain.includes(brandLower.replace(/\s+/g,'')))
          && !isOfficial) {
        return {
          brand:     brand.name,
          spoofed:   senderDomain,
          official:  officialDomain,
          method:    'subdomain/keyword injection',
          indicator: `🔴 "${senderDomain}" contains "${brand.name}" brand name but is NOT an official ${brand.name} domain (official: ${officialDomain})`
        };
      }
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// SPAM KEYWORD RULES — 150+ phrases across 3 severity tiers
// ---------------------------------------------------------------------------
const SPAM_RULES = {
  CRITICAL: {
    weight: 100,
    phrases: [
      'verify your password','confirm your password','enter your password',
      'update your password now','validate your credentials',
      'your account has been locked','your account will be deleted',
      'verify your account immediately','confirm your identity now',
      'unusual sign-in activity','suspicious login detected',
      'your payment has failed','update your billing information',
      'your card has been declined','verify your payment method',
      'your bank account will be suspended','immediate payment required',
      'your device has been compromised','virus detected on your account',
      'your computer has been hacked','unauthorized access to your account',
      'click here to secure your account','your account will be terminated',
      'dear paypal customer','dear amazon customer','dear apple customer',
      'dear google user','dear microsoft customer','hmrc tax refund',
      'irs tax refund','government grant approved',
      'download the attachment to view','open the attached file',
      'enable macros to view','enable editing to view',
      'your parcel could not be delivered','reschedule your delivery',
      'outstanding payment required','debt collection notice'
    ]
  },
  HIGH: {
    weight: 40,
    phrases: [
      'act now','act immediately','immediate action required',
      'respond immediately','urgent action required','urgent notice',
      'last warning','final notice','final warning','last chance',
      'within 24 hours','within 48 hours','expires today',
      'account suspended','account will be suspended',
      'account has been limited','access has been restricted',
      'you have won','you have been selected','congratulations you',
      'claim your prize','claim your reward','you are our winner',
      'prize money','lottery winner','unclaimed funds',
      'inheritance funds','transfer of funds',
      'million dollars','million pounds','£1,000,000','$1,000,000',
      'click here to verify','click here to confirm','click below to verify',
      'verify your email address','confirm your email address',
      'login to verify','sign in to verify','validate your account',
      'i need your assistance','business proposition','confidential proposal',
      'percentage of the funds','help me transfer','foreign transfer',
      'next of kin','deceased customer','dormant account',
      'work from home earn','earn money from home','make money online',
      'guaranteed income','no experience required earn',
      'invoice is attached','payment receipt attached',
      'your order confirmation','delivery attempted',
      'parcel held at customs','customs fee required',
      'refund is pending','your refund has been approved'
    ]
  },
  MEDIUM: {
    weight: 20,
    phrases: [
      'unsubscribe from this','opt out from','click to unsubscribe',
      'you are receiving this because','this is a promotional email',
      'limited time offer','special offer','exclusive offer',
      'best price guaranteed','lowest price','sale ends',
      'buy now','order now','shop now',
      'lose weight fast','weight loss guaranteed','burn fat fast',
      'male enhancement','cheap medication','no prescription needed',
      'online pharmacy','miracle cure','doctors hate this',
      'bitcoin investment','crypto opportunity','invest in crypto',
      'guaranteed returns','risk free investment','100% profit',
      'double your money','passive income','financial freedom',
      'trading signals','forex opportunity',
      'dear friend','dear beneficiary','dear winner','dear user',
      'to whom it may concern',
      'this email was sent to','you are receiving this',
      'click the link below to','follow the link to',
      'do not reply to this email','this is an automated message',
      'meet singles','local singles','singles in your area',
      'as seen on tv','celebrity endorsement','endorsed by doctors'
    ]
  }
};

// ---------------------------------------------------------------------------
// SUSPICIOUS LINK DETECTION
// ---------------------------------------------------------------------------
function detectSuspiciousLinks(links) {
  const indicators = [];
  for (const link of links.slice(0, 20)) {
    try {
      const urlObj = new URL(link);
      const domain = urlObj.hostname.toLowerCase();
      const normDomain = normaliseDomain(domain.split('.')[0]);

      // Check if this link domain spoofs any known brand
      for (const brand of KNOWN_BRANDS) {
        for (const officialDomain of brand.domains) {
          const officialBase = officialDomain.split('.')[0];
          const dist = levenshtein(normDomain, officialBase);
          if (dist > 0 && dist <= 2 && normDomain.length >= 4) {
            indicators.push(`Suspicious link domain "${domain}" may spoof ${brand.name} (official: ${officialDomain})`);
            break;
          }
          if (domain.includes(officialBase) && !brand.domains.includes(domain) && !brand.domains.some(d => domain.endsWith('.' + d))) {
            indicators.push(`Link uses ${brand.name} brand name in suspicious domain: "${domain}"`);
            break;
          }
        }
      }

      // Generic suspicious patterns
      if (domain.includes('-secure') || domain.includes('-login') ||
          domain.includes('-verify') || domain.includes('-account') ||
          domain.includes('-update') || domain.includes('-confirm') ||
          /[a-z]+[0-9]{2,}[a-z]+\.[a-z]{2,}/.test(domain)) {
        indicators.push(`Suspicious URL pattern detected: "${domain}"`);
      }

      // URL shorteners used in phishing
      const shorteners = ['bit.ly','tinyurl.com','t.co','ow.ly','short.link','is.gd','buff.ly','rebrand.ly'];
      if (shorteners.some(s => domain === s || domain.endsWith('.' + s))) {
        indicators.push(`URL shortener detected (${domain}) — hides true destination`);
      }

    } catch(e) { /* invalid URL */ }
  }
  return [...new Set(indicators)]; // deduplicate
}

// ---------------------------------------------------------------------------
// FORMATTING CHECKS
// ---------------------------------------------------------------------------
function detectSpamFormatting(body) {
  const indicators = [];
  const exclamations = (body.match(/!/g) || []).length;
  if (exclamations >= 5) {
    indicators.push(`Excessive exclamation marks (${exclamations} found) — common spam pattern`);
  }
  const words    = body.split(/\s+/);
  const capsWords = words.filter(w => w.length > 3 && w === w.toUpperCase() && /[A-Z]/.test(w));
  const capsPct   = words.length > 0 ? (capsWords.length / words.length) * 100 : 0;
  if (capsPct > 20 && capsWords.length > 4) {
    indicators.push(`${Math.round(capsPct)}% of words in ALL CAPS — typical spam formatting`);
  }
  return indicators;
}

// ---------------------------------------------------------------------------
// MAIN SCANNER
// ---------------------------------------------------------------------------
function runLocalSpamScan(emailData) {
  const { subject='', senderName='', senderEmail='', body='', links=[] } = emailData;
  const fullText = `${subject} ${senderName} ${body}`.toLowerCase();

  const indicators = [];
  let totalScore   = 0;
  let highestLevel = 'LOW';

  const setLevel = (level) => {
    const order = ['LOW','MEDIUM','HIGH','CRITICAL'];
    if (order.indexOf(level) > order.indexOf(highestLevel)) highestLevel = level;
  };

  // ── Keyword scan ──
  for (const [level, rule] of Object.entries(SPAM_RULES)) {
    const matched = rule.phrases.filter(p => fullText.includes(p.toLowerCase()));
    if (matched.length > 0) {
      const score = Math.min(rule.weight * matched.length, level === 'CRITICAL' ? 100 : rule.weight * 3);
      totalScore += score;
      matched.forEach(p => indicators.push(`Matched ${level} phrase: "${p}"`));
      setLevel(level);
    }
  }

  // ── Domain spoofing ──
  const spoof = detectDomainSpoofing(senderEmail, senderName, subject, body);
  if (spoof) {
    indicators.push(spoof.indicator);
    totalScore += spoof.method === 'homoglyph substitution' ? 90 : 70;
    setLevel('CRITICAL');
  }

  // ── Link analysis ──
  const linkIssues = detectSuspiciousLinks(links);
  linkIssues.forEach(issue => {
    indicators.push(issue);
    totalScore += 35;
    setLevel('HIGH');
  });

  // ── Formatting ──
  detectSpamFormatting(body).forEach(issue => {
    indicators.push(issue);
    totalScore += 15;
    setLevel('MEDIUM');
  });

  // ── Final score & level ──
  const riskScore = Math.min(Math.round(totalScore), 100);
  let riskLevel   = riskScore === 0 ? 'LOW' : riskScore <= 20 ? 'LOW' : riskScore <= 45 ? 'MEDIUM' : riskScore <= 75 ? 'HIGH' : 'CRITICAL';
  if (highestLevel === 'CRITICAL') riskLevel = 'CRITICAL';
  else if (highestLevel === 'HIGH' && riskLevel === 'MEDIUM') riskLevel = 'HIGH';

  const hasPhishing = indicators.some(i => /domain|spoof|impersonat|credential|verify|login/i.test(i));
  const hasScam     = indicators.some(i => /lottery|winner|fund|million|transfer|inheritance/i.test(i));
  const threatType  = riskLevel === 'LOW' ? 'LEGITIMATE' : hasPhishing ? 'PHISHING' : hasScam ? 'SCAM' : 'SPAM';

  const verdicts = {
    CRITICAL: `Critical ${threatType.toLowerCase()} detected — ${indicators[0] || 'multiple high-risk indicators found'}`,
    HIGH:     `High-risk email with ${indicators.length} suspicious indicator${indicators.length !== 1 ? 's' : ''} detected`,
    MEDIUM:   `Suspicious email — ${indicators.length} potential spam indicator${indicators.length !== 1 ? 's' : ''} found`,
    LOW:      'No significant threats detected by keyword analysis'
  };

  const recs = {
    CRITICAL: 'Do NOT click any links or open attachments. Report as phishing and delete immediately.',
    HIGH:     'Do not click links or provide personal information. Verify with the sender via official channels only.',
    MEDIUM:   'Exercise caution. Verify the sender before taking any action.',
    LOW:      'Email appears legitimate based on local keyword analysis.'
  };

  return {
    riskScore, riskLevel, threatType,
    indicators: indicators.slice(0, 15),
    verdict:    verdicts[riskLevel],
    recommendation: recs[riskLevel],
    detectionMethod: 'LOCAL_KEYWORD_SCAN',
    keywordsMatched: indicators.length
  };
}

// =============================================================================
// DownloadGuard - background.js v3.0
// Single clean message listener. No duplicates.
// =============================================================================

// ---------------------------------------------------------------------------
// CONSTANTS
// ---------------------------------------------------------------------------
const DANGEROUS_EXTENSIONS = [
  '.exe', '.dmg', '.msi', '.bat', '.cmd', '.ps1',
  '.vbs', '.jar', '.sh', '.scr', '.pif', '.hta',
  '.wsf', '.reg', '.app', '.com'
];

const MEDIA_EXTENSIONS = [
  '.mp4', '.mp3', '.avi', '.mkv', '.mov', '.wmv',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx',
  '.jpg', '.jpeg', '.png', '.gif', '.zip', '.rar'
];

// ---------------------------------------------------------------------------
// DOWNLOAD MONITORING
// ---------------------------------------------------------------------------
function getExtension(filename) {
  if (!filename) return '';
  const parts = filename.toLowerCase().trim().split('.');
  return parts.length < 2 ? '' : '.' + parts[parts.length - 1];
}

function getImpliedExtension(filename) {
  // Catches "movie.mp4.exe" — finds media ext BEFORE the final extension
  if (!filename) return null;
  const lower = filename.toLowerCase();
  for (const ext of MEDIA_EXTENSIONS) {
    const idx = lower.lastIndexOf(ext);
    if (idx !== -1 && idx < lower.length - ext.length) return ext;
  }
  return null;
}

function getUrlImpliedExtension(url) {
  try {
    const path = new URL(url).pathname.toLowerCase();
    for (const ext of MEDIA_EXTENSIONS) {
      if (path.includes(ext)) return ext;
    }
  } catch (e) {}
  return null;
}

function resolveFilename(item) {
  if (item.filename?.trim()) return item.filename.split(/[/\\]/).pop().trim();
  try {
    const url = item.finalUrl || item.url;
    if (url.startsWith('data:')) return '';
    return decodeURIComponent(new URL(url).pathname.split('/').pop()) || '';
  } catch (e) { return ''; }
}

chrome.downloads.onCreated.addListener(async (item) => {
  const filename = resolveFilename(item);
  console.log('[DG] Download detected:', filename, '|', (item.finalUrl || item.url).substring(0, 60));

  if (!filename) { console.log('[DG] No filename — skip'); return; }

  const actualExt = getExtension(filename);
  console.log('[DG] Extension:', actualExt);

  if (!DANGEROUS_EXTENSIONS.includes(actualExt)) {
    console.log('[DG] Safe extension — no warning');
    return;
  }

  const url             = item.finalUrl || item.url;
  const impliedFromFile = getImpliedExtension(filename);
  const impliedFromUrl  = getUrlImpliedExtension(url);
  const impliedExt      = impliedFromFile || impliedFromUrl;
  const isMasq          = impliedExt !== null && impliedExt !== actualExt;

  console.log('[DG] DANGEROUS — implied:', impliedExt, '| masquerading:', isMasq);

  // ── Pause the download immediately so the file isn't written to disk ──
  chrome.downloads.pause(item.id, () => {
    if (chrome.runtime.lastError) {
      // Download completed before we could pause — nothing we can do
      console.warn('[DG] Could not pause download:', chrome.runtime.lastError.message);
      return;
    }

    const warningData = {
      downloadId:      item.id,
      filename,
      actualExt,
      url,
      isMasquerading:  isMasq,
      impliedExt:      impliedExt || null,
      threatLevel:     isMasq ? 'CRITICAL' : 'HIGH',
      detectedAt:      new Date().toISOString()
    };

    // Store so warning.js can retrieve it via GET_WARNING_DATA
    chrome.storage.session.set(
      { [`dg_warning_${item.id}`]: warningData },
      () => {
        // Open warning page in a new tab
        chrome.tabs.create({
          url: chrome.runtime.getURL(`warning.html?id=${item.id}`)
        });
      }
    );
  });
});

// ---------------------------------------------------------------------------
// SINGLE MESSAGE LISTENER — handles everything
// ---------------------------------------------------------------------------
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  // ── Download decisions ──
  if (msg.action === 'RESUME_DOWNLOAD') {
    chrome.downloads.resume(msg.downloadId, () =>
      sendResponse({ success: !chrome.runtime.lastError })
    );
    return true;
  }

  if (msg.action === 'CANCEL_DOWNLOAD') {
    chrome.downloads.cancel(msg.downloadId, () => sendResponse({ success: true }));
    return true;
  }

  if (msg.action === 'GET_WARNING_DATA') {
    chrome.storage.session.get(`dg_warning_${msg.downloadId}`, (r) =>
      sendResponse({ data: r[`dg_warning_${msg.downloadId}`] || null })
    );
    return true;
  }

  // ── VirusTotal scan ──
  if (msg.action === 'SCAN_VIRUSTOTAL') {
    chrome.storage.local.get('dg_vt_key', async (stored) => {
      const key = msg.apiKey || stored.dg_vt_key;
      if (!key) { sendResponse({ success: false, error: 'No VirusTotal API key saved.' }); return; }
      try {
        const result = await scanWithVT(msg.url, key);
        sendResponse({ success: true, result });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    });
    return true;
  }

  // ── Email analysis: local keyword scan first, Gemini as fallback ──
  if (msg.action === 'ANALYSE_PHISHING') {

    // Step 1: Run local keyword scan instantly (no API, no quota)
    const localResult = runLocalSpamScan(msg.emailData);
    console.log('[DG] Local scan:', localResult.riskLevel, localResult.riskScore, localResult.keywordsMatched, 'keywords');

    // Step 2: If local scan found something definitive, return it immediately
    // CRITICAL or HIGH with 2+ keywords = confident enough, skip Gemini
    if (localResult.riskLevel === 'CRITICAL' ||
       (localResult.riskLevel === 'HIGH' && localResult.keywordsMatched >= 2)) {
      localResult.detectionMethod = 'LOCAL_KEYWORD_SCAN';

      // Store result for download warning correlation
      if (sender.tab?.id) {
        chrome.storage.session.set({
          [`dg_phishing_${sender.tab.id}`]: {
            ...localResult,
            subject:  msg.emailData.subject,
            sender:   msg.emailData.senderEmail,
            storedAt: new Date().toISOString()
          }
        });
      }
      sendResponse({ success: true, result: localResult });
      return true;
    }

    // Step 3: For MEDIUM/LOW/ambiguous — try Gemini for deeper analysis
    chrome.storage.local.get('dg_gemini_key', async (stored) => {
      const key = stored.dg_gemini_key;

      // No Gemini key — just return local result as-is
      if (!key) {
        localResult.detectionMethod = 'LOCAL_KEYWORD_SCAN (no Gemini key)';
        sendResponse({ success: true, result: localResult });
        return;
      }

      try {
        const geminiResult = await analyseWithGemini(msg.emailData, key);

        // Merge: take the higher risk level between local and Gemini
        const levels   = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
        const localIdx = levels.indexOf(localResult.riskLevel);
        const geminiIdx = levels.indexOf(geminiResult.riskLevel);
        const finalResult = geminiIdx >= localIdx ? geminiResult : localResult;

        // Combine indicators from both scans
        finalResult.indicators = [
          ...new Set([
            ...(geminiResult.indicators || []),
            ...(localResult.indicators  || [])
          ])
        ].slice(0, 12);

        finalResult.detectionMethod = 'GEMINI + LOCAL_KEYWORDS';

        if (sender.tab?.id) {
          chrome.storage.session.set({
            [`dg_phishing_${sender.tab.id}`]: {
              ...finalResult,
              subject:  msg.emailData.subject,
              sender:   msg.emailData.senderEmail,
              storedAt: new Date().toISOString()
            }
          });
        }
        sendResponse({ success: true, result: finalResult });

      } catch (e) {
        // Gemini failed (quota, network etc) — fall back to local result
        console.warn('[DG] Gemini failed, using local result:', e.message);
        localResult.detectionMethod = 'LOCAL_KEYWORD_SCAN (Gemini unavailable)';
        localResult.verdict += ' (Gemini unavailable — local scan only)';
        sendResponse({ success: true, result: localResult });
      }
    });
    return true;
  }

  // ── Inject content script into current tab (user clicked Allow) ──
  if (msg.action === 'INJECT_CONTENT_SCRIPT') {
    chrome.tabs.query({ active: true, lastFocusedWindow: true }, async (tabs) => {
      const tab = tabs[0];
      if (!tab) { sendResponse({ success: false, error: 'No active tab found.' }); return; }
      try {
        await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ['content.js'] });
        await chrome.scripting.insertCSS({ target: { tabId: tab.id }, files: ['content.css'] });
        const domain = new URL(tab.url).hostname;
        const stored = await chrome.storage.local.get('dg_allowed_domains');
        const allowed = stored.dg_allowed_domains || [];
        if (!allowed.includes(domain)) allowed.push(domain);
        await chrome.storage.local.set({ dg_allowed_domains: allowed });
        sendResponse({ success: true, tabId: tab.id });
      } catch (e) {
        // If already injected, that's fine — still return success
        sendResponse({ success: true, tabId: tab?.id, note: e.message });
      }
    });
    return true;
  }

  // ── Get current tab info for popup ──
  if (msg.action === 'GET_TAB_INFO') {
    chrome.tabs.query({ active: true, lastFocusedWindow: true }, async (tabs) => {
      const tab = tabs[0];
      if (!tab) { sendResponse({ data: null }); return; }
      const hostname = (() => { try { return new URL(tab.url).hostname; } catch(e) { return ''; } })();
      const isEmail  = hostname.includes('mail.google') || hostname.includes('outlook') || hostname.includes('cloud.microsoft');
      const stored   = await chrome.storage.local.get('dg_allowed_domains');
      const allowed  = stored.dg_allowed_domains || [];
      const isAllowed = allowed.includes(hostname);
      sendResponse({ data: { url: tab.url, hostname, isEmail, isAllowed, tabId: tab.id } });
    });
    return true;
  }

  // ── API key management ──
  if (msg.action === 'SAVE_GEMINI_KEY') {
    chrome.storage.local.set({ dg_gemini_key: msg.key }, () => sendResponse({ success: true }));
    return true;
  }

  if (msg.action === 'SAVE_VT_KEY') {
    chrome.storage.local.set({ dg_vt_key: msg.key }, () => sendResponse({ success: true }));
    return true;
  }

  if (msg.action === 'GET_KEYS_STATUS') {
    chrome.storage.local.get(['dg_gemini_key', 'dg_vt_key'], (r) =>
      sendResponse({ hasGemini: !!r.dg_gemini_key, hasVT: !!r.dg_vt_key })
    );
    return true;
  }

  // ── Test Gemini key ──
  if (msg.action === 'TEST_GEMINI_KEY') {
    const key = msg.key;
    if (!key) { sendResponse({ success: false, error: 'No key provided' }); return true; }
    fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${key}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: 'Reply with the single word: OK' }] }],
        generationConfig: { maxOutputTokens: 5 }
      })
    })
    .then(async res => {
      if (res.status === 200) {
        const d = await res.json();
        const reply = d?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || 'OK';
        sendResponse({ success: true, reply });
      } else if (res.status === 429) {
        sendResponse({ success: true, reply: 'Rate limited — key is valid' });
      } else {
        const d = await res.json().catch(() => ({}));
        sendResponse({ success: false, error: d?.error?.message || `HTTP ${res.status}` });
      }
    })
    .catch(e => sendResponse({ success: false, error: e.message }));
    return true;
  }

  // ── Test VirusTotal key ──
  if (msg.action === 'TEST_VT_KEY') {
    const key = msg.key;
    if (!key) { sendResponse({ success: false, error: 'No key provided' }); return true; }
    fetch('https://www.virustotal.com/api/v3/users/current', {
      headers: { 'x-apikey': key }
    })
    .then(async res => {
      if (res.status === 200) {
        const d = await res.json();
        const quota = d?.data?.attributes?.quotas?.api_requests_daily?.allowed || 500;
        const used  = d?.data?.attributes?.quotas?.api_requests_daily?.used || 0;
        sendResponse({ success: true, quota, used });
      } else if (res.status === 429) {
        sendResponse({ success: true, quota: '?', used: '?', rateLimited: true });
      } else {
        sendResponse({ success: false, error: res.status === 401 ? 'Invalid API key' : `HTTP ${res.status}` });
      }
    })
    .catch(e => sendResponse({ success: false, error: e.message }));
    return true;
  }


  // ── Ad-wall URL resolution ──
  if (msg.action === 'RESOLVE_ADWALL') {
    const url = msg.url;
    if (!url) { sendResponse({ success: false, error: 'No URL provided' }); return true; }

    (async () => {
      try {
        // Follow HTTP redirects — this catches most link shortener chains
        const controller = new AbortController();
        const timeout    = setTimeout(() => controller.abort(), 8000);

        const response = await fetch(url, {
          method:   'GET',
          redirect: 'follow',
          signal:   controller.signal,
          headers:  { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' }
        });
        clearTimeout(timeout);

        const finalUrl  = response.url;
        let hops        = 0;

        // Count redirects by comparing original to final
        if (finalUrl !== url) hops = 1; // At least one redirect happened

        // If we ended up on another known ad-wall, try to extract URL from HTML
        const finalHost = (() => { try { return new URL(finalUrl).hostname.replace(/^www\./, ''); } catch(e) { return ''; } })();
        const adwallHosts = ['linkvertise.com','lnkfly.com','adf.ly','bc.vc','ouo.io','exe.io','shrink.pe','gplinks.in'];

        if (adwallHosts.includes(finalHost)) {
          // Parse HTML for JS-based redirects
          const html        = await response.text().catch(() => '');
          const extracted   = extractRedirectFromHtml(html);
          if (extracted) {
            sendResponse({ success: true, finalUrl: extracted, hops: hops + 1, method: 'html-parse' });
            return;
          }
        }

        sendResponse({ success: true, finalUrl, hops, method: finalUrl !== url ? 'http-redirect' : 'no-redirect' });

      } catch(e) {
        if (e.name === 'AbortError') {
          sendResponse({ success: false, error: 'Request timed out after 8 seconds' });
        } else {
          sendResponse({ success: false, error: e.message });
        }
      }
    })();
    return true;
  }

  // ── Session stats for popup ──
  if (msg.action === 'GET_STATS') {
    chrome.storage.session.get(null, (data) => {
      const dlKeys    = Object.keys(data).filter(k => k.startsWith('dg_warning_'));
      const phishKeys = Object.keys(data).filter(k => k.startsWith('dg_phishing_'));
      sendResponse({
        threats:   dlKeys.length,
        masquerade: dlKeys.filter(k => data[k]?.isMasquerading).length,
        phishing:  phishKeys.filter(k => ['HIGH','CRITICAL'].includes(data[k]?.riskLevel)).length
      });
    });
    return true;
  }
});

// ---------------------------------------------------------------------------
// VIRUSTOTAL: Submit URL and poll for results
// ---------------------------------------------------------------------------
async function scanWithVT(url, apiKey) {
  const submitRes = await fetch('https://www.virustotal.com/api/v3/urls', {
    method: 'POST',
    headers: { 'x-apikey': apiKey, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `url=${encodeURIComponent(url)}`
  });
  if (!submitRes.ok) throw new Error(`VT submission failed: HTTP ${submitRes.status}`);
  const submitData = await submitRes.json();
  const analysisId = submitData?.data?.id;
  if (!analysisId) throw new Error('VT did not return an analysis ID.');

  for (let i = 0; i < 10; i++) {
    await new Promise(r => setTimeout(r, 3000));
    const res = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: { 'x-apikey': apiKey }
    });
    if (!res.ok) continue;
    const data   = await res.json();
    const status = data?.data?.attributes?.status;
    if (status !== 'completed') continue;

    const stats   = data?.data?.attributes?.stats || {};
    const results = data?.data?.attributes?.results || {};
    const flagged = Object.entries(results)
      .filter(([, r]) => r.category === 'malicious' || r.category === 'suspicious')
      .map(([engine, r]) => ({ engine, verdict: r.result || r.category }))
      .slice(0, 10);

    return {
      malicious:  stats.malicious  || 0,
      suspicious: stats.suspicious || 0,
      harmless:   stats.harmless   || 0,
      undetected: stats.undetected || 0,
      total:      Object.values(stats).reduce((a, b) => a + b, 0),
      flaggedBy:  flagged,
      vtLink: `https://www.virustotal.com/gui/url/${btoa(url).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_')}`
    };
  }
  throw new Error('VT analysis timed out — check results at virustotal.com directly.');
}

// ---------------------------------------------------------------------------
// GEMINI: High-sensitivity phishing AND spam detection
// ---------------------------------------------------------------------------
async function analyseWithGemini(emailData, apiKey) {
  const prompt = `You are an email security analyst. Analyse this email for phishing, spam, and scams.
Return ONLY valid JSON, no markdown:
{"riskScore":<0-100>,"riskLevel":"<LOW|MEDIUM|HIGH|CRITICAL>","threatType":"<PHISHING|SPAM|SCAM|MALWARE|LEGITIMATE>","indicators":[<red flags found>],"verdict":"<one sentence>","recommendation":"<one action>"}

Scoring: 0-20=LOW, 21-45=MEDIUM, 46-75=HIGH, 76-100=CRITICAL
Err HIGH not low. Unknown senders = minimum MEDIUM.

Phishing: domain mismatch, credential requests, urgency threats, brand impersonation, fake login links.
Spam: unsolicited marketing, prize claims, crypto offers, health products, vague subjects.
Scam: advance fee, romance, tech support, job offer fraud.

Subject: ${emailData.subject || '(none)'}
From: ${emailData.senderName || 'Unknown'} <${emailData.senderEmail || 'unknown'}>
Body: ${emailData.body ? emailData.body.substring(0, 1500) : '(empty)'}
Links: ${emailData.links?.slice(0,5).join(', ') || 'none'}`;

  const res = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.05, maxOutputTokens: 1024 }
      })
    }
  );

  if (!res.ok) {
    const d = await res.json().catch(() => ({}));
    throw new Error(`Gemini error: ${d?.error?.message || 'HTTP ' + res.status}`);
  }

  const data    = await res.json();
  const rawText = data?.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!rawText) throw new Error('Gemini returned empty response.');

  const clean  = rawText.replace(/```json|```/g, '').trim();
  const parsed = JSON.parse(clean);
  if (parsed.riskScore === undefined) throw new Error('Invalid Gemini response structure.');

  // Client-side sensitivity boost: LOW with any indicators => bump to MEDIUM
  if (parsed.riskLevel === 'LOW' && parsed.indicators?.length > 0) {
    parsed.riskLevel = 'MEDIUM';
    parsed.riskScore = Math.max(parsed.riskScore, 25);
  }

  return parsed;
}

// ---------------------------------------------------------------------------
// ADWALL: Extract redirect URL from HTML page (JS-based redirects)
// ---------------------------------------------------------------------------
function extractRedirectFromHtml(html) {
  if (!html) return null;

  // Meta refresh: <meta http-equiv="refresh" content="0;url=...">
  const metaMatch = html.match(/<meta[^>]+http-equiv=["']?refresh["']?[^>]+content=["'][^"']*url=([^"'\s>]+)/i)
                 || html.match(/content=["'][^"']*url=([^"'\s>]+)/i);
  if (metaMatch) return metaMatch[1].trim();

  // window.location.href = "..."
  const locPatterns = [
    /window\.location\.href\s*=\s*["']([^"']+)["']/,
    /window\.location\s*=\s*["']([^"']+)["']/,
    /document\.location\.href\s*=\s*["']([^"']+)["']/,
    /document\.location\s*=\s*["']([^"']+)["']/,
    /location\.replace\s*\(\s*["']([^"']+)["']\s*\)/,
    /location\.assign\s*\(\s*["']([^"']+)["']\s*\)/,
  ];

  for (const pattern of locPatterns) {
    const match = html.match(pattern);
    if (match && match[1].startsWith('http')) return match[1];
  }

  // href="..." with common destination link patterns
  const hrefMatch = html.match(/href=["'](https?:\/\/[^"']+)["'][^>]*>(?:skip|continue|get link|download|proceed)/i);
  if (hrefMatch) return hrefMatch[1];

  return null;
}

