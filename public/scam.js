// Deduce heuristic engine — scam / manipulation / coordination detection. Runs offline.
(function () {
  const RULES = [
    // category, weight, regex, label
    ['Phishing', 22, /\b(verify|confirm|update|unlock|restore)\b.{0,40}\b(account|password|identity|login|payment|card|details)\b/i, 'Asks you to verify/confirm account or payment details'],
    ['Phishing', 18, /\b(suspend(ed)?|locked|disabled|restricted|unusual (sign[- ]?in|activity)|security alert)\b/i, 'Account-threat language (suspended / locked / unusual activity)'],
    ['Phishing', 14, /\b(click|tap) (the |this )?(link|here|below)\b/i, 'Pushes you to click a link'],
    ['Phishing', 20, /\b(one[- ]time|otp|verification|2fa|security) code\b/i, 'Mentions a one-time / verification code (never share these)'],
    ['Investment / crypto', 24, /\b(guaranteed|risk[- ]free|double your|10x|100x|passive income|daily (profit|returns?)|\d{2,4}% (return|profit|roi))\b/i, 'Promises guaranteed or outsized returns'],
    ['Investment / crypto', 14, /\b(bitcoin|btc|ethereum|eth|usdt|tether|crypto|forex|binary options?|trading (bot|signals?|platform)|mining pool|airdrop|presale)\b/i, 'Crypto / trading vocabulary'],
    ['Investment / crypto', 16, /\b(account manager|mentor|expert trader|my (uncle|aunt|cousin) (taught|showed))\b/i, 'Unsolicited "mentor" / account-manager framing'],
    ['Romance / pig-butchering', 18, /\b(dear|my love|honey|sweetheart|soulmate|destiny)\b.{0,80}\b(money|send|help|invest|ticket|visa|customs|hospital)\b/is, 'Affection paired with a money request'],
    ['Romance / pig-butchering', 12, /\b(wrong number|sorry,? (i|I) (think|must have)|is this .{2,20}\?)\b/i, '"Wrong number" opener (classic pig-butchering hook)'],
    ['Romance / pig-butchering', 12, /\b(deployed|oil rig|peacekeeping|un doctor|offshore engineer|widow(er)?)\b/i, 'Romance-scam backstory (soldier / oil rig / widower)'],
    ['Job / recruitment', 20, /\b(work from home|remote job|earn \$?\d+.{0,12}(per|a|\/) ?(day|hour|week)|no experience (needed|required)|hiring now|task[- ]based|like and earn|review (products|apps) for money)\b/i, 'Too-easy job / task-for-pay offer'],
    ['Job / recruitment', 18, /\b(training fee|starter kit|deposit to (start|activate)|pay for (equipment|training)|check (deposit|to buy equipment))\b/i, 'Job that requires you to pay first'],
    ['Giveaway / prize', 22, /\b(you('ve| have)? (won|been selected)|winner|claim your (prize|reward|gift)|congratulations!?)\b/i, 'Unexpected prize / "you have been selected"'],
    ['Giveaway / prize', 14, /\b(giveaway|free (iphone|gift|money|cash)|first \d+ (people|users))\b/i, 'Giveaway bait'],
    ['Advance-fee', 22, /\b(processing|release|clearance|customs|shipping|tax) fee\b/i, 'Pay a fee to release money / a package'],
    ['Advance-fee', 18, /\b(inheritance|beneficiary|next of kin|unclaimed funds|compensation fund|million (usd|dollars|euros))\b/i, 'Inheritance / unclaimed-funds story'],
    ['Payment rails', 24, /\b(gift ?cards?|itunes card|steam card|google play card|amazon card)\b/i, 'Asks for payment in gift cards'],
    ['Payment rails', 16, /\b(wire transfer|western union|moneygram|zelle|cash ?app|venmo|crypto ?atm|bitcoin atm|friends (and|&) family)\b/i, 'Irreversible payment method requested'],
    ['Impersonation', 16, /\b(official|support team|customer (care|service)|help ?desk|admin|moderator|verified)\b.{0,40}\b(page|account|team)\b/i, 'Claims to be an official support account'],
    ['Impersonation', 14, /\b(paypal|amazon|apple|microsoft|meta|facebook|instagram|whatsapp|netflix|irs|hmrc|dhl|fedex|ups|usps|bank of america|chase|wells fargo|coinbase|binance)\b/i, 'Names a major brand or agency'],
    ['Tech support', 20, /\b(virus (detected|found)|your (computer|device|pc) (is|has been) (infected|hacked|compromised)|call (microsoft|apple) support|remote access|anydesk|teamviewer)\b/i, 'Fake tech-support / remote-access request'],
    ['Recovery scam', 20, /\b(recover (your |my |all )?(lost|stolen) (funds|crypto|money)|funds recovery|hacker for hire|ethical hacker)\b/i, '"We can recover your lost money" (targets past victims)'],
    ['Marketplace', 14, /\b(overpa(id|yment)|send (the )?(rest|difference) back|shipping agent will pick up|courier will collect|pay via (link|form))\b/i, 'Marketplace overpayment / fake-courier pattern'],
    ['Off-platform move', 14, /\b(dm me|inbox me|text me|message me on|add me on|contact (me |us )?(on|via)) ?(whats ?app|telegram|signal|wechat|line|kik)?\b|\b(whats ?app|telegram)\b.{0,20}\+?\d[\d\s\-]{6,}/i, 'Pushes the conversation to WhatsApp / Telegram / DMs'],
    ['Pressure', 16, /\b(urgent|immediately|act now|right now|within (24|48) hours|last chance|expires? (today|soon|in)|limited (time|spots|slots)|only \d+ (left|spots))\b/i, 'Artificial urgency or scarcity'],
    ['Pressure', 12, /\b(don'?t tell|keep (this|it) (secret|between us)|confidential)\b/i, 'Secrecy request'],
    ['Manipulation / misinformation', 16, /\b(share (this )?before (it'?s|they) (deleted|removed|taken down)|they don'?t want you to know|mainstream media (won'?t|refuses)|wake up|do your own research|banned (video|truth))\b/i, 'Classic misinformation spread-bait'],
    ['Manipulation / misinformation', 10, /\b(breaking|shocking|you won'?t believe|leaked|exposed|100% (true|proof|confirmed))\b/i, 'Sensational framing'],
    ['Manipulation / misinformation', 10, /\b(doctors (hate|don'?t want)|miracle (cure|pill)|cures? (cancer|diabetes|everything)|big pharma)\b/i, 'Health-miracle claim'],
    ['Manipulation / misinformation', 8, /\b(scientists|experts|studies|sources) (say|show|confirm|prove)\b(?![^.]{0,60}(https?:|doi|journal|published))/i, 'Vague appeal to authority with no source'],
    ['Engagement bait', 10, /\b(like (and|&) share|type ['"]?amen|comment ['"]?yes|tag (a friend|\d+ friends)|share if you agree|99% (won'?t|can'?t))\b/i, 'Engagement bait (farms reach for later scams)'],
  ];

  const SHORTENERS = /^(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|rebrand\.ly|cutt\.ly|shorturl\.at|rb\.gy|t\.ly|tiny\.cc|s\.id|lnkd\.in|linktr\.ee|bio\.link|beacons\.ai|wa\.me|t\.me)$/i;
  const RISKY_TLD = /\.(zip|mov|xyz|top|click|link|work|support|help|live|icu|cyou|buzz|rest|shop|loan|win|bid|cam|monster|quest|sbs|cfd|lat|online|site|info|ru|tk|ml|ga|cf|gq)$/i;
  const BRANDS = ['paypal', 'amazon', 'apple', 'microsoft', 'facebook', 'instagram', 'whatsapp', 'netflix', 'google', 'coinbase', 'binance', 'metamask', 'linkedin', 'twitter', 'chase', 'wellsfargo', 'bankofamerica', 'dhl', 'fedex', 'usps', 'irs', 'meta', 'tiktok', 'telegram', 'outlook', 'office365', 'icloud', 'trustwallet', 'kraken', 'revolut', 'wise'];
  const LEET = s => s.replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e').replace(/5/g, 's').replace(/rn/g, 'm').replace(/vv/g, 'w');

  function lev(a, b) { const m = []; for (let i = 0; i <= b.length; i++) m[i] = [i]; for (let j = 0; j <= a.length; j++) m[0][j] = j; for (let i = 1; i <= b.length; i++) for (let j = 1; j <= a.length; j++) m[i][j] = b[i - 1] === a[j - 1] ? m[i - 1][j - 1] : Math.min(m[i - 1][j - 1] + 1, m[i][j - 1] + 1, m[i - 1][j] + 1); return m[b.length][a.length]; }

  const PLATFORMS = [
    [/facebook\.com|fb\.com|fb\.watch|m\.me|messenger\.com/i, 'Facebook'], [/instagram\.com|instagr\.am/i, 'Instagram'], [/(^|\.)x\.com|twitter\.com|t\.co/i, 'X / Twitter'],
    [/linkedin\.com|lnkd\.in/i, 'LinkedIn'], [/tiktok\.com/i, 'TikTok'], [/t\.me|telegram\./i, 'Telegram'], [/wa\.me|whatsapp\./i, 'WhatsApp'], [/reddit\.com|redd\.it/i, 'Reddit'],
    [/youtube\.com|youtu\.be/i, 'YouTube'], [/threads\.net/i, 'Threads'], [/bsky\.app/i, 'Bluesky'], [/discord\.(gg|com)/i, 'Discord'], [/snapchat\.com/i, 'Snapchat'],
  ];
  const PLATFORM_PLAYBOOK = {
    'Facebook': ['Marketplace overpayment & fake-courier scams', 'Hijacked pages renamed to impersonate brands, then boosted with ads', 'Fake giveaway pages that collect likes, then sell the page', 'Romance approaches via friend requests from stolen-photo profiles'],
    'Instagram': ['Fake "brand ambassador" DMs asking you to pay for products', 'Crypto "account managers" with luxury-lifestyle stolen photos', 'Lookalike handles of real creators (extra dot/underscore/digit)', 'Link-in-bio redirect pages hiding the real destination'],
    'X / Twitter': ['Reply-spam impersonating support accounts', 'Fake giveaway / airdrop threads under celebrity posts', 'Bot amplification: new accounts, digit-suffix handles, identical replies', 'Paid checkmarks used to appear official'],
    'LinkedIn': ['Fake recruiters sending "job" files or moving to Telegram/WhatsApp', 'Pig-butchering via professional networking', 'Fake consultancies harvesting CVs and IDs', 'AI-generated headshots on fake profiles'],
    'TikTok': ['Fake shop links & dropship fraud', 'Deepfake celebrity investment endorsements', '"Like and earn" task scams'],
    'Telegram': ['Pump-and-dump groups', 'Impersonated admins DMing members', 'Fake "support bots" asking for seed phrases'],
    'WhatsApp': ['"Hi Mum/Dad" new-number impersonation', 'Task-job groups', 'Investment clubs with fake trading apps'],
    'Reddit': ['Astroturfed reviews', 'Fake "recovery expert" replies to scam victims'],
    'YouTube': ['Deepfake live streams with crypto QR codes', 'Comment-section "my advisor" testimonials'],
  };

  function extractEntities(text) {
    const urls = [...new Set((text.match(/\b((?:https?:\/\/|www\.)[^\s<>"')]+|[a-z0-9-]+\.(?:com|net|org|io|co|me|ly|xyz|top|link|app|site|online|info|ru|shop|live|click)(?:\/[^\s<>"')]*)?)/gi) || []).map(u => u.replace(/[.,;:!?]+$/, '')))];
    return {
      urls,
      emails: [...new Set(text.match(/[\w.+-]+@[\w-]+\.[\w.-]+/g) || [])],
      phones: [...new Set((text.match(/\+?\d[\d\s().-]{8,}\d/g) || []).map(s => s.trim()))],
      handles: [...new Set(text.match(/(?<![\w.])@[A-Za-z0-9_.]{3,30}/g) || [])],
      wallets: [
        ...(text.match(/\b(bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g) || []).map(w => ({ chain: 'Bitcoin', addr: w, explorer: `https://www.blockchain.com/explorer/addresses/btc/${w}` })),
        ...(text.match(/\b0x[a-fA-F0-9]{40}\b/g) || []).map(w => ({ chain: 'Ethereum/EVM', addr: w, explorer: `https://etherscan.io/address/${w}` })),
        ...(text.match(/\bT[1-9A-HJ-NP-Za-km-z]{33}\b/g) || []).map(w => ({ chain: 'Tron (USDT-TRC20)', addr: w, explorer: `https://tronscan.org/#/address/${w}` })),
      ],
      money: [...new Set(text.match(/(?:[$€£₹¥]\s?\d[\d,.]*\s?(?:k|m|million|billion)?|\d[\d,.]*\s?(?:usd|usdt|eur|gbp|btc|eth|dollars|euros))/gi) || [])],
      hashtags: [...new Set(text.match(/#[\p{L}\d_]{2,40}/gu) || [])],
    };
  }

  function analyzeUrl(raw) {
    const out = { url: raw, flags: [], risk: 0 };
    let u; try { u = new URL(/^https?:/i.test(raw) ? raw : 'https://' + raw); } catch { out.flags.push('Malformed URL'); out.risk = 20; return out; }
    const host = u.hostname.toLowerCase(); out.host = host;
    const parts = host.split('.'); const reg = parts.slice(-2).join('.'); const label = parts.length > 1 ? parts[parts.length - 2] : host;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) { out.flags.push('Raw IP address instead of a domain'); out.risk += 35; }
    if (host.startsWith('xn--') || host.includes('.xn--')) { out.flags.push('Punycode domain — may use lookalike Unicode letters'); out.risk += 35; }
    if (SHORTENERS.test(host)) { out.flags.push('URL shortener / redirector hides the real destination'); out.risk += 15; }
    if (RISKY_TLD.test(host)) { out.flags.push(`High-abuse top-level domain (.${parts[parts.length - 1]})`); out.risk += 15; }
    if (u.protocol === 'http:') { out.flags.push('Not encrypted (http)'); out.risk += 8; }
    if (u.username || raw.includes('@') && /https?:\/\/[^/]*@/.test(raw)) { out.flags.push('Contains "@" trick — the real host is after the @'); out.risk += 35; }
    if (parts.length >= 4) { out.flags.push(`Deep subdomain chain (${parts.length} levels) — e.g. paypal.com.secure-login.xyz`); out.risk += 12; }
    if ((host.match(/-/g) || []).length >= 2) { out.flags.push('Several hyphens in domain — common in throwaway phishing domains'); out.risk += 10; }
    const norm = LEET(label.replace(/-/g, ''));
    for (const b of BRANDS) {
      const official = reg.startsWith(b + '.') || reg === b + '.com';
      if (official) break;
      if (host.includes(b) && !official) { out.flags.push(`Uses brand name "${b}" but is not ${b}'s domain`); out.risk += 30; break; }
      if (norm !== label && norm.includes(b)) { out.flags.push(`Look-alike spelling of "${b}" (character substitution)`); out.risk += 35; break; }
      if (label.length >= 4 && lev(label, b) === 1) { out.flags.push(`One letter away from "${b}" — typosquat`); out.risk += 35; break; }
    }
    if (/login|signin|verify|secure|account|update|wallet|claim|bonus|airdrop|support/i.test(u.pathname + host) && out.risk > 0) { out.flags.push('Credential/claim keywords in the link'); out.risk += 8; }
    const track = [...u.searchParams.keys()].filter(k => /^(utm_|fbclid|gclid|igsh|si$|ref|aff|clickid|sub\d?)/i.test(k));
    if (track.length) out.tracking = track;
    out.risk = Math.min(100, out.risk);
    out.platform = PLATFORMS.find(([re]) => re.test(host))?.[1] || null;
    return out;
  }

  function coordination(text) {
    const signals = [];
    const tags = (text.match(/#[\p{L}\d_]+/gu) || []).length;
    if (tags >= 8) signals.push(`${tags} hashtags — hashtag stuffing for reach`);
    const lines = text.split(/\n+/).map(l => l.trim().toLowerCase()).filter(l => l.length > 25);
    const dup = lines.length - new Set(lines).size;
    if (dup >= 2) signals.push(`${dup} repeated lines — copy-paste posting, typical of comment networks / bots`);
    const mentions = (text.match(/@[A-Za-z0-9_.]+/g) || []).length; if (mentions >= 6) signals.push(`${mentions} @mentions — mass-tagging`);
    const emoji = (text.match(/\p{Extended_Pictographic}/gu) || []).length; if (emoji > 15) signals.push('Heavy emoji use typical of templated promo/spam posts');
    if (/\b(i (made|earned|got) \$?\d[\d,]*.{0,40}(thanks to|because of|with) (@|mr|mrs|ms|miss|dr)\b)/i.test(text)) signals.push('Testimonial praising a named "advisor" — signature of comment-network scams');
    const caps = (text.match(/\b[A-Z]{4,}\b/g) || []).length; if (caps > 6) signals.push('Excessive ALL-CAPS shouting');
    return signals;
  }

  function analyze({ text = '', url = '' }) {
    const full = `${text}\n${url}`;
    const hits = [];
    for (const [cat, w, re, label] of RULES) {
      const m = re.exec(full);
      if (m) { const i = Math.max(0, m.index - 40); hits.push({ category: cat, weight: w, label, excerpt: (i > 0 ? '…' : '') + full.slice(i, m.index + m[0].length + 40).replace(/\s+/g, ' ').trim() + '…', match: m[0] }); }
    }
    const entities = extractEntities(full);
    if (url && !entities.urls.includes(url)) entities.urls.unshift(url);
    const links = entities.urls.slice(0, 15).map(analyzeUrl);
    const coord = coordination(text);
    const platform = (url && PLATFORMS.find(([re]) => re.test(url))?.[1]) || links.find(l => l.platform)?.platform || null;

    // Score
    const byCat = {};
    hits.forEach(h => { byCat[h.category] = (byCat[h.category] || 0) + h.weight; });
    let score = hits.reduce((a, h) => a + h.weight, 0) * 0.85;
    const linkRisk = Math.max(0, ...links.map(l => l.risk)); score += linkRisk * 0.6;
    if (entities.wallets.length) score += 18;
    if (byCat['Payment rails'] && Object.keys(byCat).length > 2) score += 10; // combo: story + payment ask
    if (byCat['Pressure'] && (byCat['Phishing'] || byCat['Investment / crypto'] || byCat['Giveaway / prize'])) score += 10;
    score += coord.length * 11;
    if (Object.entries(byCat).some(([k, v]) => v >= 30 && !['Pressure', 'Impersonation', 'Manipulation / misinformation', 'Engagement bait'].includes(k))) score += 12; // several markers of the same scheme reinforce each other
    score = Math.round(Math.min(100, score));

    const scamCats = Object.entries(byCat).filter(([c]) => !['Pressure', 'Payment rails', 'Off-platform move', 'Manipulation / misinformation', 'Engagement bait', 'Impersonation'].includes(c)).sort((a, b) => b[1] - a[1]);
    const misinfo = (byCat['Manipulation / misinformation'] || 0) + (byCat['Engagement bait'] || 0);
    let verdict, category;
    if (score >= 70 && scamCats.length) { verdict = 'Scam'; category = scamCats[0][0]; }
    else if (score >= 50 && (scamCats.length || linkRisk >= 30)) { verdict = 'Likely scam'; category = scamCats[0]?.[0] || 'Phishing link'; }
    else if (coord.length >= 2) { verdict = 'Coordinated / inauthentic'; category = 'Coordinated inauthentic behaviour'; }
    else if (misinfo >= 16) { verdict = 'Misleading / manipulated'; category = 'Misinformation techniques'; }
    else if (score >= 25) { verdict = 'Suspicious'; category = scamCats[0]?.[0] || Object.keys(byCat)[0] || 'Unclear'; }
    else if (!text.trim() && !url) { verdict = 'Insufficient evidence'; category = '—'; }
    else { verdict = 'No strong red flags'; category = 'No known scheme matched'; }

    return { score, verdict, category, hits, byCategory: byCat, entities, links, coordination: coord, platform, playbook: platform ? PLATFORM_PLAYBOOK[platform] || [] : [] };
  }

  window.DeduceHeuristics = { analyze, analyzeUrl, PLATFORM_PLAYBOOK };
})();
