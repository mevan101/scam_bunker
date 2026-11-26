// Scam Bunker — Simple mode shell (docs/PRODUCT.md).
// One smart input → one plain answer → what to do → how to check it yourself.
// Adds to window.ScamBunker: mode(), setMode(), registerIntake(), addReasons(), addActions().
// Pure helpers (plain-language copy) are exported as window.ScamBunkerSimple for tests and other modules.
(() => {
  const root = typeof window !== 'undefined' ? window : globalThis;

  // =====================================================================================
  // 1. Plain-language copy (pure functions, no DOM)
  // =====================================================================================

  // Verdict → tone + sentence. Tone always ships with an icon and words, never colour alone.
  const VERDICTS = {
    'Scam': { tone: 'danger', title: 'This is very likely a scam' },
    'Likely scam': { tone: 'danger', title: 'This looks like a scam' },
    'Suspicious': { tone: 'warn', title: 'We found warning signs' },
    'Misleading / manipulated': { tone: 'warn', title: 'This looks like false or misleading information' },
    'Coordinated / inauthentic': { tone: 'warn', title: 'These look like fake, coordinated posts' },
    'AI-generated content': { tone: 'warn', title: 'This image appears to be made with AI' },
    'Edited image': { tone: 'warn', title: 'This photo was edited after it was taken' },
    'Likely legitimate': { tone: 'ok', title: 'No warning signs found, but stay careful' },
    'No strong red flags': { tone: 'ok', title: 'No warning signs found, but stay careful' },
    'Insufficient evidence': { tone: 'info', title: 'We couldn’t tell from this alone' },
  };
  const TONE_WORD = { danger: 'Danger', warn: 'Warning', ok: 'Looks OK', info: 'Not sure' };

  // Rule categories (public/scam.js) → what the scheme is, in plain words.
  const SCHEME = {
    'Phishing': 'a phishing message (an attempt to steal your login, card or codes)',
    'Investment / crypto': 'an investment or crypto scam',
    'Job / recruitment': 'a fake job offer',
    'Advance-fee': 'an advance-fee scam (pay a fee to receive money that never comes)',
    'Romance / pig-butchering': 'a romance or “wrong number” investment scam',
    'Impersonation': 'someone pretending to be a company or authority',
    'Giveaway / prize': 'a fake prize or giveaway',
    'Tech support': 'a fake tech-support scam',
    'Recovery scam': 'a fake “money recovery” service',
    'Mobile-money fraud': 'a mobile-money scam',
    'Family-emergency impersonation': 'someone pretending to be a family member',
    'Marketplace': 'a buying-and-selling scam',
    'Extortion': 'extortion (threats unless you pay)',
    'Payment rails': 'a request for a payment you can’t get back',
  };

  // Why a matched phrase matters, by rule category. Rule hits may carry their own `plain` sentence (preferred).
  const WHY = {
    'Phishing': 'Messages that rush you to log in, verify or confirm details are a common way to steal accounts and card numbers.',
    'Investment / crypto': 'Promises of guaranteed or very high returns are the clearest sign of an investment scam. Real investments always carry risk.',
    'Job / recruitment': 'Real employers don’t charge you to start, and don’t hire through chat apps without an interview.',
    'Advance-fee': 'Being asked to pay first to receive money, a prize or a job is the classic advance-fee scam.',
    'Manipulation / misinformation': 'This is a typical way false stories spread: urgency, secrecy and no source you can check.',
    'Romance / pig-butchering': 'A friendly “wrong number” or a sudden online friendship that turns to money is a known scam script.',
    'Pressure': 'Scammers rush you so you act before you think. Real organisations give you time.',
    'Payment rails': 'It wants a payment that can’t be reversed, such as crypto, gift cards or a wire transfer.',
    'Impersonation': 'It uses a trusted name. Scammers borrow well-known brands and authorities to look real.',
    'Giveaway / prize': 'Prizes you never entered for, especially ones that ask for a fee or your details, are almost always fake.',
    'Tech support': 'Real tech companies don’t contact you about viruses or ask for remote access to your device.',
    'Recovery scam': 'People who promise to get lost money back for a fee are running a second scam on victims.',
    'Mobile-money fraud': 'Mobile-money companies never ask for your PIN or code, or ask you to send back a “mistaken” payment.',
    'Family-emergency impersonation': 'A “family member” with a new number who urgently needs money is a common scam. Call them on the number you already have.',
    'Off-platform move': 'Moving the chat to WhatsApp or Telegram takes you away from the app’s protection and reporting tools.',
    'Marketplace': 'Overpayments, “courier” links and paying outside the marketplace are common buying-and-selling scams.',
    'Extortion': 'Threatening to share private material unless you pay is extortion. Paying rarely makes it stop.',
    'Engagement bait': 'Asking people to like, share or type a word is used to spread posts and build fake audiences.',
  };


  // Per-rule plain sentences (rule ids in public/scam.js). A hit's own `plain` field wins when present.
  const PLAIN = {
    'verify-details': 'It asks you to confirm your account or card details. Banks and shops never ask for these by message.',
    'account-threat': 'It says your account is locked or suspended to scare you into acting fast.',
    'click-link': 'It pushes you to tap a link. That is how fake sign-in pages are delivered.',
    'otp': 'It mentions a one-time code. Never share these codes: they let someone take over your account.',
    'seed-phrase': 'It asks for a wallet recovery phrase. Whoever has it can empty the wallet.',
    'wallet-drainer': 'It asks you to “validate” or “connect” your wallet to claim something. That is how wallets are drained.',
    'toll-smishing': 'Texts about an unpaid toll or fine with a payment link are a common scam.',
    'parcel-lure': 'Texts about a parcel that can’t be delivered unless you pay a small fee are a common scam.',
    'guaranteed-returns': 'It promises guaranteed or very high profits. Real investments always carry risk.',
    'multiplier-returns': 'It promises to multiply your money many times over. Real investments don’t work that way.',
    'crypto-vocab': 'It talks about crypto or trading, the subject of most investment scams.',
    'mentor': 'A stranger offering to be your trading “mentor” is a known investment-scam script.',
    'celebrity-platform': 'Ads where a celebrity “reveals” a trading platform are usually fake, often with doctored video.',
    'affection-money': 'Affection paired with talk of money is how romance scams work.',
    'wrong-number': 'A friendly “sorry, wrong number” message is a common way these scams start a conversation.',
    'romance-backstory': 'Stories like a soldier abroad or an oil-rig worker are common in romance scams.',
    'easy-job': 'High pay for little work, with no experience needed, is a sign of a fake job.',
    'task-jargon': 'Words like “product boosting” or “combination orders” come from task scams, where you pay to unlock earnings.',
    'pay-to-start': 'It asks you to pay before you start work. Real employers never charge you to get a job.',
    'prize': 'It says you have won or been selected, although you never entered anything.',
    'giveaway': 'Giveaways like this are used to collect your details or a “processing fee”.',
    'release-fee': 'It asks you to pay a fee to release money or a package. The money never arrives.',
    'pay-to-withdraw': 'It says you must pay a fee or tax before you can withdraw your own money. That is the end stage of many scams.',
    'inheritance': 'Stories about an unclaimed inheritance or fund are a classic advance-fee scam.',
    'gift-card': 'It asks for payment in gift cards. No real company or authority takes payment that way.',
    'irreversible-rails': 'It asks for a payment that can’t be reversed, such as crypto or a wire transfer.',
    'crypto-kiosk': 'It sends you to a crypto ATM. No real bank or authority asks you to pay that way.',
    'official-support': 'It claims to be official support. Real support teams don’t contact you first through chat apps.',
    'brand': 'It uses the name of a well-known company or authority to look trustworthy.',
    'fake-virus': 'Pop-ups or messages saying your device is infected are fake tech-support scams.',
    'remote-access': 'It asks you to install a remote-access app, which would let them control your device.',
    'recovery-promise': 'People who promise to get lost money back are usually running a second scam on victims.',
    'recovery-firm': '“Fund-recovery” firms that contact victims first are a known follow-up scam.',
    'overpayment': 'Overpaying and asking for the difference back, or a “courier” payment link, is a known marketplace scam.',
    'hi-mum': '“Hi Mum, this is my new number” messages are a common scam. Call your child on the number you already have.',
    'sextortion': 'Claims to have compromising images and demands for crypto are a mass-mailed extortion scam.',
    'off-platform': 'It moves the chat to WhatsApp or Telegram, away from the app’s protection and reporting tools.',
    'urgency': 'It rushes you (“act now”, “only today”) so you don’t stop to check.',
    'secrecy': 'It asks you to keep it secret, so nobody you trust can warn you.',
    'spread-bait': 'Phrases like “share before it’s deleted” are used to make false stories spread.',
    'sensational': 'Sensational wording like this is common in false or misleading posts.',
    'health-miracle': 'Miracle cures are a classic form of health misinformation.',
    'vague-authority': 'It appeals to unnamed “doctors” or “scientists” without a source you can check.',
    'engagement-bait': 'Asking people to like, share or type a word is used to spread posts and build fake audiences.',
    'mfs-pin': 'It asks for a bKash, Nagad or Rocket PIN or code. The real services never ask for these.',
    'wrong-send': '“I sent money to your number by mistake, please send it back” is a known mobile-money scam.',
    'mfs-office': 'Callers claiming to be from the bKash, Nagad or Rocket office are a common scam.',
    'account-block': 'It threatens that your account or SIM will be blocked, to make you panic.',
    'job-fee': 'It asks for a registration or processing fee for a job or visa. Real employers don’t charge this.',
    'easy-income': '“Earn from home every day” offers are a common way fake jobs begin.',
    'free-visa': '“Free visa” overseas-job offers are common in labour-migration fraud.',
  };
  let ctxIds = null;
  const contextIds = () => ctxIds || (ctxIds = new Set((root.DeduceHeuristics?.RULES || []).filter(r => r.context).map(r => r.id)));
  const plainFor = x => x.plain || PLAIN[x.id] || PLAIN[String(x.id || '').replace(/^(bn|i18n)-/, '')] || (x.id === 'bn-urgency' && PLAIN.urgency) || (x.id === 'bn-prize' && PLAIN.prize) || (x.id === 'bn-prize-fee' && PLAIN['release-fee']) || (x.id === 'bn-otp' && PLAIN.otp) || WHY[x.category] || `${x.label}.`;

  // Link flags (scam.js analyzeUrl) → plain sentences. First match wins; order = most telling first.
  const LINK_FLAGS = [
    [/Uses brand name "([^"]+)"/, m => `It uses the name “${m[1]}”, but it is not ${m[1]}’s real website.`],
    [/Look-alike spelling of "([^"]+)"/, m => `The address is spelled to look like “${m[1]}”, but it isn’t.`],
    [/One letter away from "([^"]+)"/, m => `The address is one letter away from “${m[1]}”, a trick called typosquatting.`],
    [/Punycode/, () => 'The address uses look-alike letters from other alphabets to imitate a real site.'],
    [/"@" trick/, () => 'The link uses an “@” trick to hide the website it really opens.'],
    [/Raw IP address/, () => 'The link points to a bare number (an IP address) instead of a website name.'],
    [/Deep subdomain chain/, () => 'A real-looking name sits at the start of the address, but the real website is the part at the end.'],
    [/High-abuse top-level domain \(([^)]+)\)/, m => `The address ends in ${m[1]}, an ending that is cheap and widely used for scam sites.`],
    [/shortener/i, () => 'The link is shortened, which hides where it really goes.'],
    [/Several hyphens/, () => 'The website name has several hyphens, which is common for throwaway scam sites.'],
    [/Credential\/claim keywords/, () => 'The link contains words like “login” or “verify”, used to make fake sign-in pages look real.'],
    [/Not encrypted/, () => 'The link is not secure (it starts with http, not https).'],
  ];
  const plainLinkFlag = flag => { for (const [re, f] of LINK_FLAGS) { const m = String(flag || '').match(re); if (m) return f(m); } return flag ? `${flag}.` : ''; };

  const RISK_WORDS = [[70, 'Very high'], [50, 'High'], [25, 'Medium'], [0, 'Low']];
  const riskWord = n => (RISK_WORDS.find(([t]) => (+n || 0) >= t) || RISK_WORDS[3])[1];
  const WEIGHT_WORD = { proof: 'Proof', strong: 'Strong sign', moderate: 'Warning sign', weak: 'Weak hint', ok: 'Reassuring', info: 'Good to know' };
  const RANK = { proof: 0, strong: 1, moderate: 2, info: 3, weak: 4, ok: 5 };
  const short = (s, n = 70) => { s = String(s || '').replace(/\s+/g, ' ').trim(); return s.length > n ? s.slice(0, n - 1) + '…' : s; };

  function verdictCopy(v, c) {
    const base = VERDICTS[v.verdict] || { tone: 'info', title: v.verdict || 'Checked' };
    const scheme = SCHEME[v.category] || SCHEME[c?.heuristics?.category];
    const sub = {
      danger: `${scheme ? `It matches ${scheme}. ` : ''}Don’t pay, don’t click any links and don’t reply.`,
      warn: v.verdict === 'Suspicious' ? `${scheme ? `It has signs of ${scheme}. ` : ''}Check it through a channel you trust before you do anything.`
        : v.verdict === 'Misleading / manipulated' ? 'It uses tricks common in false stories and gives no source you can check. Don’t share it yet.'
        : v.verdict === 'Coordinated / inauthentic' ? 'The same words are repeated as if by different people. Treat the testimonials as fake.'
        : v.verdict === 'AI-generated content' ? 'Don’t treat it as a photo of a real event or person.'
        : v.verdict === 'Edited image' ? 'It came from a real camera but went through editing software, so it may not show what really happened.'
        : 'Be careful before you act on it.',
      ok: 'None of the scam or manipulation patterns we know matched. That isn’t a guarantee: if it asks for money or details, check with the sender another way.',
      info: 'There isn’t enough here to judge. Paste more of the message, or add a screenshot.',
    }[base.tone];
    return { tone: base.tone, toneWord: TONE_WORD[base.tone], title: base.title, sub, risk: +v.risk || 0, riskWord: riskWord(v.risk) };
  }

  // Plain reasons, strongest first, each quoting the exact words or detail it is about.
  function plainReasons(c) {
    const out = [], h = c.heuristics || { hits: [], links: [], entities: {}, coordination: [] }, f = c.forensics;
    (c.offenders || []).forEach(o => out.push({ weight: 'strong', quote: o.label, text: `This ${o.type} also appeared in ${o.cases.length} earlier message${o.cases.length > 1 ? 's' : ''} checked on this device. Scammers change their stories but rarely their numbers or wallets.`, source: 'offenders' }));
    const seen = new Set(), hits = (h.hits || []).slice().sort((a, b) => b.weight - a.weight);
    hits.forEach(x => {
      const key = x.id || x.label; if (seen.has(key)) return; seen.add(key);
      if ((x.context || contextIds().has(x.id)) && hits.length > 2) return; // broad context signals only matter when little else fired
      const w = x.weight >= 20 ? 'strong' : x.weight >= 14 ? 'moderate' : 'weak';
      out.push({ weight: w, quote: short(x.match, 60), text: plainFor(x), source: 'rules', category: x.category });
    });
    (h.links || []).filter(l => l.risk >= 15 && l.flags?.length).forEach(l => out.push({ weight: l.risk >= 35 ? 'strong' : 'moderate', quote: l.host || l.url, text: plainLinkFlag(l.flags[0]), source: 'links' }));
    (h.entities?.wallets || []).forEach(w => out.push({ weight: 'strong', quote: `${w.addr.slice(0, 10)}…`, text: `It asks you to send cryptocurrency to a wallet (${w.chain}). Crypto payments can’t be reversed or refunded.`, source: 'wallets' }));
    if ((h.coordination || []).length) out.push({ weight: 'moderate', quote: short(h.coordination[0], 60), text: 'The same words are repeated as if by different people, which points to fake or coordinated accounts.', source: 'coordination' });
    if (f) {
      if (['confirmed', 'likely'].includes(f.ai?.verdict)) out.push({ weight: f.ai.verdict === 'confirmed' ? 'proof' : 'strong', quote: f.ai.generators?.[0] || '', text: f.ai.verdict === 'confirmed' ? 'The file itself declares that it was made with an AI tool.' : 'The file carries the fingerprint of an AI image generator.', source: 'image' });
      else if (f.ai?.verdict === 'possible') out.push({ weight: 'weak', quote: '', text: 'Some details of the picture are typical of AI images, but that alone proves nothing.', source: 'image' });
      if (f.editors?.length) out.push({ weight: 'moderate', quote: f.editors[0], text: 'The photo was saved in editing software after it was taken, so it may have been changed.', source: 'image' });
      if (f.earliest) out.push({ weight: 'info', quote: String(f.earliest.when).replace('T', ' ').slice(0, 16), text: `The file says it was taken on this date. If a post says it shows something newer, the photo may be old or reused.`, source: 'image' });
      else if (f.exif && !Object.keys(f.exif).length) out.push({ weight: 'info', quote: '', text: 'The photo’s hidden details (date, camera) were removed, as happens on social media. A reverse image search (below) can show when it first appeared.', source: 'image' });
    }
    (c.simpleReasons || []).forEach(r => out.push({ weight: r.weight || 'moderate', quote: r.quote || '', text: r.text, source: r.source || 'module' }));
    if (!out.length) out.push({ weight: 'ok', quote: '', text: 'None of the scam, manipulation or AI patterns we know matched.', source: 'rules' });
    return out.sort((a, b) => (RANK[a.weight] ?? 9) - (RANK[b.weight] ?? 9)).slice(0, 5);
  }

  // What to do now, tailored to the verdict and scheme. Rule hits may carry an `advice` key (preferred when the map exists).
  function plainActions(c, v) {
    const h = c.heuristics || { hits: [], links: [], entities: {} }, cat = v.category || h.category || '', where = c.platform ? `on ${c.platform}` : 'in the app it came from';
    const acts = [], add = (text, href, label) => { if (!acts.some(a => a.text === text)) acts.push({ text, href, label }); };
    const ADV = root.DeduceHeuristics?.ADVICE;
    if (ADV) (h.hits || []).forEach(x => { const a = x.advice && ADV[x.advice]; if (a) typeof a === 'string' ? add(a) : add(a.text, a.href, a.label); });
    const scammy = ['Scam', 'Likely scam', 'Suspicious'].includes(v.verdict);
    if (scammy) {
      add('Don’t send money, gift cards or crypto, and never share codes, PINs or passwords.');
      if ((h.links || []).length) add('Don’t open the link or download anything it asks you to install.');
      if (/Phishing|Impersonation/.test(cat)) add('Worried about your account? Open the official app, or type the company’s address yourself, or call the number on the back of your card.');
      if (/Job/.test(cat)) add('Look the job up on the company’s official careers page. Real employers never charge a fee to start.');
      if (/Investment|Romance/.test(cat)) add('Don’t invest or move money because someone you only know online suggests it. Check that any firm is registered with your financial regulator.');
      if (/Mobile-money/.test(cat)) add('Never share your PIN or code. If in doubt, call your provider’s helpline from its official app or website.');
      if (/Family/.test(cat)) add('Call your family member on the number you already have before doing anything.');
      if (/Recovery/.test(cat)) add('Nobody can recover lost money for an upfront fee. Report the loss to your bank and the police instead.');
      if (/Extortion/.test(cat)) add('Don’t pay. Save the messages, stop replying, and report it to the platform and the police.');
      if (/Tech support/.test(cat)) add('Don’t give anyone remote access to your device. Close the page and contact the company through its official website.');
      if (/Giveaway|Advance-fee/.test(cat)) add('You never have to pay to receive a real prize, refund or payment.');
      add(`Stop replying. Block the sender and report the message ${where}.`);
      add('Already paid or shared details? Contact your bank or payment provider now, change your passwords, and report it.', 'https://www.econsumer.gov/', 'Report a scam (econsumer.gov, many countries)');
      if ((h.links || []).some(l => l.risk >= 25)) add('Report the website so browsers can warn other people.', 'https://safebrowsing.google.com/safebrowsing/report_phish/', 'Report a phishing site to Google');
    } else if (v.verdict === 'Misleading / manipulated') {
      add('Don’t share it yet.'); add('Look for the same claim on trusted news or fact-check sites (see “Check it yourself”).'); add('If you already shared it, consider posting a correction.');
    } else if (v.verdict === 'Coordinated / inauthentic') {
      add('Treat the testimonials as fake, and don’t contact the account they promote.'); add(`Report the accounts as spam ${where}.`);
    } else if (['AI-generated content', 'Edited image'].includes(v.verdict)) {
      add('Don’t treat the image as proof that something happened.'); add('Look for the original with a reverse image search (see “Check it yourself”).'); add('Ask the person who shared it where it came from.');
    } else if (v.verdict === 'Insufficient evidence') {
      add('Paste the whole message, or add a screenshot of it.');
    } else {
      add('If it asks for money, codes or personal details, check with the person or company through a channel you already trust.');
      add('Still unsure? Open the full investigation, or ask Claude for a second opinion.');
    }
    (c.simpleActions || []).forEach(a => add(a.text, a.href, a.label));
    return acts;
  }

  // One-click ways to check it yourself (they teach the method).
  function selfChecks(c, v) {
    const out = [], h = c.heuristics || { links: [], entities: {} }, f = c.forensics;
    const add = (label, href, how) => { if (/^https?:\/\//i.test(href) && out.length < 8 && !out.some(o => o.href === href)) out.push({ label, href, how }); };
    (f?.reverse || []).slice(0, 3).forEach(r => add(`Search for this image on ${r.name}`, r.url, r.how));
    const BIG = /(^|\.)(facebook|instagram|linkedin|twitter|x|tiktok|youtube|google|whatsapp|telegram|lnkd|bit|t)\.(com|ly|me|in|co)$/i;
    (h.links || []).filter(l => l.host && !BIG.test(l.host)).slice(0, 2).forEach(l => {
      const host = l.host.replace(/^www\./, '');
      add(`See when ${host} was registered`, `https://who.is/whois/${encodeURIComponent(host)}`, 'Scam sites are often only days or weeks old.');
      add(`Check ${host} with Google Safe Browsing`, `https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(host)}`, 'Shows whether Google has flagged the site as dangerous.');
    });
    (h.entities?.phones || []).slice(0, 1).forEach(p => add(`Search the number ${p}`, `https://www.google.com/search?q=${encodeURIComponent(`"${p}" scam`)}`, 'Other people often report scam numbers online.'));
    (h.entities?.wallets || []).slice(0, 1).forEach(w => add('See the wallet’s payments on a block explorer', w.explorer, 'Shows how much money this address has received.'));
    (h.entities?.handles || []).slice(0, 1).forEach(x => add(`Search for ${x}`, `https://www.google.com/search?q=${encodeURIComponent(`"${x}" scam`)}`, 'See whether others have reported this account.'));
    const claim = String(c.text || '').replace(/https?:\S+/g, '').replace(/[#@]\w+/g, '').replace(/\s+/g, ' ').trim().split(/(?<=[.!?])\s/).sort((a, b) => b.length - a.length)[0];
    if (claim && (v.verdict === 'Misleading / manipulated' || !['Scam', 'Likely scam'].includes(v.verdict))) add('Look for existing fact-checks of this claim', `https://toolbox.google.com/factcheck/explorer/search/${encodeURIComponent(short(claim, 90).replace(/…$/, ''))};hl=en`, 'Google Fact Check Explorer collects work by fact-checkers worldwide.');
    return out;
  }

  // "Hidden in this file", in plain words.
  function plainHidden(hidden) {
    const map = [
      [/^GPS location: (.+)$/, m => `This photo still contains the exact place it was taken (${m[1]}). Remove the location before sharing your own photos.`],
      [/^Camera serial number: (.+)$/, m => `It contains the serial number of the camera that took it (${m[1]}).`],
      [/^Camera owner name: (.+)$/, m => `It contains the camera owner’s name (${m[1]}).`],
      [/^(Artist field|XMP creator|Copyright): (.+)$/, m => `It contains a name: ${m[2]}.`],
      [/^Location in XMP: (.+)$/, m => `It names a place: ${m[1]}.`],
      [/^Device: (.+)$/, m => `It says which camera or phone took it: ${m[1]}.`],
      [/AI prompt/, () => 'It contains the text prompt that was used to generate it with AI.'],
      [/^Original document ID/, () => 'It contains an ID that links it to the original file it was made from.'],
    ];
    return (hidden || []).map(x => { for (const [re, f] of map) { const m = String(x).match(re); if (m) return f(m); } return String(x); });
  }

  function summaryText(c, v, url) {
    const vc = verdictCopy(v, c);
    return [`Scam Bunker check: ${vc.title} (scam risk: ${vc.riskWord.toLowerCase()}).`, vc.sub, '', 'Why:', ...plainReasons(c).map(r => `- ${r.quote ? `“${r.quote}”: ` : ''}${r.text}`), '', 'What to do:', ...plainActions(c, v).map(a => `- ${a.text}`), '', `Checked with Scam Bunker, a free and private checker${url ? `: ${url}` : '.'}`].join('\n');
  }

  // Built-in intake adapters. Others (OCR, QR, email headers, phone) register through ScamBunker.registerIntake.
  const isVideoFile = f => !!f && (/^video\//.test(f.type) || /\.(mp4|m4v|mov|webm|mkv)$/i.test(f.name || ''));
  const isImageFile = f => !!f && (/^image\//.test(f.type) || /\.(heic|heif|avif|webp|jpe?g|png|gif)$/i.test(f.name || ''));
  const URL_ONLY = /^(https?:\/\/\S+|(www\.)?[a-z0-9-]+(\.[a-z0-9-]+)+(\/\S*)?)$/i;
  const BUILTIN_INTAKES = [
    { id: 'video', label: 'Video', detect: i => isVideoFile(i.file) ? 1 : 0, async extract(i) { return { text: i.text || '', attachments: [i.file], notes: ['We read the video file on your device.'] }; } },
    { id: 'image', label: 'Photo or screenshot', detect: i => isImageFile(i.file) ? 0.9 : 0, async extract(i) { return { text: i.text || '', attachments: [i.file] }; } },
    { id: 'url', label: 'Link', detect: i => !i.file && URL_ONLY.test(String(i.text || '').trim()) ? 0.95 : 0, async extract(i) { const t = String(i.text).trim(); return { text: '', url: /^https?:/i.test(t) ? t : 'https://' + t }; } },
    { id: 'text', label: 'Message or post', detect: i => !i.file && String(i.text || '').trim() ? 0.6 : 0, async extract(i) { return { text: String(i.text || '').trim() }; } },
  ];
  function pickIntake(list, input) {
    let best = null, score = 0;
    for (const a of list) { let s = 0; try { s = +a.detect(input) || 0; } catch { } if (s > score) { best = a; score = s; } }
    return score > 0.5 ? best : null;
  }

  root.ScamBunkerSimple = { VERDICTS, SCHEME, WHY, PLAIN, plainFor, riskWord, plainLinkFlag, verdictCopy, plainReasons, plainActions, selfChecks, plainHidden, summaryText, pickIntake, BUILTIN_INTAKES };
  if (typeof document === 'undefined' || !root.ScamBunker) return; // tests / no app

  // =====================================================================================
  // 2. Shell (DOM)
  // =====================================================================================
  const SB = root.ScamBunker, esc = SB.esc, $ = s => document.querySelector(s), $$ = s => [...document.querySelectorAll(s)];
  const html = document.documentElement;
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');

  // ---------- Mode ----------
  const MODES = ['simple', 'investigator'];
  const readMode = () => { try { const m = localStorage.getItem('scambunker.mode'); return MODES.includes(m) ? m : 'simple'; } catch { return 'simple'; } };
  let mode = html.dataset.mode = MODES.includes(html.dataset.mode) ? html.dataset.mode : readMode();
  function setMode(m, { silent } = {}) {
    if (!MODES.includes(m)) return;
    const changed = m !== mode; mode = html.dataset.mode = m;
    try { localStorage.setItem('scambunker.mode', m); } catch { }
    $$('[data-mode-set]').forEach(b => b.setAttribute('aria-pressed', b.dataset.modeSet === m));
    if (m === 'simple' && SB.current) render(SB.current);
    if (changed && !silent) document.dispatchEvent(new CustomEvent('sb:mode', { detail: { mode: m } }));
  }
  $$('[data-mode-set]').forEach(b => b.addEventListener('click', () => setMode(b.dataset.modeSet)));
  setMode(mode, { silent: true });

  // ---------- Tour + guide ----------
  $('#btn-tour')?.addEventListener('click', () => document.dispatchEvent(new CustomEvent('sb:tour', { detail: { mode } })));
  // The guide page ships separately (public/guide.html); hide the link until it exists.
  const guide = $('a.top-link[href="guide.html"]');
  if (guide) fetch('guide.html', { method: 'HEAD', cache: 'no-store' }).then(r => { if (!r.ok) guide.hidden = true; }).catch(() => { guide.hidden = true; });

  // ---------- Intake ----------
  const intakes = [...BUILTIN_INTAKES];
  function registerIntake(a) {
    if (!a || !a.id || typeof a.detect !== 'function' || typeof a.extract !== 'function') throw new Error('registerIntake needs { id, label, detect(input), extract(input) }');
    const i = intakes.findIndex(x => x.id === a.id); if (i >= 0) intakes.splice(i, 1);
    intakes.unshift(a); // newest first: a specialised adapter wins ties against the built-ins
  }

  const form = $('#s-form'), ta = $('#s-text'), fileIn = $('#s-fileinput'), go = $('#s-go'), status = $('#s-status'), result = $('#s-result');
  let file = null, pendingIntake = null, runId = 0, awaiting = 0;

  function setFile(f) {
    file = f || null;
    const box = $('#s-file'); box.hidden = !file;
    if (file) {
      const thumb = $('#s-thumb');
      if (isImageFile(file)) { thumb.src = URL.createObjectURL(file); thumb.hidden = false; } else thumb.hidden = true;
      $('#s-file-name').textContent = `${file.name || 'Pasted image'} · ${Math.max(1, Math.round(file.size / 1024))} KB`;
    } else fileIn.value = '';
  }
  fileIn.addEventListener('change', () => fileIn.files[0] && setFile(fileIn.files[0]));
  $('#s-file-remove').addEventListener('click', () => { setFile(null); ta.focus(); });
  ['dragenter', 'dragover'].forEach(e => form.addEventListener(e, ev => { ev.preventDefault(); form.classList.add('over'); }));
  ['dragleave', 'drop'].forEach(e => form.addEventListener(e, ev => { ev.preventDefault(); form.classList.remove('over'); }));
  form.addEventListener('drop', ev => { const f = ev.dataTransfer?.files?.[0]; if (f) setFile(f); });
  // Pasting an image anywhere in Simple mode attaches it (app.js handles paste for Investigator mode).
  document.addEventListener('paste', e => { if (mode !== 'simple') return; const it = [...(e.clipboardData?.items || [])].find(i => i.kind === 'file'); if (it) { e.stopImmediatePropagation(); setFile(it.getAsFile()); } }, true);
  ta.addEventListener('keydown', e => { if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) { e.preventDefault(); e.stopPropagation(); form.requestSubmit(); } });

  // Hand the material to the investigator intake (app.js) and run the normal engines.
  function feedApp({ text, url, file: f }) {
    $('#text').value = text || ''; $('#url').value = url || ''; $('#platform').value = '';
    const fi = $('#file');
    if (f) { const dt = new DataTransfer(); dt.items.add(f); fi.files = dt.files; fi.dispatchEvent(new Event('change', { bubbles: true })); }
    else $('#clear-img').click();
  }
  function startChecking(label) {
    awaiting = ++runId; html.dataset.simpleState = 'checking';
    status.textContent = label || 'Checking…'; go.disabled = true; go.textContent = 'Checking…';
  }
  function stopChecking() { go.disabled = false; go.textContent = 'Check it'; status.textContent = ''; delete html.dataset.simpleState; }

  form.addEventListener('submit', async e => {
    e.preventDefault();
    const input = { text: ta.value, file };
    if (!input.text.trim() && !input.file) { showError('Paste a message, link, number or email, or add a screenshot first.'); ta.focus(); return; }
    const adapter = pickIntake(intakes, input);
    if (!adapter) { showError('We can’t read this kind of file yet. Try a screenshot or photo (JPG, PNG), a video, or paste the text.'); return; }
    startChecking(`Checking your ${adapter.label ? adapter.label.toLowerCase() : 'input'}…`);
    let out = {};
    try { out = (await adapter.extract(input)) || {}; }
    catch (err) { console.error(err); out = { notes: [`We couldn’t read it as ${adapter.label || adapter.id}; checking the rest.`] }; }
    const text = [out.text !== undefined ? out.text : input.text].concat(out.text !== undefined && input.text.trim() && !String(out.text).includes(input.text.trim()) && adapter.id !== 'url' ? [input.text] : []).filter(Boolean).join('\n\n').trim();
    const att = (out.attachments || []).find(x => x && typeof x === 'object' && 'size' in x) || (out.attachments ? null : input.file);
    pendingIntake = { adapter: adapter.id, label: adapter.label || adapter.id, notes: out.notes || [], attachments: out.attachments || [] };
    if (!text && !out.url && !att) { stopChecking(); showError('We couldn’t find anything to check in that. Try pasting the text instead.'); return; }
    feedApp({ text, url: out.url || '', file: att });
    $('#go').click();
  });

  // Example chips reuse app.js samples ([data-sample]); clear any attached file first, then mirror the text.
  document.addEventListener('click', e => {
    const chip = e.target.closest('#simple [data-sample]'); if (!chip) return;
    setFile(null); $('#clear-img').click(); pendingIntake = { adapter: 'example', label: 'Example', notes: [] };
    startChecking('Checking the example…');
  }, true);
  $$('#simple [data-sample]').forEach(b => b.addEventListener('click', () => { ta.value = $('#text').value; }));

  // If the run ends without a case (an error was toasted), never leave a spinner.
  new MutationObserver(() => { if (!$('#go').disabled && html.dataset.simpleState === 'checking') { stopChecking(); if (awaiting) showError('We couldn’t finish checking this. Please try again, or paste the text instead.'); } }).observe($('#go'), { attributes: true, attributeFilter: ['disabled'] });

  document.addEventListener('sb:case', e => {
    const c = e.detail; if (!c) return;
    if (pendingIntake) { c.intake = pendingIntake; pendingIntake = null; }
    awaiting = 0; stopChecking(); render(c, { reveal: mode === 'simple' });
  });
  document.addEventListener('sb:case-complete', e => { if (e.detail === SB.current) render(e.detail); });

  function showError(msg) {
    result.hidden = false;
    result.innerHTML = `<div class="s-card s-error" role="alert"><h2 class="s-err-h">${esc(msg)}</h2></div>`;
  }

  // ---------- Module contracts ----------
  function addReasons(c, list) { if (!c) return; c.simpleReasons = [...(c.simpleReasons || []), ...(list || []).filter(r => r && r.text)]; if (c === SB.current) render(c); }
  function addActions(c, list) { if (!c) return; c.simpleActions = [...(c.simpleActions || []), ...(list || []).filter(a => a && a.text && (!a.href || /^https?:\/\//i.test(a.href)))]; if (c === SB.current) render(c); }

  // ---------- Render ----------
  const ICON = {
    danger: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8.3 2.5h7.4l5.3 5.3v7.4l-5.3 5.3H8.3L3 15.2V7.8z"/><path d="M12 7.5v5.5M12 16.4v.1"/></svg>',
    warn: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3.2 22 20.5H2z"/><path d="M12 9.5v5M12 17.6v.1"/></svg>',
    ok: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9.5"/><path d="m7.8 12.3 2.9 2.9 5.6-6"/></svg>',
    info: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9.5"/><path d="M12 11v6M12 7.6v.1"/></svg>',
    ext: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M6 3.5H3.5v9h9V10M9 3h4v4M13 3 7.5 8.5"/></svg>',
    eye: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/><circle cx="12" cy="12" r="3"/></svg>',
  };
  const BAR_N = { 'Low': 1, 'Medium': 2, 'High': 3, 'Very high': 4 };

  function render(c, { reveal } = {}) {
    if (!c) return;
    const v = c.final || c.local; if (!v) return;
    const vc = verdictCopy(v, c), reasons = plainReasons(c), acts = plainActions(c, v), checks = selfChecks(c, v), hidden = plainHidden(v.hidden_info || c.forensics?.hidden);
    const srv = SB.server(), agents = srv.ai ? `AI agents are reviewing it too (${esc(srv.provider || 'on')}).` : 'For a second opinion, ask Claude.';
    const intakeNote = c.intake && c.intake.adapter !== 'example' ? [`We checked it as: ${esc((c.intake.label || '').toLowerCase())}.`, ...(c.intake.notes || []).map(esc)].join(' ') : '';
    const n = BAR_N[vc.riskWord];
    result.hidden = false;
    result.innerHTML = `
      <article class="s-card s-verdict tone-${vc.tone}" data-tour="verdict" aria-labelledby="s-verdict-h">
        <div class="s-v-top"><span class="s-v-icon">${ICON[vc.tone]}</span><span class="s-v-word">${esc(vc.toneWord)}</span></div>
        <h2 id="s-verdict-h" tabindex="-1">${esc(vc.title)}</h2>
        <p class="s-v-sub">${esc(vc.sub)}</p>
        <div class="s-risk" title="Scam risk score: ${vc.risk} out of 100">
          <span class="s-risk-label">Scam risk</span>
          <span class="s-risk-bars" aria-hidden="true">${[1, 2, 3, 4].map(i => `<i class="${i <= n ? 'on' : ''}"></i>`).join('')}</span>
          <b class="s-risk-word">${esc(vc.riskWord)}</b>
        </div>
      </article>

      <section class="s-card s-sec" data-tour="reasons" aria-labelledby="s-why-h">
        <h3 id="s-why-h">Why we think so</h3>
        <ol class="s-reasons">${reasons.map(r => `<li class="w-${esc(r.weight)}"><span class="w ${esc(r.weight)}">${esc(WEIGHT_WORD[r.weight] || r.weight)}</span>${r.quote ? `<q>${esc(r.quote)}</q>` : ''}<p>${esc(r.text)}</p></li>`).join('')}</ol>
      </section>

      <section class="s-card s-sec" data-tour="actions" aria-labelledby="s-do-h">
        <h3 id="s-do-h">What to do now</h3>
        <ol class="s-actions">${acts.map(a => `<li><span class="s-tick" aria-hidden="true"></span><p>${esc(a.text)}${a.href ? ` <a href="${esc(a.href)}" target="_blank" rel="noopener noreferrer">${esc(a.label || 'Open')}<span class="sr-only"> (opens in a new tab)</span></a>` : ''}</p></li>`).join('')}</ol>
      </section>

      ${checks.length ? `<section class="s-card s-sec" aria-labelledby="s-self-h">
        <h3 id="s-self-h">Check it yourself</h3>
        <p class="s-sec-lede">Each button opens a free tool, so you can see the evidence with your own eyes.</p>
        <ul class="s-tools">${checks.map(x => `<li><a class="s-tool" href="${esc(x.href)}" target="_blank" rel="noopener noreferrer"><span><b>${esc(x.label)}</b>${x.how ? `<small>${esc(x.how)}</small>` : ''}</span>${ICON.ext}<span class="sr-only"> (opens in a new tab)</span></a></li>`).join('')}</ul>
      </section>` : ''}

      ${hidden.length ? `<section class="s-card s-sec s-hidden" aria-labelledby="s-hid-h">
        <h3 id="s-hid-h"><span class="s-h-icon">${ICON.eye}</span>Hidden in this file</h3>
        <ul class="s-hidden-list">${hidden.map(x => `<li>${esc(x)}</li>`).join('')}</ul>
      </section>` : ''}

      <footer class="s-foot">
        <div class="s-foot-actions">
          <button type="button" class="ghost s-btn" data-open-full>Open full investigation</button>
          <button type="button" class="ghost s-btn" data-copy-simple>Copy a summary to share</button>
          <button type="button" class="ghost s-btn" data-handoff>Ask Claude about this ↗</button>
        </div>
        <p class="s-quiet">${SB.isStatic() ? 'Checked in your browser. Nothing was uploaded.' : 'Checked on your device. Nothing was uploaded.'} ${agents}${intakeNote ? ` ${intakeNote}` : ''}</p>
      </footer>`;
    if (reveal) {
      const h = $('#s-verdict-h');
      result.scrollIntoView({ behavior: reduced.matches ? 'auto' : 'smooth', block: 'start' });
      h.focus({ preventScroll: true });
    }
  }

  result.addEventListener('click', async e => {
    if (e.target.closest('[data-open-full]')) {
      setMode('investigator'); SB.showTab('deduction');
      scrollTo(0, 0);
      const t = $('#v-title'); if (t && !$('#report').hidden) { t.setAttribute('tabindex', '-1'); t.focus({ preventScroll: true }); }
    }
    if (e.target.closest('[data-copy-simple]')) {
      const c = SB.current; if (!c) return;
      try { await navigator.clipboard.writeText(summaryText(c, c.final || c.local, location.origin + location.pathname)); SB.toast('Summary copied. Paste it wherever you want to share it'); }
      catch { SB.toast('Your browser blocked copying. Select the text and copy it instead'); }
    }
  });

  // Public API
  Object.assign(SB, { mode: () => mode, setMode, registerIntake, addReasons, addActions, intakes: () => intakes.map(a => ({ id: a.id, label: a.label })) });
  document.addEventListener('sb:ready', () => { if (mode === 'simple' && SB.current) render(SB.current); });
})();
