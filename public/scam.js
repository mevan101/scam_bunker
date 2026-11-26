// Scam Bunker heuristic engine — scam / manipulation / coordination detection. Runs offline.
(function () {
  // Rule: [category, weight, regex, label, opts]
  //   opts.id        stable id; every id needs >= 2 should-match and >= 2 should-not-match phrases in test/rules.test.js
  //   opts.signature near-diagnostic on its own: with a payment or credential ask present the score is raised to "Likely scam"
  //   opts.ask       the match itself is a payment or credential request
  //   opts.scheme    verdict category to use when the rule's own category is not a scheme (e.g. Payment rails)
  //   opts.context   deliberately broad context signal with a low weight; never enough on its own
  //   opts.plain     one-sentence reason an ordinary person understands (shown in Simple mode)
  //   opts.advice    action key into ADVICE (what to do next); both are copied onto every hit
  //   opts.lang      'bn' = Bangla (Bengali script) + Banglish pack, 'i18n' = translated rules
//   opts.unless    guard regex tested on the sentence around the match (opts.unlessScope 'adjacent' adds one sentence each side, 'message' tests the whole message)
  const NEG = String.raw`(?<!\b(never|not|don'?t|do not|won'?t|will not|nobody|no one|cannot|can'?t)\b[^.!?\n]{0,40})`;
  const GIFT = String.raw`(gift ?cards?|(itunes|steam|google play|apple|amazon|ebay|razer gold)( gift)? cards?)`;
  const SAFETY_NOTICE = /\b(never|do not|don['’]?t|won['’]?t|will not)\b[^.!?\n]{0,20}\b(share|disclose|forward|give|tell|text|read out|enter|type|input|ask (you )?for)\b[^.!?\n]{0,25}\b(codes?|otp|pin|it|this)\b|\b(never|do not|don['’]?t)\s+(share|send|disclose|forward|give|tell)\s+(it\s+|this\s+)?(with|to)\s+(anyone|anybody|others|someone)\b|\b(never|do not|don'?t)\s+send\s+(this|the|your)\s+([\w-]+\s+){0,2}(codes?|otp|pin)\b|(কাউকে|দিবেন না|দেবেন না|বলবেন না|শেয়ার করবেন না|\bkauke\b|\bdiben na\b)/i;
  // An explicit request to hand the code over (not negated) outweighs any safety footer in the same message.
  const CODE_ASK = /(?<!(\bnever|\bnot|n['’]t)\s(ever\s|\w+ly\s)?)\b(send|share|provide|reply with|text|read|tell|give|forward)\b( (it )?(to )?(me|us|back))?[^.!?\n]{0,30}\b(codes?|otp|pin)\b|(?<!(\bnever|\bnot|n['’]t)\s(ever\s|\w+ly\s)?)\b(enter|input|type|submit)\b[^.!?\n]{0,30}\b(codes?|otp|pin)\b[^.!?\n]{0,30}\b(link\w*|url)\b/i;
  const OTP_GUARD = new RegExp(String.raw`^(?![\s\S]*(?:${CODE_ASK.source}))[\s\S]*(?:${SAFETY_NOTICE.source})`, 'iu');
  const RULES = [
    // ----- Phishing -----
    ['Phishing', 22, new RegExp(NEG + String.raw`\b(verify|confirm|update|unlock|restore)\b[^.!?\n]{0,15}\b(your|ur)\b[^.!?\n]{0,25}\b(account|password|identity|login|payment|card|details)\b`, 'i'), 'Asks you to verify/confirm account or payment details', { id: 'verify-details', plain: 'It asks you to confirm your account or payment details. Real companies do not ask for these in a message.', advice: 'dont_click', ask: true }],
    ['Phishing', 18, /\b(your|ur)\b[^.!?\n]{0,15}\b(account|card|profile|wallet|access)\b[^.!?\n]{0,25}\b(suspended|locked|disabled|restricted|blocked|deactivated|frozen)\b|\b(suspended|locked|disabled|restricted|blocked|deactivated) (your|ur) (account|card|profile|access)\b|\bunusual (sign[- ]?in|login|activity)\b|\bsecurity alert\b/i, 'Account-threat language (suspended / locked / unusual activity)', { id: 'account-threat', plain: 'It says your account is locked or at risk to scare you into acting fast. Check by opening the official app yourself, not the link.', advice: 'verify_official_channel' }],
    ['Phishing', 10, /\b(click|tap) (on )?(the |this )?(link|here|below)\b(?![^.!?\n]{0,25}\b(unsubscribe|view (this |the )?(email|message|newsletter)|manage (your )?(preferences|subscription)))/i, 'Pushes you to click a link', { id: 'click-link', plain: 'It pushes you to tap a link. Scam links lead to fake login or payment pages.', advice: 'dont_click' }],
    ['Phishing', 20, new RegExp(NEG + String.raw`\b(one[- ]time|otp|verification|2fa|security|\d-digit) (pass)?code\b`, 'i'), 'Mentions a one-time / verification code (never share these)', { id: 'otp', plain: 'It mentions a one-time code. Anyone who gets that code can take over your account.', advice: 'dont_share_code', ask: true, unless: OTP_GUARD, unlessScope: 'message' }],
    ['Phishing', 32, new RegExp(NEG.replace('{0,40}', '{0,25}') + String.raw`\b(enter|share|send|provide|type|submit|confirm|validate|sync|import|give)\b[^.!?\n]{0,30}\b(seed|recovery|secret|mnemonic|backup) ?(phrase|words|key)\b`, 'i'), 'Asks for a wallet seed / recovery phrase (whoever has it controls the wallet)', { id: 'seed-phrase', plain: 'It asks for your wallet recovery phrase. Whoever has those words can empty your wallet; no real service ever asks for them.', advice: 'dont_share_code', signature: true, ask: true }],
    ['Phishing', 22, /\b(validate|synchroni[sz]e|sync|rectify|re-?activate|connect) (your )?wallet\b[^.!?\n]{0,40}\b(to (claim|receive|fix|restore|avoid|unlock)|airdrop|reward)\b|\bwallet (validation|synchroni[sz]ation|rectification)\b/i, 'Wallet "validation / sync / connect to claim" request (wallet-drainer pattern)', { id: 'wallet-drainer', plain: 'It asks you to "connect" or "validate" your wallet to claim something. This is how wallet-draining sites steal crypto.', advice: 'dont_click' }],
    ['Phishing', 20, /\b(unpaid|outstanding|overdue)\s+(toll|parking|traffic|road|congestion)\s+(balance|fee|charge|fine|invoice|bill)s?\b/i, 'Unpaid toll / parking / fine text (smishing lure)', { id: 'toll-smishing', plain: 'It says you owe a small toll or parking fine and gives a link. This is a common text-message scam.', advice: 'dont_click' }],
    ['Phishing', 18, /\b(package|parcel|shipment|delivery)\b[^.!?\n]{0,40}\b(could not be delivered|undeliverable|is on hold|held at (our|the) (depot|warehouse)|address (is )?(incomplete|incorrect|invalid)|redelivery fee)\b/i, 'Undeliverable-parcel / redelivery-fee lure', { id: 'parcel-lure', plain: 'It says a parcel could not be delivered and asks you to act. Couriers do not ask for fees through text links.', advice: 'dont_click' }],
    // ----- Investment / crypto -----
    ['Investment / crypto', 24, /\b(guaranteed (returns?|profits?|income|payouts?)|risk[- ]free (investment|returns?|profits?|trading)|double your (money|bitcoin|crypto|investment)|passive income|daily (profit|returns?)|\d{1,4}% (daily |weekly |monthly )?(returns?|profit|roi))\b/i, 'Promises guaranteed or outsized returns', { id: 'guaranteed-returns', plain: 'It promises guaranteed or very high returns. Real investments can lose money and never guarantee profit.', advice: 'dont_pay' }],
    ['Investment / crypto', 16, /\b(10|100|1000)x (returns?|gains?|profits?|your (money|investment|crypto))\b/i, 'Promises a 10x / 100x multiple', { id: 'multiplier-returns', plain: 'It promises to multiply your money 10 or 100 times. Real investments do not work like that.', advice: 'dont_pay' }],
    ['Investment / crypto', 8, /\b(bitcoin|btc|ethereum|usdt|tether|crypto(currency)?|forex|binary options?|trading (bot|signals?|platform)|mining pool|airdrop|presale)\b/i, 'Crypto / trading vocabulary', { id: 'crypto-vocab', plain: 'It talks about crypto or trading. That alone is not a scam, but most investment scams use crypto.', advice: 'take_your_time', context: true }],
    ['Investment / crypto', 16, /\b(expert trader|(uncle|aunt|cousin)( is| was)? (an? )?(expert |professional )?(trader|analyst)|my (uncle|aunt|cousin) (taught|showed) me)\b|\b(my|our|your) (personal )?(account manager|mentor|trading (coach|teacher))\b[^.!?\n]{0,60}\b(trad(e|ing)|invest|profits?|crypto|returns?|signals?)\b/i, 'Unsolicited "mentor" / account-manager framing', { id: 'mentor', plain: 'A stranger offers to be your trading "mentor" or account manager. Scammers use this to steer you into fake investment apps.', advice: 'dont_pay' }],
    ['Investment / crypto', 18, /\b(elon musk|musk|jeff bezos|warren buffett?|bill gates|martin lewis|mark cuban|zuckerberg|cristiano ronaldo)\b[^.!?\n]{0,60}\b(new|secret|revolutionary|his|own|exclusive)\s+(ai |crypto |trading |investment |quantum )?(trading )?(platform|app|system|bot)\b/i, 'Celebrity "reveals new trading platform" (deepfake-ad pattern)', { id: 'celebrity-platform', plain: 'It claims a celebrity revealed a new trading platform. These ads use fake or edited videos of famous people.', advice: 'dont_click' }],
    // ----- Romance / pig-butchering -----
    ['Romance / pig-butchering', 18, /\b(dear(est)? (?!(customer|sir|madam|user|member|client|valued|mr|mrs|ms|dr|team|all|colleagues?|parents?|students?|applicants?|candidates?|subscribers?|guests?|patients?|partners?|shareholders?|account ?holder)\b)[a-z]+|my love|honey|sweetheart|soulmate|my destiny)\b[^]{0,80}?\b(send (me )?(some )?(money|cash|funds)|money|funds|invest|plane ticket|flight ticket|visa (fee|money)|customs (fee|charge)|hospital (bill|fee)s?|medical bills?)\b/i, 'Affection paired with a money request', { id: 'affection-money', plain: 'It mixes affection with a request for money. Romance scammers build feelings first, then ask for money.', advice: 'dont_pay' }],
    ['Romance / pig-butchering', 12, /\b([Ww]rong number|(texted|messaged) the wrong (person|number))\b|\b[Ii]s this (?!(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday|January|February|March|April|May|June|July|August|September|October|November|December|Ok|Okay|It|That|This|True|Real|Right|Free|Safe|Legit|Correct|Normal|Yours|Mine)\b)[A-Z][a-z]{1,15}\s*\?/, '"Wrong number" opener (classic pig-butchering hook)', { id: 'wrong-number', plain: 'It starts with a "wrong number" message. Scammers use this to begin a friendly chat that later turns into an investment pitch.', advice: 'block_report' }],
    ['Romance / pig-butchering', 12, /\b(deployed (in|to) (syria|afghanistan|iraq|yemen|somalia|overseas|abroad)|(working|work|stationed) on an? (oil rig|offshore (rig|platform|vessel))|(un|united nations) (doctor|peacekeeper|surgeon)|peacekeeping mission|offshore engineer|(i am|i'?m) a widow(er)?)\b/i, 'Romance-scam backstory (soldier / oil rig / widower)', { id: 'romance-backstory', plain: 'It uses a story (soldier abroad, oil rig, widower) that romance scammers use to explain why they cannot meet.', advice: 'dont_pay' }],
    // ----- Job / recruitment -----
    ['Job / recruitment', 20, /\b(earn|make) (up to )?[$€£₹]?\d[\d,]*k?\+?( ?(usd|dollars|tk|taka))?.{0,12}(per|a|\/|each) ?(day|hour|task)\b|\bno experience (needed|required)\b[^.!?\n]{0,60}\b(earn|income|commission|per day|daily)\b|\b(like and earn|(review|rate) (products|apps|hotels) for (money|cash|commission)|task[- ]based (job|work|income))\b/i, 'Too-easy job / task-for-pay offer', { id: 'easy-job', plain: 'It offers a lot of money for very little work. Real jobs do not pay like this for simple tasks.', advice: 'dont_pay' }],
    ['Job / recruitment', 20, /\b(product boosting|boost(ing)? (products|orders|merchants?)|app optimi[sz]ation|data optimi[sz]ation|order grabbing|grab orders|double (task|order)s?|combination (task|order)s?|lucky order)\b/i, 'Task-scam jargon (product boosting / app optimisation / combination orders)', { id: 'task-jargon', plain: 'It uses words from "task" job scams, like product boosting or combination orders. These jobs make you deposit money and never pay out.', advice: 'dont_pay' }],
    ['Job / recruitment', 18, /\b(training|onboarding|activation) fee\b|\b(pay|buy|purchase)( for)? (the |a |your )?(starter kit|work equipment|work laptop)\b|\bdeposit to (start|activate)\b|\bsend (you )?a check\b[^.!?\n]{0,40}\b(equipment|supplies)\b/i, 'Job that requires you to pay first', { id: 'pay-to-start', plain: 'It asks you to pay a fee before you can start a job. Real employers never do this.', advice: 'dont_pay' }],
    // ----- Giveaway / prize -----
    ['Giveaway / prize', 22, /\b(you('ve| have)?|u have) (just )?(won|been (randomly )?(selected|chosen))\b[^.!?\n]{0,40}\b(prize|reward|gift|cash|iphone|voucher|lottery|draw|giveaway|jackpot)\b|\bclaim (your|the) (prize|reward|winnings)\b|\b(lucky|lottery|prize) (winner|draw)\b/i, 'Unexpected prize / "you have been selected"', { id: 'prize', plain: 'It says you won a prize you never entered for. Surprise prizes are used to get your money or details.', advice: 'dont_pay', unless: /\b(scam|fraud|alert|beware|warning|if (someone|anyone|they|a (message|caller|text)))\b/i }],
    ['Giveaway / prize', 10, /\bfree (iphone|ps5|money|cash|bitcoin|crypto|usdt)\b|\b(crypto|bitcoin|eth|usdt|iphone) giveaway\b|\bfirst \d+ (people|users) (to|who) (send|deposit|register|click|share)\b/i, 'Giveaway bait', { id: 'giveaway', plain: 'It offers free money, crypto or phones. Giveaway bait is used to collect payments or details.', advice: 'dont_click' }],
    // ----- Advance-fee -----
    ['Advance-fee', 22, /\b(release|clearance|processing|activation|unlock(ing)?) (fee|charge)s?\b[^.!?\n]{0,60}\b(funds?|money|prize|winnings|package|parcel|inheritance|consignment|loan)\b|\b(funds?|money|prize|winnings|inheritance|consignment|loan)\b[^.!?\n]{0,60}\b(release|clearance|processing|activation) (fee|charge)s?\b/i, 'Pay a fee to release money / a package', { id: 'release-fee', plain: 'It asks you to pay a fee to release money, a prize or a package. Real money is never held back for a fee.', advice: 'dont_pay', unless: /\b(deducted|taken out of|included in|waived)\b/i }],
    ['Advance-fee', 28, /\b(deposit|recharge|top[- ]?up|pay)\b[^.!?\n]{0,50}\b(to|before (you|u) can|in order to|so (you|u) can)\s+(withdraw|unfreeze|cash out|(unlock|release) (\w+ ){0,2}(funds|money|profits?|earnings|winnings|commission|balance|withdrawals?|assets|(trading|investment) account))\b|\b(withdraw\w*|frozen|unfreeze)\b[^\n]{0,80}?\b(send|transfer|pay|deposit)\b([^.!?\n]|\.\d){0,30}\bfor (\w+ )?(verification|unfreezing|activation)\b|\b(withdrawals?|account)\b[^.!?\n]{0,30}\b(frozen|locked|suspended|on hold|blocked|restricted)\b[^.!?\n]{0,60}\b(tax|(?<!\bno )fees?(?![^.!?\n]{0,20}\b(waived|(won['’]?t|will not|not) be charged))|deposit|margin|insurance|verification (fee|deposit|payment))\b/i, 'Must pay a deposit, tax or fee before you can withdraw (pay-to-withdraw)', { id: 'pay-to-withdraw', plain: 'It says you must pay a deposit, tax or fee before you can withdraw your money. This is the final stage of most investment and job scams.', advice: 'dont_pay', unless: /\b(never|do not|don['’]t|no need to|(never|not) ask (you )?to)\s+(pay|deposit|send|transfer)\b/i, unlessScope: 'adjacent', signature: true, ask: true }],
    ['Advance-fee', 18, /\b(unclaimed (funds|inheritance|estate)|next of kin\b[^.!?\n]{0,60}\b(deceased|late|fund|estate)|(sole |legal )?beneficiary\b[^.!?\n]{0,60}\b(fund|estate|million|deceased|late client)|compensation fund|million (usd|us dollars|dollars|euros|pounds)\b[^.!?\n]{0,60}\b(transfer|fund|inheritance|beneficiary|share))\b/i, 'Inheritance / unclaimed-funds story', { id: 'inheritance', plain: 'It tells a story about an inheritance or unclaimed millions. These stories always end with a fee.', advice: 'dont_pay' }],
    // ----- Payment rails -----
    ['Payment rails', 24, new RegExp(String.raw`\b(buy|purchase|get|pick up|send|pay (with|in|using|via|by))\b[^.!?\n]{0,40}\b${GIFT}\b[^]{0,120}?\b((send|text|email|read|give|share|tell)( me| us| them)?( all)? (the )?(\w+ )?(codes?|pins?|numbers?|photos?|pictures?)|scratch)\b|\b(scratch|send|text|read|give)\b[^.!?\n]{0,30}\b(codes?|pins?|photos?|pictures?)\b[^.!?\n]{0,30}\b${GIFT}\b`, 'i'), 'Asks for payment in gift cards (and the codes on them)', { id: 'gift-card', plain: 'It asks you to pay with gift cards and send the codes. No real company, boss or government agency takes payment this way.', advice: 'dont_pay', signature: true, ask: true, scheme: 'Gift-card payment scam' }],
    ['Payment rails', 12, /\b(wire transfer|western union|moneygram|zelle|cash ?app|venmo|friends (and|&) family)\b/i, 'Irreversible payment method requested', { id: 'irreversible-rails', plain: 'It asks for a payment method that is very hard to reverse (wire, Zelle, Cash App and similar).', advice: 'dont_pay', context: true }],
    ['Payment rails', 20, /\b(bitcoin|crypto(currency)?|btc)\s+(atm|kiosk|machine)s?\b|\b(scan|use) (the|this) qr code\b[^.!?\n]{0,60}\b(deposit|kiosk|atm|machine)\b/i, 'Directs you to a crypto ATM / kiosk', { id: 'crypto-kiosk', plain: 'It sends you to a crypto ATM or kiosk. Real banks, police and governments never ask you to pay this way.', advice: 'dont_pay' }],
    // ----- Impersonation -----
    ['Impersonation', 16, /\b(this is|we are|i am|i'?m|calling (you )?from|contacting you from) (the |your )?(official |verified )?([a-z]+ )?(support|security|fraud|customer (care|service)|help ?desk|admin|moderator) (team|department|desk|page|account|centre|center)\b/i, 'Claims to be an official support account', { id: 'official-support', plain: 'It claims to be an official support or security team. Scammers pretend to be support to gain your trust.', advice: 'verify_official_channel' }],
    ['Impersonation', 10, /\b(paypal|amazon|microsoft|facebook|instagram|whatsapp|netflix|irs|hmrc|dhl|fedex|usps|bank of america|wells fargo|coinbase|binance|metamask)\b|\bApple (ID|[Ss]upport|account)\b|\bChase (Bank|account|card)\b|\bUPS\b|\bMeta (support|account|verified)\b/i, 'Names a major brand or agency', { id: 'brand', plain: 'It names a well-known company or agency. Scammers often borrow famous names.', advice: 'verify_official_channel', context: true }],
    // ----- Tech support -----
    ['Tech support', 20, /\b(virus (detected|found)|your (computer|device|pc|phone) (is|has been) (infected|hacked|compromised)|call (microsoft|apple|windows) support)\b/i, 'Fake tech-support alert', { id: 'fake-virus', plain: 'It says your device has a virus and you must call support. Real virus warnings do not ask you to call a number.', advice: 'dont_install' }],
    ['Tech support', 22, /\b(install|download|open)\b[^.!?\n]{0,30}\b(rustdesk|ultraviewer|screenconnect|connectwise|quick ?assist|quicksupport|supremo|airdroid|ammyy|anydesk|teamviewer)\b/i, 'Asks you to install a remote-access tool', { id: 'remote-access', plain: 'It asks you to install a remote-access app. That lets a stranger control your phone or computer.', advice: 'dont_install' }],
    // ----- Recovery scam -----
    ['Recovery scam', 20, /\b(recover (your |my |all )?(lost|stolen|scammed) (funds|crypto|money)|funds recovery|hacker for hire|ethical hacker)\b/i, '"We can recover your lost money" (targets past victims)', { id: 'recovery-promise', plain: 'It promises to recover money you lost. Recovery offers are a second scam aimed at past victims.', advice: 'no_recovery_fees' }],
    ['Recovery scam', 22, /\b(crypto(currency)? (fund |asset )?recovery (law )?(firm|agency|agent|service|specialist)s?|asset recovery (agent|specialist|firm)|(list|database|registry) of (scam |fraud )?victims|recovered (your|the) (stolen|lost|scammed) funds)\b/i, 'Fund-recovery firm or "list of victims" approach (targets past victims)', { id: 'recovery-firm', plain: 'It claims to be a fund-recovery firm or says you are on a list of victims. These firms take a fee and recover nothing.', advice: 'no_recovery_fees' }],
    // ----- Marketplace -----
    ['Marketplace', 14, /\boverpa(id|yment)\b[^.!?\n]{0,60}\b(refund|send|return|back|difference)\b|\bsend (the )?(rest|difference|balance|extra) back\b|\bshipping agent will pick up\b|\bcourier will (collect|pick up)\b|\bpay via (link|form)\b/i, 'Marketplace overpayment / fake-courier pattern', { id: 'overpayment', plain: 'It talks about overpaying and sending the difference back, or a courier collecting. This is a known marketplace trick.', advice: 'dont_pay' }],
    // ----- Family emergency / extortion -----
    ['Family-emergency impersonation', 32, /\b(hi|hey|hello)\s+(mum|mom|mam|mummy|mommy|dad|daddy)\b[^]{0,120}?\b(new (number|phone|mobile)(?! (case|charger|cover|screen|protector|plan))|lost my phone|broke my phone|phone (is |got )?(broken|smashed|lost)|this is my new)\b/i, '"Hi Mum / Dad, this is my new number" impersonation', { id: 'hi-mum', plain: 'Someone says they are your child on a new number. Scammers do this, then ask for money urgently.', advice: 'verify_person', signature: true }],
    ['Extortion', 32, /\b(recorded you|hacked (your|ur) (device|phone|computer|camera|webcam)|(intimate|nude|explicit|compromising) (video|photos?|images?|recording)s?)\b[^]{0,200}?\b(bitcoin|btc|crypto|usdt|wallet)\b/i, 'Claims compromising material and demands crypto (sextortion)', { id: 'sextortion', plain: 'It claims to have private images of you and demands crypto. These are usually bluffs; paying leads to more demands.', advice: 'get_support', signature: true, ask: true }],
    // ----- Off-platform move -----
    ['Off-platform move', 14, /\b(dm|inbox|text|message|add|contact|reach|chat with|talk to|join) (me|us)( (on|via|at|through|in))? (whats ?app|telegram|signal|wechat|line app|kik|viber|imo)\b|\b(move|continue|take) (this|our|the) (chat|conversation) (to|on|over to) (whats ?app|telegram|signal|wechat|viber)\b|\b(whats ?app|telegram)\b.{0,20}\+?\d[\d\s\-]{6,}/i, 'Pushes the conversation to WhatsApp / Telegram / DMs', { id: 'off-platform', plain: 'It tries to move the chat to WhatsApp, Telegram or another app, away from the platform\'s safety checks.', advice: 'block_report' }],
    // ----- Pressure -----
    ['Pressure', 16, /\b(urgent(ly)?|immediately|act now|within (24|48|12|2) hours|last chance|expires? (today|soon|in \d)|limited (time offer|spots|slots)|only \d+ (spots|slots|places) left)\b/i, 'Artificial urgency or scarcity', { id: 'urgency', plain: 'It rushes you with a deadline. Pressure to act now is a common scam tactic.', advice: 'take_your_time', context: true }],
    ['Pressure', 12, /\b(keep (this|it) (a )?(secret|between us)|don'?t tell (anyone|anybody|your (family|bank|wife|husband|parents|kids)))\b/i, 'Secrecy request', { id: 'secrecy', plain: 'It asks you to keep this secret. Scammers do this so nobody warns you.', advice: 'verify_person' }],
    // ----- Manipulation / misinformation -----
    ['Manipulation / misinformation', 16, /\b(share (this )?before (it'?s|they) (deleted|removed|taken down)|they don'?t want you to know|mainstream media (won'?t|refuses)|wake up|do your own research|banned (video|truth))\b/i, 'Classic misinformation spread-bait', { id: 'spread-bait', plain: 'It urges you to share before it is "deleted". This phrase is used to spread false claims.', advice: 'check_before_sharing' }],
    ['Manipulation / misinformation', 10, /\b(you won'?t believe|leaked (video|footage|documents?)|exposed!|100% (true|proof|confirmed)|shocking (truth|video|footage))\b/i, 'Sensational framing', { id: 'sensational', plain: 'It uses shocking words like "leaked" or "100% proof" to get attention, not to inform.', advice: 'check_before_sharing' }],
    ['Manipulation / misinformation', 10, /\b(doctors (hate|don'?t want)|miracle (cure|pill)|cures? (cancer|diabetes|everything)|big pharma)\b/i, 'Health-miracle claim', { id: 'health-miracle', plain: 'It claims a miracle cure. Real medical breakthroughs do not spread through forwarded messages.', advice: 'check_before_sharing' }],
    ['Manipulation / misinformation', 8, /\b(scientists|experts|studies|sources) (say|show|confirm|prove)\b(?![^.]{0,60}(https?:|doi|journal|published))/i, 'Vague appeal to authority with no source', { id: 'vague-authority', plain: 'It says "experts" or "studies" agree but names no source you can check.', advice: 'check_before_sharing' }],
    ['Engagement bait', 10, /\b(like (and|&) share|type ['"]?amen|comment ['"]?yes|tag (a friend|\d+ friends)|share if you agree|99% (won'?t|can'?t))\b/i, 'Engagement bait (farms reach for later scams)', { id: 'engagement-bait', plain: 'It asks you to like, share or comment to spread it. Pages do this to grow, then use the reach for scams.', advice: 'check_before_sharing' }],
  ];

  // ----- Common-scam pack (rules v3): customs fees, tax / benefit, utilities, shops, tickets, rentals, loan apps, betting,
  // fake support numbers, SIM swap / account recovery, charity, visas / scholarships, deepfake ads, marketplace codes, stranded friends -----
  const NUM = String.raw`\+?\(?\d[\d\s().-]{7,}\d`;
  const BRAND_GOODS = String.raw`(iphone|ipad|macbook|airpods|ps5|playstation|rolex|nike|adidas|gucci|louis vuitton|prada|dyson|ray-?ban|pandora)`;
  RULES.push(
    ['Delivery / customs fee', 30, /\b(parcel|package|shipment|consignment|gift box|item)\b[^]{0,100}?\b(customs|import|clearance)\s+(duty|duties|fee|fees|charges?|tax)\b[^]{0,80}?\b(pay|settle|transfer|send)\b|\b(pay|settle|transfer|send)\b[^.!?\n]{0,40}\b(customs|import|clearance)\s+(duty|duties|fee|fees|charges?|tax)\b[^]{0,80}?\b(release|deliver|receive|collect|parcel|package|shipment)\b/i, 'Customs / import fee demanded to release a parcel', { id: 'customs-fee', plain: 'It asks you to pay a customs or import fee to release a parcel. Fake courier messages use this to take your money and card details.', advice: 'dont_pay', ask: true }],
    ['Tax / benefit impersonation', 30, /\b(tax refund|tax rebate|refund from (the )?(irs|hmrc|tax office|income tax department)|stimulus (payment|check)|cost of living payment|(government|federal|state|council|national) (grant|benefit|relief|subsidy|payment|allowance)|unclaimed (benefit|refund))\b[^]{0,120}?(\b(click|tap|visit|open|follow)\b[^.!?\n]{0,30}\b(link|here|below)\b|https?:\/\/|\b(provide|enter|submit|confirm|verify|update)\b[^.!?\n]{0,20}\b(your )?(card|bank|account|payment|banking|personal) (details|information|info|number)\b|\b(processing|release|activation|registration|application) fee\b)/i, 'Tax refund / government benefit lure with a link, details request or fee', { id: 'gov-payment-lure', plain: 'It offers a tax refund or government payment if you click a link or give card details. Tax offices and benefit agencies do not pay out through text links.', advice: 'verify_official_channel' }],
    ['Utility disconnection', 30, /\b(your|ur)\b[^.!?\n]{0,20}\b(electricity|electric|power|gas|water|energy|utility|light)\b( bill| connection| supply| service| meter| account)?[^.!?\n]{0,30}\b(will be|is being|to be|shall be|is going to be|is scheduled to be)\s+(disconnected|cut off|shut off|suspended|terminated)\b[^]{0,120}?\b(call|contact|pay|clear|settle|whatsapp|update|text)\b/i, 'Utility disconnection threat with a call-or-pay demand', { id: 'utility-disconnect', plain: 'It threatens to cut off your power, gas or water unless you call or pay now. Real utilities send written notices and let you pay through your normal account.', advice: 'verify_official_channel', unless: /\b(maintenance|repairs?|planned works?|engineering works|upgrade works)\b/i }],
    ['Fake shop', 20, new RegExp(String.raw`\b(iphone ?1[0-9]( pro)?( max)?|ipad pro|macbook( air| pro)?|airpods( pro)?|ps5|playstation 5|xbox series x|rolex|dyson (airwrap|v1[0-9])|galaxy s2[0-9]( ultra)?)\b[^.!?\n]{0,30}\b(for|only|just|at|now)\s?[$€£]\s?[1-9]\d?(\.\d\d)?(?!\d|[,.]\d|\s*(\/|per\b|a month|each|monthly))|\b9\d\s?% off\b[^.!?\n]{0,40}\b${BRAND_GOODS}\b|\b${BRAND_GOODS}\b[^.!?\n]{0,40}\b9\d\s?% off\b`, 'i'), 'Famous product at an impossible price', { id: 'too-cheap', plain: 'It sells a famous product at a price far too low to be real. Fake shops use impossible deals to take payment and send nothing.', advice: 'dont_pay' }],
    ['Fake shop', 22, /\b(only accept|accept only|we only take|payment (is )?only|only (by|via|through)|no (card|cards|credit cards?|paypal|cod|cash on delivery)( payments?)?( accepted)?)\b[^.!?\n]{0,30}\b(bank transfer|wire|crypto|bitcoin|usdt|zelle|cash ?app|venmo|gift cards?|friends (and|&) family|bkash|nagad|western union)\b|\bpaypal\b[^.!?\n]{0,15}\b(friends (and|&) family|f&f|as a gift)\b/i, 'Seller accepts only payments with no buyer protection', { id: 'shop-no-protection', plain: 'The seller will only take a payment you cannot get back, like a bank transfer, crypto or PayPal "friends and family". Real shops let you pay by card.', advice: 'dont_pay', ask: true }],
    ['Ticket scam', 30, /(\btickets?\b[^]{0,100}?\b(sold out|front row|vip|face value|can'?t (go|make it)|cannot (go|make it)|spare)\b|\b(sold out|front row|vip|face value|can'?t (go|make it)|cannot (go|make it)|spare)\b[^]{0,60}?\btickets?\b)[^]{0,100}?\b(pay|send|transfer)\b[^.!?\n]{0,40}\b(first|upfront|up front|in advance|before i (send|transfer)|friends (and|&) family|f&f|zelle|cash ?app|bank transfer|gift cards?)\b/i, 'Resale tickets for a sold-out event, paid up front with no protection', { id: 'ticket-resale', plain: 'Someone offers tickets to a sold-out event and wants payment first by a method you cannot reverse. Buy only from the official ticket seller or its resale page.', advice: 'dont_pay' }],
    ['Rental / housing', 30, /\b(deposit|first month'?s? rent|holding fee|reservation fee|booking fee|security fee)\b[^]{0,80}?\b(before|without|prior to)\b[^.!?\n]{0,25}\b(viewing|view|seeing|see|visit|visiting|inspection|showing)\b|\b(i am|i'm|we are|we're|currently)\b[^.!?\n]{0,25}\b(abroad|overseas|out of the country|on a mission|working away|deployed)\b[^]{0,150}?\b(keys?|apartment|flat|house|property|room)\b[^]{0,100}?\b(mail|post|courier|ship|airbnb)\b/i, 'Rental deposit before viewing / absent landlord posting keys', { id: 'rental-deposit', plain: 'It asks for a deposit before you can see the home, or the "landlord" is abroad and will post the keys. Never pay before you have seen the place and checked who owns it.', advice: 'dont_pay' }],
    ['Loan app', 30, /\b(loan|credit)\b[^]{0,100}?\b(approved|sanctioned|ready|disburs\w*|pre-approved)\b[^]{0,100}?\b(pay|deposit|transfer|send)\b[^.!?\n]{0,40}\b(processing|insurance|approval|registration|file|disbursal|disbursement|activation|gst|security|verification) (fee|charges?|deposit|amount)\b|\b(instant|quick|easy)\s+(loan|cash)\b[^.!?\n]{0,60}\b(no (credit check|cibil( check)?|documents?|paperwork)|without (documents?|cibil|credit check)|guaranteed approval|100% approval)\b/i, 'Instant loan with no checks / upfront fee before the loan is paid out', { id: 'loan-upfront-fee', plain: 'It promises a fast loan with no checks, or asks for a fee before paying the loan out. Real lenders take fees from the loan, not before it.', advice: 'dont_pay', ask: true }],
    ['Loan app', 30, /\b(repay|pay|clear)\b[^]{0,80}?\b(or|otherwise|else|if not)\b[^]{0,60}?\b(we|we'?ll|i|i'?ll)\b[^.!?\n]{0,20}\b(send|share|post|message|call|inform|expose|tell|forward)\b[^.!?\n]{0,30}\b(your )?(contacts|contact list|relatives|friends|family|colleagues|employer)\b|\b(repay|clear|loan|dues?|emi|overdue|debt|borrowed|instal?l?ments?)\b[^]{0,80}?\b(or|otherwise|else|if not)\b[^]{0,60}?\b(we|we'?ll|i|i'?ll)\b[^.!?\n]{0,20}\b(send|share|post|message|call|inform|expose|tell|forward)\b[^.!?\n]{0,30}\b(your (photos?|pictures?|videos?)|(the |those |these )?(photos?|pictures?|videos?) of you)\b|\b(morphed|edited|nude|obscene)\s+(photos?|pictures?|images?)\b[^]{0,80}?\b(loan|repay|overdue|dues?|emi)\b|\b(loan|repay|overdue|dues?|emi)\b[^]{0,80}?\b(morphed|edited|nude|obscene)\s+(photos?|pictures?|images?)\b/i, 'Loan-app harassment: threats to shame you to your contacts', { id: 'loan-harassment', plain: 'It threatens to message your contacts or share edited photos unless you pay. This is illegal debt harassment; save the messages and report it.', advice: 'keep_evidence', signature: true, ask: true }],
    ['Betting / gambling', 26, /\b(colou?r prediction|colou?r trading|wingo|win ?go (game|app)|aviator (game|predictor|signals?|hack)|predict(ion)? (the )?colou?r)\b/i, '"Colour prediction" / crash-game earning app', { id: 'color-prediction', plain: 'It promotes a "colour prediction" or crash-game app as a way to earn. These apps are built so you lose and often block withdrawals.', advice: 'dont_pay' }],
    ['Betting / gambling', 30, /\b(guaranteed|sure|100%|fixed|risk-?free|confirmed)\s+(win|wins|winning|profit|odds|match|matches|tips?|bets?)\b[^.!?\n]{0,60}\b(bet|betting|casino|cricket|football|match|game|slots?|prediction|odds)\b|\b(bet|betting|casino|slots?)\b[^.!?\n]{0,60}\b(guaranteed|sure|100%)\s+(win|wins|winning|profit|returns?)\b|\bfixed match(es)?\b/i, 'Guaranteed betting wins / "fixed matches"', { id: 'sure-win-betting', plain: 'It promises sure wins or fixed matches. Nobody can guarantee a bet; these offers take a fee or deposit and disappear.', advice: 'dont_pay' }],
    ['Tech support', 30, new RegExp(String.raw`\b(if (this|it) (was|is) not you|if (this|it) (wasn'?t|isn'?t) you|if you did(n'?t| not) (make|authori[sz]e|place|order|request|recogni[sz]e)|to (cancel|dispute|stop|reverse)( this| the)?( order| transaction| subscription| charge| payment| renewal)?)\b[^]{0,100}?\b(call|dial|contact|ring|whatsapp)\b[^]{0,40}?${NUM}|\b(norton|mcafee|geek squad|paypal|amazon|microsoft|apple)\b[^]{0,80}?\b(renew(al|ed)|charged|debited|subscription|invoice)\b[^]{0,80}?\b(call|dial|contact)\b[^]{0,30}?${NUM}`, 'i'), 'Fake charge / renewal notice with a "call this number" support line', { id: 'support-number', plain: 'It reports a charge you did not make and gives a phone number to cancel it. Fake support lines use this to get remote access or card details; use the number on the company\'s own website or app.', advice: 'verify_official_channel' }],
    ['Account takeover', 30, /\b(sim|e-?sim)\s+(upgrade|swap|replacement|activation|change|migration|port)\b[^]{0,100}?\b(code|otp|pin|reply|confirm|press 1|text back)\b|\b(port|transfer|move)\b[^.!?\n]{0,15}\b(your|ur)\b[^.!?\n]{0,10}\b(number|sim|phone number)\b[^]{0,80}?\b(code|otp|pin|confirm|reply)\b/i, 'SIM swap / number-port request asking for a code', { id: 'sim-swap', plain: 'It asks for a code to "upgrade" or move your SIM. With that code someone can take your phone number and reset your bank and email logins.', advice: 'dont_share_code' }],
    ['Account takeover', 26, /\b(sent|send|sending|texted|forwarded)\b[^.!?\n]{0,25}\b(a |the |my )?(code|link|otp|sms)\b[^.!?\n]{0,25}\b(to )?(your|ur) (phone|number)\b[^]{0,80}?\b(by mistake|accidentally|wrongly|send it|forward it|share it|give it|tell me)\b|\b(help me|can you help|i need you to help)\b[^.!?\n]{0,30}\b(recover|get back|unlock|restore|log ?in to|access)\b[^.!?\n]{0,20}\b(my )?(account|instagram|facebook|whatsapp|tiktok|snapchat|gmail)\b[^]{0,100}?\b(send|forward|give|tell|share|read)\b[^.!?\n]{0,15}\b(me )?(the |that |this |your )?(code|otp)\b/i, '"I sent my code to your phone by mistake" / account-recovery help request', { id: 'account-recovery-help', unless: /\b(scam alert|fraud alert|beware|fake buyers?|scammers? (often |may |will |usually )?(say|ask|pretend|claim))\b|^(?![^]*\b(send|forward|give|tell|text|read)\b[^.!?\n]{0,25}\bme\b)[^]*\b(never|don'?t|do not|nobody|no one|won'?t|will not)\b[^.!?\n]{0,40}\b(share|send|tell|give|ask|read|forward)\b/i, unlessScope: 'adjacent', plain: 'Someone asks you to pass on a code sent to your phone "by mistake" or to help recover their account. That code unlocks your own account for them.', advice: 'dont_share_code', signature: true, ask: true }],
    ['Charity / disaster appeal', 30, /\b(earthquake|floods?|cyclone|hurricane|typhoon|tsunami|wildfire|bushfire|war|famine|refugees?|orphans?|disaster)\b[^]{0,120}?\b(donate|donation|donations|contribute|send help|help (the )?victims)\b[^]{0,80}?\b(crypto|bitcoin|btc|usdt|eth|gift cards?|zelle|cash ?app|western union|wallet address|personal account|my (own )?account)\b/i, 'Disaster / charity appeal paid to crypto, gift cards or a personal account', { id: 'disaster-appeal', plain: 'It asks for donations to crypto, gift cards or a personal account after a disaster. Give through a registered charity\'s own website instead.', advice: 'verify_official_channel' }],
    ['Visa / scholarship', 26, /\b(guaranteed|100%|sure|assured)\s+(visa|work permit|green card|pr|permanent residency|residence permit|citizenship|scholarship|admission|job visa)\b|\b(visa|work permit|green card|scholarship|admission|residence permit)\b[^.!?\n]{0,40}\b(guaranteed|100% (approval|success|guarantee)|without (interview|ielts|toefl|documents|any documents)|no (ielts|interview) (needed|required))\b/i, 'Guaranteed visa / scholarship / admission', { id: 'visa-guarantee', plain: 'It guarantees a visa, scholarship or admission. Only embassies and universities decide these, and nobody can guarantee them.', advice: 'verify_official_channel', unless: /\b(not|never|no one can|nobody can|cannot|can'?t)\b[^.!?\n]{0,20}\bguarantee/i }],
    ['Visa / scholarship', 30, /(\b(scholarship|bursary|fellowship|green card|dv lottery|visa lottery|work permit|visa|admission)\b[^]{0,120}?\b(selected|awarded|approved|won|winner|chosen|shortlisted|granted)\b|\b(selected|awarded|approved|won|winner|chosen|shortlisted|granted)\b[^]{0,60}?\b(scholarship|bursary|fellowship|green card|dv lottery|visa lottery|work permit|visa|admission)\b)[^]{0,120}?\b(pay|send|transfer|deposit)\b[^.!?\n]{0,40}\b(fee|fees|charges?|payment|deposit)\b/i, 'Scholarship / visa "award" that needs a fee to claim', { id: 'scholarship-fee', plain: 'It says you won a scholarship, visa or grant but must pay a fee to claim it. Real awards do not charge you to receive them.', advice: 'dont_pay', ask: true, unless: /\bno\b[^.!?\n]{0,20}\bfees?\b|free of charge|never (ask|charge)/i, unlessScope: 'message' }],
    ['Investment / crypto', 30, /\b(as seen on|featured on|revealed on|appeared on|live on|interview (on|with))\b[^.!?\n]{0,40}\b(bbc|cnn|fox|sky news|shark tank|dragons'? den|this morning|60 minutes|the tonight show)\b[^]{0,120}?\b(invest|investment|trading|platform|bot|earn|profit|crypto)\b|\b(banks?|government|central bank|the elite)\b[^.!?\n]{0,30}\b(tried to|wants? to|is trying to|are trying to|doesn'?t want you to)\b[^.!?\n]{0,15}\b(stop|ban|block|shut down|hide|know)\b[^]{0,100}?\b(invest|investing|trading|platform|earn|profit|crypto|income)\b/i, 'Fake TV endorsement / "the banks want to ban this" investment ad', { id: 'media-endorse', plain: 'It claims a TV show or famous person backs an investment, or that banks want to ban it. These ads use fake articles and AI-made videos.', advice: 'dont_pay' }],
    ['Investment / crypto', 28, /\bsend\b(?:[^.!?\n]|\.\d){0,30}\b(btc|eth|bitcoin|ethereum|usdt|sol|xrp|doge|crypto)\b[^.!?\n]{0,60}\b(get|receive|we('ll| will) send|i('ll| will) send|returned?)\b[^.!?\n]{0,30}\b(double|2x|twice|x2)\b|\bdouble (your )?(btc|eth|bitcoin|ethereum|crypto|usdt)\b/i, '"Send crypto, get double back" giveaway', { id: 'double-crypto', plain: 'It says if you send crypto you will get double back. This is a classic fake-giveaway scam, often in fake celebrity live streams.', advice: 'dont_pay', signature: true, ask: true }],
    ['Marketplace', 30, /\b(make sure|prove|verify|confirm|check|know)\b[^.!?\n]{0,20}\b(you('re| are)|that you('re| are)|you)\b[^.!?\n]{0,10}\b(real|legit|legitimate|genuine|not a (scammer|bot|fake)|a real person|human|the real (seller|owner))\b[^]{0,120}?\b(?<!\b(product|serial|model|promo|promotional|discount|coupon|voucher|zip|postal|post|area|bar|item|tracking|order|colou?r|style|size|batch|lot|imei)\s)code\b|\b(i('ll| will| am going to| just)|we('ll| will))\s+(send|sent|text|texted)\b[^.!?\n]{0,20}\b(you )?an?\b[^.!?\n]{0,15}\bcode\b[^]{0,80}?\b(tell|send|give|read|share)\b[^.!?\n]{0,15}\b(it|the code|code|me (back )?(the |that )?(code|it|what it says|(number|digits)))\b|\b(buy|buying|bought|purchas\w*|listing|seller|for sale|your ad|the item)\b[^]{0,120}?\b(send|tell|give|read|share|forward)\b[^.!?\n]{0,10}\bme\b[^.!?\n]{0,25}\b(otp|verification code|\d[- ]?digit code|code (that )?you (just )?(got|received|get))\b|\b(otp|verification code|\d[- ]?digit (verification )?code)\b[^]{0,80}?\b(verify|confirm|prove|check|know)\b[^.!?\n]{0,20}\byou('re| are)\b[^.!?\n]{0,10}\b(the |a )?(real |genuine )?(seller|owner)\b/i, 'Buyer asks for a verification code "to prove you are real"', { id: 'marketplace-code', unless: /\b(scam alert|fraud alert|beware|fake buyers?|scammers? (often |may |will |usually )?(say|ask|pretend|claim))\b|^(?![^]*\b(send|forward|give|tell|text|read)\b[^.!?\n]{0,25}\bme\b)[^]*\b(never|don'?t|do not|nobody|no one|won'?t|will not)\b[^.!?\n]{0,40}\b(share|send|tell|give|ask|read|forward)\b/i, unlessScope: 'adjacent', plain: 'A "buyer" asks you to read back a code to prove you are real. That code lets them set up an account in your name or take over yours.', advice: 'dont_share_code', signature: true, ask: true }],
    ['Family-emergency impersonation', 30, /\b(i'?m|i am|we'?re|we are|got)\s+(stuck|stranded|in trouble|in hospital|in the hospital|arrested|in jail|robbed|mugged|detained)\b[^]{0,120}?\b(send|transfer|wire|lend|need)\b[^.!?\n]{0,40}(\b(money|cash|funds|bail)\b|\d[\d,.]*\s?(usd|gbp|eur|inr|tk|taka|dollars|pounds)\b|[$€£₹৳]\s?\d)|\b(lost|broke|dropped|smashed) my (phone|mobile)\b[^]{0,120}?\b(send|transfer|wire|lend)\b[^.!?\n]{0,40}\b(money|cash|funds)\b/i, 'Friend / relative "stranded" and needs money urgently', { id: 'stranded-urgent-money', plain: 'Someone says they are stranded, robbed or in hospital and need money now. Call the person on the number you already have before sending anything.', advice: 'verify_person' }],
  );

  // ----- Bangla (Bengali script) + Banglish pack: bKash / Nagad / Rocket fraud, fake jobs & visas, prizes, OTP -----
  // Bengali letters are not \w, so \b is used only around Latin (Banglish) words. Sources are NFC-normalised like the input.
  const bn = (src, flags = 'iu') => new RegExp(src.normalize('NFC'), flags);
  const MFS = String.raw`(বিকাশ|নগদ|রকেট|\bb-?kash\b|\bnagad\b|\brocket\b)`;
  const BN_ASK = String.raw`(দিন|দেন|বলুন|বলেন|পাঠান|লিখুন|\bdin\b|\bden\b|\bdao\b|\bbolen\b|\bbolun\b|\bbolo\b|\bpathan\b)`;
  const BN_NEVER = bn(String.raw`(কাউকে|কখনো|দিবেন না|দেবেন না|বলবেন না|শেয়ার করবেন না|\bkauke\b|\bkokhono\b|\bdiben na\b|\bbolben na\b|\bshare korben na\b|\bnever\b|\bdo not share\b|\bdon'?t share\b)`);
  const BN_WARNING = bn(String.raw`(সাবধান|সতর্ক|প্রতারণা|প্রতারক|ভুয়া|\bsabdhan\b|\bshabdhan\b|\bsotorko\b|\bprotarona\b|\bprotarok\b|\bbhua\b|\bfake\b|\bscam\b)`);
  const BN_SEND = String.raw`(পাঠান|পাঠাবেন|পাঠিয়ে দিন|জমা দিন|জমা দেন|জমা দিতে হবে|\bpathan\b|\bpathaben\b|\bpathiye din\b|\bjoma (din|den|dite hobe)\b|\bsend koren\b)`;
  const BN_PAY = String.raw`(পাঠান|পাঠাও|পাঠাবেন|জমা|বিকাশ|নগদ|রকেট|পরিশোধ|দিতে হবে|\bpathan\b|\bpathao\b|\bjoma\b|\bb-?kash\b|\bnagad\b|\brocket\b|\bdite hobe\b|\bporishodh\b)`;
  RULES.push(
    ['Mobile-money fraud', 30, bn(MFS + String.raw`[^।.!?\n]{0,60}(পিন|\bpin\b|ওটিপি|\botp\b|কোড|\bcode\b)[^।.!?\n]{0,30}` + BN_ASK + '|' + String.raw`(পিন|\bpin\b|ওটিপি|\botp\b)[^।.!?\n]{0,25}` + BN_ASK + String.raw`[^।.!?\n]{0,60}` + MFS), 'Asks for a bKash / Nagad / Rocket PIN or code (the real services never ask)', { id: 'bn-mfs-pin', plain: 'It asks for your bKash, Nagad or Rocket PIN or code. These services never ask for your PIN.', advice: 'dont_share_code', lang: 'bn', signature: true, ask: true, unless: BN_NEVER }],
    ['Phishing', 20, bn(String.raw`(ওটিপি|\botp\b|ভেরিফিকেশন কোড|পিন নম্বর|পিন নাম্বার|পিন কোড|পিনটি|\bpin ta\b|\bpin number\b|কোডটি|কোড টা|কোড নম্বর|গোপন কোড|\bcode ta\b|\bcode ti\b|\bcode number\b)[^।.!?\n]{0,30}(বলুন|বলেন|দিন|দেন|পাঠান|ফরোয়ার্ড|\bbolen\b|\bbolun\b|\bdin\b|\bden\b|\bpathan\b|\bforward\b|\bsend koren\b)`), 'Asks you to read out or forward a one-time code or PIN (Bangla / Banglish)', { id: 'bn-otp', plain: 'It asks you to read out or forward a code or PIN. Anyone with that code can take your money or account.', advice: 'dont_share_code', lang: 'bn', ask: true, unless: BN_NEVER }],
    ['Mobile-money fraud', 30, bn(String.raw`(ভুল(ে| করে)|\b(vul|bhul|vule|bhule)\b)[^।.!?\n]{0,50}(টাকা|\btaka\b|\btk\b|৳)[^]{0,80}?(ফেরত|\bferot\b|\bfert\b|\bferat\b|\breturn\b)`), '"I sent money to your number by mistake, please return it" (mobile-money reversal scam)', { id: 'bn-wrong-send', plain: 'Someone says they sent you money by mistake and asks you to send it back. This is a common mobile-money trick.', advice: 'verify_official_channel', lang: 'bn', unless: BN_WARNING }],
    ['Impersonation', 16, bn(MFS + String.raw`\s*(অফিস|হেড ?অফিস|কাস্টমার ?কেয়ার|এজেন্ট|\boffice\b|\bhead office\b|\bcustomer care\b|\bagent\b)\s*(থেকে|\btheke\b)\s*(বলছি|বলা হচ্ছে|কল করেছি|ফোন করেছি|\bbolchi\b|\bcall korchi\b|\bcall dichi\b|\bphone dichi\b)`), 'Caller claims to be from the bKash / Nagad / Rocket office', { id: 'bn-mfs-office', plain: 'The caller says they are from the bKash, Nagad or Rocket office. These services do not call customers to ask for details.', advice: 'verify_official_channel', lang: 'bn' }],
    ['Phishing', 16, bn(String.raw`(একাউন্ট|অ্যাকাউন্ট|সিম|\baccount\b|\bsim\b)[^।.!?\n]{0,25}(বন্ধ|ব্লক|লক|স্থগিত|\bbondho\b|\bblock\b|\block\b)\s*(হয়ে যাবে|করা হবে|হয়ে গেছে|করা হয়েছে|\bhoye jabe\b|\bkora hobe\b|\bhoye geche\b|\bkora hoyeche\b)`), 'Threatens that your account or SIM will be blocked (Bangla / Banglish)', { id: 'bn-account-block', plain: 'It threatens that your account or SIM will be blocked. This threat is used to make you act without thinking.', advice: 'verify_official_channel', lang: 'bn', unless: BN_WARNING }],
    ['Job / recruitment', 30, bn(String.raw`(চাকরি|চাকুরি|চাকুরী|ভিসা|\bchakri\b|\bchakuri\b|\bjob\b|\bvisa\b)[^]{0,80}?(রেজিস্ট্রেশন|রেজিষ্ট্রেশন|প্রসেসিং|জামানত|অগ্রিম|মেডিকেল|\bregistration\b|\bprocessing\b|\bjoining\b|\badvance\b|\bjamanot\b|\bmedical\b)\s*(ফি|চার্জ|বাবদ|\bfee\b|\bcharge\b)[^]{0,60}?` + BN_SEND), 'Job / visa offer that asks you to send a registration or processing fee', { id: 'bn-job-fee', plain: 'It asks you to pay a registration or processing fee for a job or visa. Real employers and agencies do not take fees by mobile money.', advice: 'dont_pay', lang: 'bn', ask: true, unless: bn(String.raw`(লাগবে না|লাগে না|নেই|নাই|কোনো ফি|কোন ফি|\blagbe na\b|\blage na\b|\bno fee\b|\bkono fee\b)`) }],
    ['Job / recruitment', 16, bn(String.raw`(ঘরে বসে|\bghore (boshe|bose)\b)[^।.!?\n]{0,40}(আয়|ইনকাম|উপার্জন|টাকা|\bincome\b|\binkam\b|\btaka\b)|(দৈনিক|প্রতিদিন|\bdoinik\b|\bprotidin\b|\bdaily\b)\s*[০-৯\d,]{3,}\s*(টাকা|\btaka\b|\btk\b)\s*(আয়|ইনকাম|\bincome\b|\binkam\b)`), '"Earn from home / daily income" offer (Bangla / Banglish)', { id: 'bn-easy-income', plain: 'It promises easy daily income from home. These offers usually end with you paying money.', advice: 'dont_pay', lang: 'bn' }],
    ['Job / recruitment', 14, bn(String.raw`(ফ্রি|ফ্রী)\s*ভিসা|\bfree visa\b`), '"Free visa" overseas-job offer (common labour-migration fraud)', { id: 'bn-free-visa', plain: 'It offers a "free visa" for work abroad. This is a common bait in labour-migration fraud.', advice: 'verify_official_channel', lang: 'bn', unless: BN_WARNING }],
    ['Giveaway / prize', 22, bn(String.raw`(লটারি|লটারী|পুরস্কার|পুরষ্কার|\blottery\b|\bpuroskar\b|\bprize\b)[^।.!?\n]{0,40}(জিতেছেন|বিজয়ী হয়েছেন|পেয়েছেন|নির্বাচিত হয়েছেন|\bjitechen\b|\bjitesen\b|\bpeyechen\b|\bbijoyi hoyechen\b)|(আপনি|\bapni\b)[^।.!?\n]{0,30}(জিতেছেন|\bjitechen\b|\bjitesen\b)[^।.!?\n]{0,40}(লাখ|হাজার|টাকা|গাড়ি|মোটরসাইকেল|আইফোন|\blakh\b|\btaka\b|\biphone\b)`), '"You have won a lottery / prize" (Bangla / Banglish)', { id: 'bn-prize', plain: 'It says you won a lottery or prize you never entered for.', advice: 'dont_pay', lang: 'bn', unless: BN_WARNING }],
    ['Advance-fee', 24, bn(String.raw`(লটারি|পুরস্কার|পুরষ্কার|উপহার|গিফট|\blottery\b|\bpuroskar\b|\bprize\b|\bgift\b)[^]{0,120}?(ফি|চার্জ|ট্যাক্স|\bfee\b|\bcharge\b|\btax\b)[^]{0,60}?` + BN_SEND), 'Pay a fee or tax to receive a prize (Bangla / Banglish)', { id: 'bn-prize-fee', plain: 'It asks you to pay a fee or tax to receive a prize. Real prizes never cost money to collect.', advice: 'dont_pay', lang: 'bn', ask: true, unless: BN_WARNING }],
    ['Pressure', 8, bn(String.raw`(এখনই|এখুনি|জরুরি|জরুরী|দ্রুত|[০-৯\d]+ ?ঘ(ন্|ণ্)টার মধ্যে|\bekhoni\b|\bjoruri\b|\bdruto\b)`), 'Urgency (Bangla / Banglish)', { id: 'bn-urgency', plain: 'It rushes you to act now. Pressure is a common scam tactic.', advice: 'take_your_time', lang: 'bn', context: true }],
    ['Delivery / customs fee', 30, bn(String.raw`(পার্সেল|কুরিয়ার|গিফট|উপহার|প্যাকেট|\bparcel\b|\bcourier\b|\bgift\b|\bpacket\b)[^]{0,100}(কাস্টমস|কাস্টম|শুল্ক|এয়ারপোর্ট|বিমানবন্দর|\bcustoms?\b|\bairport\b)[^]{0,100}(ফি|চার্জ|ট্যাক্স|কর|\bfee\b|\bcharge\b|\btax\b)[^]{0,80}` + BN_PAY), 'Customs fee for a "gift parcel" (Bangla / Banglish)', { id: 'bn-customs', plain: 'It says a gift parcel is held at customs or the airport and asks you to pay a fee by mobile money. Customs never collects fees through bKash or Nagad.', advice: 'dont_pay', signature: true, lang: 'bn', ask: true, unless: BN_WARNING, unlessScope: 'message' }],
    ['Tax / benefit impersonation', 30, bn(String.raw`(সরকারি|সরকারী|\bsorkari\b|\bshorkari\b)\s*(অনুদান|ভাতা|সহায়তা|সাহায্য|প্রণোদনা|উপবৃত্তি|\bonudan\b|\bvata\b|\bbhata\b|\bshohayota\b|\bsahajjo\b)[^]{0,100}(ফি|চার্জ|পিন|ওটিপি|কোড|লিংকে|লিঙ্কে|\bfee\b|\bcharge\b|\bpin\b|\botp\b|\bcode\b|\blink\b)`), 'Government grant / allowance lure with a fee, PIN or link (Bangla / Banglish)', { id: 'bn-govt-benefit', plain: 'It offers a government grant or allowance if you pay a fee or share a PIN or link. Government payments never need a fee or your PIN.', advice: 'verify_official_channel', lang: 'bn', unless: bn(BN_NEVER.source + '|' + BN_WARNING.source), unlessScope: 'message' }],
    ['Utility disconnection', 30, bn(String.raw`(বিদ্যুৎ|বিদ্যুত|গ্যাস|মিটার|\bbiddut\b|\bcurrent\b|\bmeter\b|\bgas\b)[^]{0,60}(সংযোগ বিচ্ছিন্ন|বিচ্ছিন্ন করা হবে|লাইন কেটে|কেটে দেওয়া হবে|কেটে দেয়া হবে|সংযোগ বন্ধ|\bline kete\b|\bkete deya hobe\b|\bkete dewa hobe\b|\bdisconnect\b)[^]{0,100}(বিল|টাকা|বিকাশ|নগদ|যোগাযোগ|কল|\bbill\b|\btaka\b|\bb-?kash\b|\bcall\b|\bjogajog\b)`), 'Electricity / gas disconnection threat (Bangla / Banglish)', { id: 'bn-utility', plain: 'It threatens to cut your electricity or gas unless you pay or call now. Pay bills only through the official app, meter card or office.', advice: 'verify_official_channel', lang: 'bn', unless: bn(String.raw`(রক্ষণাবেক্ষণ|মেরামত|\bmaintenance\b)`), unlessScope: 'adjacent' }],
    ['Loan app', 30, bn(String.raw`(লোন|ঋণ|\bloan\b)[^]{0,100}(প্রসেসিং|ফাইল|রেজিস্ট্রেশন|জামানত|ইন্স্যুরেন্স|বীমা|\bprocessing\b|\bfile\b|\bregistration\b|\binsurance\b)\s*(ফি|চার্জ|খরচ|\bfee\b|\bcharge\b|\bkhoroch\b)[^]{0,80}` + BN_PAY), 'Loan that needs a fee first (Bangla / Banglish)', { id: 'bn-loan-fee', plain: 'It asks for a file or processing fee before giving you a loan. Real lenders do not ask for fees by mobile money first.', advice: 'dont_pay', lang: 'bn', ask: true }],
    ['Loan app', 30, bn(String.raw`(লোন|ঋণ|কিস্তি|\bloan\b|\bkisti\b|\brin\b)[^]{0,120}?(না দিলে|না দেন|না করলে|না হলে|নাহলে|নইলে|\bna dile\b|\bna den\b|\bna korle\b|\bnaile\b|\bnahole\b)[^।.!?\n]{0,80}?(ছবি|ফটো|\bchobi\b|\bphoto\b|\bpic\b|\bpicture\b)[^।.!?\n]{0,80}?(কন্টাক্ট|কনটাক্ট|পরিচিত|আত্মীয়|ফেসবুক|সবাইকে|সবার কাছে|\bcontacts?\b|\battiyo\b|\bfacebook\b|\bsobaike\b|\bsobar kache\b)[^।.!?\n]{0,40}?(পাঠিয়ে|পাঠাবো|পাঠাব|পাঠানো হবে|ছড়িয়ে|ছেড়ে দিব|পোস্ট|ভাইরাল|\bpathiye\b|\bpathabo\b|\bpathai\b|\bchariye\b|\bpost\b|\bviral\b)`), 'Loan-app harassment: threat to send your photos to contacts (Bangla / Banglish)', { id: 'bn-loan-harassment', plain: 'It threatens to send your photos to your contacts or post them online unless you repay a loan. This is illegal harassment; save the messages and report it.', advice: 'keep_evidence', lang: 'bn', signature: true, ask: true }],
    ['Betting / gambling', 30, bn(String.raw`(বেটিং|জুয়া|ক্যাসিনো|\bbetting\b|\bbet\b|\bjua\b|\bcasino\b|\bcolou?r prediction\b)[^]{0,80}(নিশ্চিত|গ্যারান্টি|ডাবল|দ্বিগুণ|প্রতিদিন|\bguaranteed?\b|\bdouble\b|\bsure\b|\bprotidin\b|\bnishchit\b)[^]{0,60}(আয়|ইনকাম|লাভ|জিত|টাকা|\bincome\b|\blav\b|\btaka\b|\btk\b)`), 'Betting app promising sure or daily winnings (Bangla / Banglish)', { id: 'bn-betting', plain: 'It promises sure or daily money from a betting app. Betting apps are built so you lose, and online gambling is illegal in Bangladesh.', advice: 'dont_pay', lang: 'bn', unless: BN_WARNING, unlessScope: 'message' }],
    ['Account takeover', 30, bn(String.raw`(সিম|\bsim\b)[^]{0,30}(আপগ্রেড|রিপ্লেস|রিপ্লেসমেন্ট|পরিবর্তন|\bupgrade\b|\breplace\b|\breplacement\b|\b4g\b|\b5g\b|৪জি|৫জি)[^]{0,80}(কোড|পিন|ওটিপি|\bcode\b|\bpin\b|\botp\b)`), 'SIM "upgrade" that needs your code (Bangla / Banglish)', { id: 'bn-sim', plain: 'It asks for the code on your phone to "upgrade" or replace your SIM. With that code someone can take your number and your mobile-money account.', advice: 'dont_share_code', lang: 'bn', unless: bn(BN_NEVER.source + '|' + BN_WARNING.source), unlessScope: 'message' }],
    ['Family-emergency impersonation', 30, bn(String.raw`(বিপদে|বিপদ|সমস্যায়|হাসপাতালে|এক্সিডেন্ট|দুর্ঘটনা|আটকে|\bbipode\b|\bbipod\b|\bsomossay\b|\bhospital\b|\baccident\b|\batke\b)[^]{0,80}(জরুরি|জরুরী|এখনই|\bjoruri\b|\bekhoni\b|লাগবে|\blagbe\b)[^]{0,60}(টাকা|\btaka\b|\btk\b)[^]{0,60}(বিকাশ|নগদ|রকেট|পাঠা|\bb-?kash\b|\bnagad\b|\bpathao\b|\bpathan\b|\bsend\b)`), 'Friend / relative "in trouble" needs money by bKash now (Bangla / Banglish)', { id: 'bn-friend-urgent', plain: 'Someone says they are in trouble and need money by bKash or Nagad right now. Call the person on their old number first; hacked accounts send this message.', advice: 'verify_person', lang: 'bn' }],
    ['Visa / scholarship', 30, bn(String.raw`(স্কলারশিপ|বৃত্তি|\bscholarship\b|\bbritti\b)[^]{0,100}(ফি|চার্জ|\bfee\b|\bcharge\b)[^]{0,80}` + BN_PAY), 'Scholarship that needs a fee by mobile money (Bangla / Banglish)', { id: 'bn-scholarship', plain: 'It asks for a fee by mobile money to confirm a scholarship. Real scholarships do not take fees through bKash or Nagad.', advice: 'dont_pay', lang: 'bn', ask: true, unless: BN_NEVER, unlessScope: 'message' }],
  );

  // ----- Translations of the most template-like rules (task jargon, pay-to-withdraw, seed phrase, "Hi Mum"): es, pt, fr, ar, hi, id -----
  RULES.push(
    ['Job / recruitment', 16, /(pedido combinado|tarea combinada|commande combinée|tâche combinée|pesanan kombinasi|tugas kombinasi|طلب مدمج|مهمة مدمجة|कॉम्बिनेशन ऑर्डर|प्रोडक्ट बूस्टिंग|optimi[zs]aci[óo]n de (productos|pedidos)|otimiza[çc][ãa]o de (produtos|pedidos)|optimisation (des |de )?(produits|commandes)|optimasi (produk|pesanan)|تحسين (المنتجات|الطلبات))[^]{0,80}?(comisi[óo]n|comiss[ãa]o|commission|komisi|عمولة|कमीशन|tareas|tarefas|tâches|tugas|مهام|टास्क)/iu, 'Task-scam jargon (translated: es / pt / fr / ar / hi / id)', { id: 'i18n-task-jargon', plain: 'It uses words from "task" job scams. These jobs make you deposit money and never pay out.', advice: 'dont_pay', lang: 'i18n' }],
    ['Advance-fee', 28, /\b(deposit[ae]r?|pag(ar|ue|a)|recarg(ar|a|ue)|recarregue|recarregar|d[ée]pose[rz]|paye[rz]|recharge[rz]|setor|bayar|isi ulang)\b[^.!?\n]{0,50}\b(para (poder )?(retirar|sacar)|pour (pouvoir )?retirer|(untuk|agar bisa|supaya bisa) (menarik|tarik|melakukan penarikan))\b|(إيداع|أودع|ادفع|اشحن)[^.!?\n]{0,50}(لسحب|للسحب|حتى تتمكن من السحب)|(निकालने|निकासी)[^।.!?\n]{0,40}(जमा करें|जमा करना होगा|भुगतान करें|रिचार्ज करें)/iu, 'Must pay before you can withdraw (translated: es / pt / fr / ar / hi / id)', { id: 'i18n-pay-to-withdraw', plain: 'It says you must pay before you can withdraw your money. This is the final stage of most investment and job scams.', advice: 'dont_pay', lang: 'i18n', signature: true, ask: true }],
    ['Phishing', 32, /\b(ingres[ae]|introduc[ea]|compart[ae]|env[íi][ae]|escrib[ae]|proporcion[ae]|insira|digite|compartilhe|envie|informe|entrez|saisissez|partagez|envoyez|communiquez|donnez|masukkan|kirim(kan)?|bagikan)\b[^.!?\n]{0,30}((frase|palabras) (semilla|de recuperaci[óo]n)|frase (semente|de recupera[çc][ãa]o)|phrase (de r[ée]cup[ée]ration|secr[èe]te|mn[ée]monique)|frasa (pemulihan|benih|rahasia))|(أدخل|ارسل|أرسل|شارك|اكتب)[^.!?\n]{0,30}عبارة (الاسترداد|الاسترجاع|البذور|السرية)|(सीड|रिकवरी) (फ्रेज़|फ्रेज|वाक्यांश)[^।.!?\n]{0,30}(दर्ज करें|भेजें|शेयर करें|बताएं)/iu, 'Asks for a wallet seed / recovery phrase (translated: es / pt / fr / ar / hi / id)', { id: 'i18n-seed-phrase', plain: 'It asks for your wallet recovery phrase. Whoever has those words can empty your wallet.', advice: 'dont_share_code', lang: 'i18n', signature: true, ask: true, unless: /\b(nunca|no|não|jamais|ne|jangan|tidak)\b|(لا|أبدا|أبدًا)\s|(कभी|मत|न करें)/iu }],
    ['Family-emergency impersonation', 32, /\b(hola|oi|ol[áa]|salut|coucou|bonjour|halo|hai)\s+(mam[áa]|pap[áa]|m[ãa]e|pai|maman|papa|ma|mama|ibu|bu|ayah|pa)(?!\p{L})[^]{0,120}?(nuevo n[úu]mero|n[úu]mero nuevo|se me rompi[óo] el (m[óo]vil|celular|tel[ée]fono)|perd[íi] (mi|el) (m[óo]vil|celular|tel[ée]fono)|n[úu]mero novo|novo n[úu]mero|meu (celular|telem[óo]vel) (quebrou|caiu)|nouveau num[ée]ro|j'ai perdu mon (t[ée]l[ée]phone|portable)|mon (t[ée]l[ée]phone|portable) est cass[ée]|nomor baru|ganti nomor|hp (aku|saya) (rusak|hilang))|(مرحبا|اهلا|أهلا|هلا)\s+(ماما|امي|أمي|بابا|ابي|أبي)[^]{0,120}?(رقمي الجديد|رقم جديد|هاتفي (انكسر|ضاع)|ضاع هاتفي)|(हाय|हेलो|नमस्ते)\s+(मम्मी|माँ|मां|पापा)[^]{0,120}?(नया नंबर|मेरा फ़?ोन (टूट|खो) गया)/iu, '"Hi Mum / Dad, this is my new number" (translated: es / pt / fr / ar / hi / id)', { id: 'i18n-hi-mum', plain: 'Someone says they are your child on a new number. Scammers do this, then ask for money urgently.', advice: 'verify_person', lang: 'i18n', signature: true }],
  );

  // ---------- Checksum validators (synchronous, zero-dependency) ----------
  // A string that merely looks like an address is not evidence. Only checksum-valid addresses are scored or indexed.
  const K256 = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
  function sha256(bytes) {
    const l = bytes.length, n = ((l + 9 + 63) >> 6) << 6, m = new Uint8Array(n); m.set(bytes); m[l] = 0x80;
    const dv = new DataView(m.buffer); dv.setUint32(n - 4, l * 8); dv.setUint32(n - 8, Math.floor(l / 0x20000000));
    let h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    const w = new Uint32Array(64), r = (x, k) => (x >>> k) | (x << (32 - k));
    for (let o = 0; o < n; o += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(o + i * 4);
      for (let i = 16; i < 64; i++) { const s0 = r(w[i - 15], 7) ^ r(w[i - 15], 18) ^ (w[i - 15] >>> 3), s1 = r(w[i - 2], 17) ^ r(w[i - 2], 19) ^ (w[i - 2] >>> 10); w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0; }
      let [a, b, c, d, e, f, g, hh] = h;
      for (let i = 0; i < 64; i++) { const t1 = (hh + (r(e, 6) ^ r(e, 11) ^ r(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i]) | 0, t2 = ((r(a, 2) ^ r(a, 13) ^ r(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) | 0; hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0; }
      h = h.map((v, i) => (v + [a, b, c, d, e, f, g, hh][i]) | 0);
    }
    const out = new Uint8Array(32); h.forEach((v, i) => new DataView(out.buffer).setUint32(i * 4, v)); return out;
  }
  // Keccak-256 (the pre-standard padding Ethereum uses, not SHA3-256). BigInt lanes: slow but only ever run on 40 hex chars.
  const M64 = (1n << 64n) - 1n, KRC = [], KROT = Array(25).fill(0);
  (() => {
    let R = 1; const bit = () => { const b = R & 1; R = (R & 0x80) ? ((R << 1) ^ 0x171) & 0xff : R << 1; return b; };
    for (let i = 0; i < 24; i++) { let c = 0n; for (let j = 0; j < 7; j++) if (bit()) c |= 1n << BigInt((1 << j) - 1); KRC.push(c); }
    let x = 1, y = 0; for (let t = 0; t < 24; t++) { KROT[x + 5 * y] = ((t + 1) * (t + 2) / 2) % 64; [x, y] = [y, (2 * x + 3 * y) % 5]; }
  })();
  const rotl = (v, n) => n ? ((v << BigInt(n)) | (v >> BigInt(64 - n))) & M64 : v;
  function keccakF(s) {
    for (let round = 0; round < 24; round++) {
      const C = [0, 1, 2, 3, 4].map(x => s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20]);
      for (let x = 0; x < 5; x++) { const D = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1); for (let y = 0; y < 25; y += 5) s[x + y] ^= D; }
      const B = Array(25);
      for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(s[x + 5 * y], KROT[x + 5 * y]);
      for (let x = 0; x < 5; x++) for (let y = 0; y < 25; y += 5) s[x + y] = B[x + y] ^ ((B[(x + 1) % 5 + y] ^ M64) & B[(x + 2) % 5 + y]);
      s[0] ^= KRC[round];
    }
  }
  function keccak256(bytes, dsByte = 0x01) {
    const rate = 136, padded = new Uint8Array(Math.floor(bytes.length / rate) * rate + rate); padded.set(bytes);
    padded[bytes.length] ^= dsByte; padded[padded.length - 1] ^= 0x80;
    const s = Array(25).fill(0n);
    for (let o = 0; o < padded.length; o += rate) {
      for (let i = 0; i < rate / 8; i++) { let v = 0n; for (let b = 7; b >= 0; b--) v = (v << 8n) | BigInt(padded[o + i * 8 + b]); s[i] ^= v; }
      keccakF(s);
    }
    const out = new Uint8Array(32); for (let i = 0; i < 32; i++) out[i] = Number((s[i >> 3] >> BigInt(8 * (i & 7))) & 0xffn); return out;
  }
  const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  function b58decode(str) {
    const bytes = [0];
    for (const ch of str) { const v = B58.indexOf(ch); if (v < 0) return null; let carry = v; for (let i = 0; i < bytes.length; i++) { carry += bytes[i] * 58; bytes[i] = carry & 0xff; carry >>= 8; } while (carry) { bytes.push(carry & 0xff); carry >>= 8; } }
    while (bytes.length > 1 && bytes[bytes.length - 1] === 0) bytes.pop();
    for (const ch of str) { if (ch === '1') bytes.push(0); else break; }
    return new Uint8Array(bytes.reverse());
  }
  function base58checkOk(str) {
    const b = b58decode(str); if (!b || b.length < 5) return false;
    const h = sha256(sha256(b.slice(0, -4))); return b.slice(-4).every((x, i) => x === h[i]);
  }
  // Bech32 (BIP-173) / Bech32m (BIP-350) checksum for bc1 addresses
  function bech32Ok(addr) {
    const CH = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l', s = addr.toLowerCase();
    if (s !== addr && addr.toUpperCase() !== addr) return false;
    const p = s.lastIndexOf('1'); if (p < 1 || p + 7 > s.length || s.length > 90) return false;
    const hrp = s.slice(0, p); if (hrp !== 'bc') return false; const data = [...s.slice(p + 1)].map(c => CH.indexOf(c)); if (data.some(x => x < 0)) return false;
    const G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]; let chk = 1;
    const pm = v => { const t = chk >>> 25; chk = ((chk & 0x1ffffff) << 5) ^ v; for (let i = 0; i < 5; i++) if ((t >>> i) & 1) chk ^= G[i]; };
    for (const c of hrp) pm(c.charCodeAt(0) >> 5); pm(0); for (const c of hrp) pm(c.charCodeAt(0) & 31); for (const d of data) pm(d);
    if (data[0] === 0) return chk === 1; // witness v0 must use Bech32
    return chk === 0x2bc830a3;           // v1+ (taproot) must use Bech32m
  }
  // EIP-55: mixed-case EVM addresses carry a checksum in the capitalisation; all-lower / all-upper carry none.
  function eip55(addr) {
    const hex = addr.slice(2).toLowerCase(), hash = keccak256(Uint8Array.from(hex, c => c.charCodeAt(0)));
    return '0x' + [...hex].map((c, i) => (/[a-f]/.test(c) && ((hash[i >> 1] >> (i & 1 ? 0 : 4)) & 0xf) >= 8) ? c.toUpperCase() : c).join('');
  }
  function evmChecksum(addr) {
    const body = addr.slice(2);
    if (body === body.toLowerCase() || body === body.toUpperCase()) return 'none';
    return eip55(addr) === addr ? 'valid' : 'invalid';
  }
  function walletCheck(chain, a) {
    if (chain === 'Bitcoin') {
      if (/^bc1/i.test(a)) return bech32Ok(a) ? 'valid' : 'invalid';
      const b = b58decode(a); return base58checkOk(a) && b.length === 25 && (b[0] === 0x00 || b[0] === 0x05) ? 'valid' : 'invalid';
    }
    if (chain.startsWith('Tron')) { const b = b58decode(a); return base58checkOk(a) && b[0] === 0x41 && b.length === 25 ? 'valid' : 'invalid'; }
    return evmChecksum(a);
  }

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

  // ---------- Phone numbers ----------
  // Returns { raw, e164, digits, country } or null when the digits are more likely a date, time, IP, order/reference number or filler.
  const PHONE_CTX_REJECT = /\b(order|invoice|inv|ref(erence)?|tracking|track|awb|case|ticket|txn|trx|transaction|trxid|tran id|account|acct|a\/c|id|no|nid|serial|sku|isbn|reg(istration)?|roll|policy|bill|receipt|pnr|booking)\b\s*(no\.?|number|num|#|id)?\s*[:#.-]?\s*$|#\s*$/i;
  function normalizePhone(raw, before = '') {
    const s = raw.trim();
    if (PHONE_CTX_REJECT.test(before.slice(-25))) return null;
    if (/^(19|20)\d{2}[\s./-]+(0?[1-9]|1[0-2])[\s./-]+(0?[1-9]|[12]\d|3[01])(\D|$)/.test(s)) return null; // 2024-11-26 10, 2024 11 26 1030
    if (/^(0?[1-9]|[12]\d|3[01])[\s./-]+(0?[1-9]|1[0-2])[\s./-]+(19|20)\d{2}(\D|$)/.test(s)) return null; // 26/11/2024
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return null; // IPv4
    if (/\d\.\d/.test(s) && !/^\+/.test(s) && !/^\(?\d{3}\)?[\s.-]\d{3}[.-]\d{4}$/.test(s)) return null; // decimals / version numbers
    let d = s.replace(/\D/g, '');
    const intl = /^\+/.test(s) || /^00[1-9]/.test(d);
    if (/^00/.test(d)) d = d.slice(2);
    if (/^(\d)\1+$/.test(d) || '01234567890123456789'.includes(d) || '98765432109876543210'.includes(d)) return null;
    const formatted = /[\s().-]/.test(s);
    const out = (cc, nat, country) => ({ raw: s, e164: '+' + cc + nat, digits: cc + nat, country });
    // Bangladesh: +880 1[3-9]XXXXXXXX mobile, 01[3-9]XXXXXXXX local, landlines +880 2 / +880 [3-9]X with 7-9 subscriber digits
    if (/^8801[3-9]\d{8}$/.test(d)) return out('880', d.slice(3), 'BD');
    if (!intl && /^01[3-9]\d{8}$/.test(d)) return out('880', d.slice(1), 'BD');
    if (intl && /^880/.test(d)) return /^880[2-9]\d{7,9}$/.test(d) ? out('880', d.slice(3), 'BD') : null;
    if (intl) {
      if (d.length < 8 || d.length > 15) return null;
      if (/^1[2-9]\d{2}[2-9]\d{6}$/.test(d)) return out('1', d.slice(1), 'NANP');
      if (/^1/.test(d)) return null;
      if (/^44/.test(d)) return /^44[1-9]\d{8,9}$/.test(d) ? out('44', d.slice(2), 'GB') : null;
      if (/^91/.test(d)) return /^91[6-9]\d{9}$/.test(d) ? out('91', d.slice(2), 'IN') : null;
      return { raw: s, e164: '+' + d, digits: d, country: null };
    }
    // National numbers without a country code: only accept known shapes; bare digit runs are usually order / reference numbers.
    if (/^0?7\d{9}$/.test(d) && /^07/.test(d)) return out('44', d.slice(1), 'GB');
    if (formatted && /^1?[2-9]\d{2}[2-9]\d{6}$/.test(d) && /^(\+?1[\s.-]?)?\(?[2-9]\d{2}\)?[\s.-]?\d{3}[\s.-]?\d{4}$/.test(s)) return out('1', d.slice(-10), 'NANP');
    if (formatted && d.length >= 9 && d.length <= 11 && /^0[1-9]/.test(d)) return { raw: s, e164: null, digits: d.replace(/^0/, ''), country: null };
    return null;
  }

  // ---------- Wallets ----------
  // Token contracts and similar addresses are shared by millions of users and never identify a scammer.
  const SHARED_WALLETS = new Set(['TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t', '0xdac17f958d2ee523a2206206994597c13d831ec7', '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', 'TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8']);
  const WALLET_PATTERNS = [
    ['Bitcoin', /(?<![\w])(bc1[ac-hj-np-z02-9]{11,71}|BC1[AC-HJ-NP-Z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})(?![\w])/g, w => `https://www.blockchain.com/explorer/addresses/btc/${w}`],
    ['Ethereum/EVM', /(?<![\w])0x[a-fA-F0-9]{40}(?![\w])/g, w => `https://etherscan.io/address/${w}`],
    ['Tron (USDT-TRC20)', /(?<![\w])T[1-9A-HJ-NP-Za-km-z]{33}(?![\w])/g, w => `https://tronscan.org/#/address/${w}`],
  ];
  function extractWallets(text) {
    const wallets = [], rejected = [], shared = [];
    for (const [chain, re, explorer] of WALLET_PATTERNS) for (const addr of new Set(text.match(re) || [])) {
      const check = walletCheck(chain, addr);
      if (check === 'invalid') { rejected.push({ chain, addr, reason: chain === 'Ethereum/EVM' ? 'EIP-55 checksum fails' : 'checksum fails' }); continue; }
      const w = { chain, addr, explorer: explorer(addr), checksum: check === 'valid' ? 'valid' : 'unchecked' };
      (SHARED_WALLETS.has(chain === 'Ethereum/EVM' ? addr.toLowerCase() : addr) ? shared : wallets).push(w);
    }
    return { wallets, rejected, shared };
  }

  const BN_DIGITS = s => s.replace(/[০-৯]/g, c => String(c.charCodeAt(0) - 0x09E6));
  function extractEntities(input) {
    const text = BN_DIGITS(input);
    const urls = [...new Set((text.match(/\b((?:https?:\/\/|www\.)[^\s<>"')]+|[a-z0-9-]+\.(?:com|net|org|io|co|me|ly|xyz|top|link|app|site|online|info|ru|shop|live|click)(?:\/[^\s<>"')]*)?)/gi) || []).map(u => u.replace(/[.,;:!?]+$/, '')))];
    const phoneDetails = [];
    for (const m of text.matchAll(/(?<![\w+.:/-])\+?\(?\d[\d\s().-]{6,}\d(?![\w-]|\.\d)/g)) {
      const p = normalizePhone(m[0], text.slice(Math.max(0, m.index - 25), m.index));
      if (p && !phoneDetails.some(x => x.digits === p.digits)) phoneDetails.push(p);
    }
    const { wallets, rejected, shared } = extractWallets(text);
    return {
      urls,
      emails: [...new Set(text.match(/[\w.+-]+@[\w-]+\.[\w.-]+/g) || [])],
      phones: phoneDetails.map(p => p.e164 || p.raw),
      phoneDetails,
      handles: [...new Set(text.match(/(?<![\w.])@[A-Za-z0-9_.]{3,30}/g) || [])], // weak indicator only: never a "confirmed" repeat-offender link
      wallets,
      rejectedWallets: rejected,
      sharedWallets: shared,
      money: [...new Set(text.match(/(?:[$€£₹¥৳]\s?\d[\d,.]*\s?(?:k|m|million|billion)?|\d[\d,.]*\s?(?:usd|usdt|eur|gbp|btc|eth|dollars|euros|tk|taka|টাকা)(?![a-z]))/gi) || [])],
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

  // A payment or credential ask anywhere in the message (used for the signature-rule floor).
  const ASK = /\b(send|transfer|wire|pay|lend|deposit)\b[^.!?\n]{0,40}(\b(money|cash|funds|bill|invoice|fee|payment|rent)\b|\d[\d,.]*\s?k?\s?(usd|usdt|usdc|gbp|eur|inr|bdt|tk|taka|rs|rupees?|dollars?|pounds?|euros?|bucks)\b)|\b(pay|wire|lend)\b( me| us| it)?\b[^.!?\n]{0,10}\b(now|asap|today|urgently)\b|\b(bank details|account number|sort code|card number|cvv|password|pin)\b|[$€£₹৳]\s?\d|\b(taka|tk)\b[^.!?\n]{0,30}\b(pathao|pathan|pathaba|pathabe|din|den|dao|lagbe)\b|(টাকা|৳)[^।.!?\n]{0,30}(পাঠা|দাও|দিন|দেন|লাগবে)|\b(transferencia|transferência|virement|pix|kirim (uang|dana))\b|पैसे भेज|(أرسل|حوّل|حول)[^.!?\n]{0,10}(المال|مبلغ)/iu;
  const NON_SCHEME = ['Pressure', 'Payment rails', 'Off-platform move', 'Manipulation / misinformation', 'Engagement bait', 'Impersonation'];
  const SIGNATURE_FLOOR = 55;
  // The text a rule's `unless` guard is tested on: the sentence around the match, its neighbours, or the whole message.
  const sentenceAt = (s, i, len, scope) => {
    const back = a => { while (a > 0 && !/[.!?।\n]/.test(s[a - 1])) a--; return a; }, fwd = b => { while (b < s.length && !/[.!?।\n]/.test(s[b])) b++; return b; };
    let a = back(i), b = fwd(i + len);
    if (scope === 'message') return s;
    if (scope === 'adjacent') { if (a > 0) a = back(a - 1); if (b < s.length) b = fwd(b + 1); }
    return s.slice(a, b);
  };

  function analyze({ text = '', url = '' }) {
    const full = `${text}\n${url}`.normalize('NFC');
    const hits = [];
    for (const [cat, w, re, label, o = {}] of RULES) {
      const m = re.exec(full);
      if (!m || (o.unless && o.unless.test(sentenceAt(full, m.index, m[0].length, o.unlessScope)))) continue;
      const i = Math.max(0, m.index - 40);
      hits.push({ id: o.id, category: cat, weight: w, label, excerpt: (i > 0 ? '…' : '') + full.slice(i, m.index + m[0].length + 40).replace(/\s+/g, ' ').trim() + '…', match: m[0], signature: !!o.signature, scheme: o.scheme, lang: o.lang, plain: o.plain, advice: o.advice });
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
    if (entities.wallets.length) score += 18; // checksum-valid, non-shared addresses only
    if (byCat['Payment rails'] && Object.keys(byCat).length > 2) score += 10; // combo: story + payment ask
    if (byCat['Pressure'] && (byCat['Phishing'] || byCat['Investment / crypto'] || byCat['Giveaway / prize'] || byCat['Mobile-money fraud'])) score += 10;
    score += coord.length * 11;
    if (Object.entries(byCat).some(([k, v]) => v >= 30 && !['Pressure', 'Impersonation', 'Manipulation / misinformation', 'Engagement bait'].includes(k))) score += 12; // several markers of the same scheme reinforce each other
    // Signature rules are near-diagnostic: with a payment or credential ask present, the case is at least "Likely scam".
    const signatures = hits.filter(h => h.signature);
    const ask = RULES.some(([, , , , o = {}]) => o.ask && hits.some(h => h.id === o.id)) || !!byCat['Payment rails'] || entities.wallets.length > 0 || ASK.test(full);
    const signatureFloor = signatures.length > 0 && ask;
    if (signatureFloor) score = Math.max(score, SIGNATURE_FLOOR);
    score = Math.round(Math.min(100, score));

    const schemeTotals = {};
    hits.forEach(h => { const c = h.scheme || h.category; if (!NON_SCHEME.includes(c)) schemeTotals[c] = (schemeTotals[c] || 0) + h.weight + (h.signature && signatureFloor ? 100 : 0); });
    const scamCats = Object.entries(schemeTotals).sort((a, b) => b[1] - a[1]);
    const misinfo = (byCat['Manipulation / misinformation'] || 0) + (byCat['Engagement bait'] || 0);
    let verdict, category;
    if (score >= 70 && scamCats.length) { verdict = 'Scam'; category = scamCats[0][0]; }
    else if (score >= 50 && (scamCats.length || linkRisk >= 30)) { verdict = 'Likely scam'; category = scamCats[0]?.[0] || 'Phishing link'; }
    else if (coord.length >= 2) { verdict = 'Coordinated / inauthentic'; category = 'Coordinated inauthentic behaviour'; }
    else if (misinfo >= 16) { verdict = 'Misleading / manipulated'; category = 'Misinformation techniques'; }
    else if (score >= 25) { verdict = 'Suspicious'; category = scamCats[0]?.[0] || Object.keys(byCat)[0] || 'Unclear'; }
    else if (!text.trim() && !url) { verdict = 'Insufficient evidence'; category = '—'; }
    else { verdict = 'No strong red flags'; category = 'No known scheme matched'; }

    return { score, verdict, category, hits, byCategory: byCat, signatureFloor, entities, links, coordination: coord, platform, playbook: platform ? PLATFORM_PLAYBOOK[platform] || [] : [] };
  }

  // ---------- Plain-language actions and reporting routes (Simple mode) ----------
  // Every rule carries `advice` (a key below) and `plain` (a one-sentence reason). Reporting links were checked against the official sites.
  const ADVICE = {
    dont_pay: { text: 'Do not pay any fee, deposit or charge they ask for. If you already paid, contact your bank or payment app right away.', report: true },
    dont_click: { text: 'Do not tap the link. Open the company\'s official app or type its address yourself.', report: true },
    dont_share_code: { text: 'Never share a code, PIN, password or recovery phrase. If you already did, change your password and call your bank or provider now.', report: true },
    verify_official_channel: { text: 'Check with the company or agency using a phone number or website you find yourself, not one in the message.', report: true },
    verify_person: { text: 'Call the person on the number you already have, or ask a question only they would know, before doing anything.', report: true },
    block_report: { text: 'Stop replying, block the sender and report the account on the platform.', report: true },
    contact_bank: { text: 'Call your bank or card provider using the number on your card and ask them to stop or reverse the payment.', report: true },
    keep_evidence: { text: 'Do not delete anything. Take screenshots of messages, numbers and payment receipts and report them.', report: true },
    dont_install: { text: 'Do not install apps or give anyone remote access to your device. If you did, disconnect from the internet and get help from someone you trust.', report: true },
    no_recovery_fees: { text: 'Nobody can get lost money back for a fee. Report the original loss to the police and your bank only.', report: true },
    get_support: { text: 'Do not pay and do not reply. Save the messages, block the sender and talk to someone you trust or a support service.', report: true },
    take_your_time: { text: 'Slow down. A real company or person will still be there tomorrow; talk to someone you trust first.', report: false },
    check_before_sharing: { text: 'Check the claim with a trusted news source or fact-checker before sharing it.', report: false },
  };
  // Official reporting routes per country. `links` are https only; `phones` are numbers to show as text or tel: links.
  const REPORTING = {
    US: { name: 'United States', links: [{ label: 'FTC: report fraud', url: 'https://reportfraud.ftc.gov/' }, { label: 'FBI IC3: report internet crime', url: 'https://www.ic3.gov/' }] },
    UK: { name: 'United Kingdom', links: [{ label: 'Report Fraud (formerly Action Fraud)', url: 'https://www.reportfraud.police.uk/' }, { label: 'NCSC: report a scam email, text or website', url: 'https://www.ncsc.gov.uk/collection/phishing-scams/report-scam-email' }], phones: [{ label: 'Report Fraud', number: '0300 123 2040' }, { label: 'Forward scam texts to', number: '7726' }] },
    IN: { name: 'India', links: [{ label: 'National Cyber Crime Reporting Portal', url: 'https://cybercrime.gov.in/' }, { label: 'Sanchar Saathi: report fraud calls and SMS', url: 'https://sancharsaathi.gov.in/' }], phones: [{ label: 'Cyber crime helpline', number: '1930' }] },
    BD: { name: 'Bangladesh', links: [{ label: 'Police Cyber Support for Women (Facebook)', url: 'https://www.facebook.com/PCSW.PHQ' }, { label: 'BGD e-GOV CIRT: report a cyber incident', url: 'https://www.cirt.gov.bd/' }], phones: [{ label: 'National emergency service', number: '999' }, { label: 'bKash helpline (bKash fraud)', number: '16247' }] },
    EU: { name: 'European Union', links: [{ label: 'Europol: find your country\'s cybercrime reporting site', url: 'https://www.europol.europa.eu/report-a-crime/report-cybercrime-online' }] },
  };
  // Plain reasons + tailored actions for a result, strongest hit first. `country` is a REPORTING key (omit for none).
  function adviceFor(result, country) {
    const hits = [...(result?.hits || [])].filter(h => h.plain).sort((a, b) => b.weight - a.weight);
    const reasons = [...new Map(hits.map(h => [h.plain, { id: h.id, plain: h.plain, advice: h.advice }])).values()];
    const keys = [...new Set(hits.map(h => h.advice).filter(k => ADVICE[k]))];
    const actions = keys.map(key => ({ key, text: ADVICE[key].text }));
    const report = keys.some(k => ADVICE[k].report) && REPORTING[country] ? REPORTING[country] : null;
    return { reasons, actions, report };
  }

  const RULE_INDEX = RULES.map(([category, weight, re, label, o = {}]) => ({ id: o.id, category, weight, label, plain: o.plain, advice: o.advice, signature: !!o.signature, ask: !!o.ask, context: !!o.context, lang: o.lang || 'en', test: s => { const t = String(s).normalize('NFC'); const m = re.exec(t); return !!m && !(o.unless && o.unless.test(sentenceAt(t, m.index, m[0].length, o.unlessScope))); } }));
  window.DeduceHeuristics = { analyze, analyzeUrl, PLATFORM_PLAYBOOK, RULES: RULE_INDEX, ADVICE, REPORTING, adviceFor, normalizePhone, walletCheck, eip55 };
})();
