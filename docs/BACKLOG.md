# Scam Bunker research backlog

Prepared 26 November 2026 from the research behind `docs/METHODOLOGY.md`. Prioritised for engineers. No code has been changed.

Priority key: **P0** fixes a correctness or harm problem in shipped behaviour. **P1** is a high-value addition with a clear spec. **P2** is worth doing after P1.

Verification status key: **[tested]** means verified in this session (regexes run in Node against the phrases listed; API responses fetched live on 2026-11-26 and the shape copied from the real response). **[docs]** means taken from official documentation but not called. **[verify]** means from memory or secondary sources; confirm before building.

Scratch artefacts (not part of the repo):
- `/tmp/claude-0/-home-user/33e9c6b1-490b-5803-b683-d2f5ce7fa50d/scratchpad/rules.js` holds every proposed regex with its should and should-not phrases. `node rules.js` prints "all pass".
- `/tmp/claude-0/-home-user/33e9c6b1-490b-5803-b683-d2f5ce7fa50d/scratchpad/validators.js` is a zero-dependency, synchronous reference implementation of SHA-256, Base58Check, Bech32/Bech32m and a phone-number guard. `node validators.js` runs its self-tests.
- `/tmp/claude-0/-home-user/33e9c6b1-490b-5803-b683-d2f5ce7fa50d/scratchpad/scam.patched.js` is a copy of `public/scam.js` with the new rules applied. The existing `test/run.js` cases still pass against it (run via `run.patched.js` in the same folder).

---

## Summary: top items

| # | Pri | Item | Why |
|---|---|---|---|
| 1 | P0 | Validate phones before indexing | Dates such as `2024-11-26 10` are extracted as phone `2024112610` and stored as offender indicators, so unrelated cases with the same timestamp get linked as a "repeat offender" [tested] |
| 2 | P0 | Validate wallet checksums | Any 26 to 35 character Base58 string becomes a "Bitcoin wallet": +18 score and an offender indicator. The wallet in `test/run.js` (`TJYeasTPa6gpEEfYqCP9sMBc7NJqKPDJvT`) fails the Tron checksum [tested] |
| 3 | P0 | Fix the "is this Anna?" rule | The trailing `\b` after `\?` means the classic opener `Hello, is this Anna?` never matches [tested] |
| 4 | P0 | Tighten three over-broad rules | `guaranteed`, `10x` and `risk-free` fire on ordinary marketing; the OTP rule fires on bank safety warnings; `dear ... send` fires on customer service mail [tested] |
| 5 | P1 | Add 12 high-precision rules | Task scams, pay-to-withdraw, seed-phrase requests, recovery firms, "Hi Mum", toll and parcel smishing, sextortion and others. All tested |
| 6 | P1 | "Signature" rules | A single near-diagnostic rule currently cannot reach "Likely scam" because of the 0.85 multiplier and the 25/50/70 thresholds |
| 7 | P1 | Perceptual image hash (dHash) for the offender index | SHA-256 misses every re-encoded copy of a reused scam photo |
| 8 | P1 | Free lookups: Wayback CDX, RDAP, crt.sh, mempool.space, TronGrid, Blockscout, Open-Meteo | All verified live without a key |
| 9 | P1 | Evidence log and hashed export | Berkeley Protocol-style chain of custody; the pro tools all have it |
| 10 | P1 | Admiralty grading and estimative verdict language | Methodology section 3 |

---

## (i) Rule changes for `public/scam.js`

Rules are `[category, weight, regex, label]`. Current scoring: `score = sum(weights) * 0.85 + ...`, with **Suspicious at 25 or more**, **Likely scam at 50 or more** (needs a scam category or link risk 30 or more) and **Scam at 70 or more**. `Pressure`, `Payment rails`, `Off-platform move`, `Manipulation / misinformation`, `Engagement bait` and `Impersonation` are excluded from the scheme category. Any other category name counts as a scheme.

### P0-A. Fix: "wrong number" opener (Romance / pig-butchering)

Bug: `/\b(wrong number|sorry,? (i|I) (think|must have)|is this .{2,20}\?)\b/i`. The final `\b` after `?` requires a word character immediately after the question mark, so `Hello, is this Anna?` does not match. `is this Anna?Hi` does. The `.{2,20}` with `/i` would also match `is this the right place?` if the boundary bug were fixed.

```js
['Romance / pig-butchering', 12, /\b(wrong number|texted the wrong (person|number))\b|\b[Ii]s this [A-Z][a-z]{1,15}\s*\?/, '"Wrong number" opener (classic pig-butchering hook)'],
```

Note: no `/i` flag, deliberately. The capital letter is what separates a name from a question.

| Should match | Should not match |
|---|---|
| `Hello, is this Anna?` | `Is this the right place?` |
| `Sorry, I texted the wrong person` | `is this ok?` |
| `wrong number, sorry` | |

Known false positive: `Is this Monday?` (a capitalised common word). Acceptable at weight 12. Source for the indicator: 69% of interviewed victims were first contacted by a fake wrong-number message ([arXiv 2503.20821](https://arxiv.org/html/2503.20821v1)). [tested]

### P0-B. Fix: guaranteed returns (Investment / crypto, 24)

Bug: the bare words `guaranteed`, `risk-free`, `10x` and `100x` match `Satisfaction guaranteed or your money back`, `Risk-free 30 day trial` and `10x zoom lens`.

```js
['Investment / crypto', 24, /\b(guaranteed (returns?|profits?|income|payouts?)|risk[- ]free (investment|returns?|profits?|trading)|double your (money|bitcoin|crypto|investment)|passive income|daily (profit|returns?)|\d{1,4}% (daily |weekly |monthly )?(returns?|profit|roi))\b/i, 'Promises guaranteed or outsized returns'],
```

| Should match | Should not match |
|---|---|
| `Guaranteed returns of 30% monthly` | `Satisfaction guaranteed or your money back` |
| `5% daily returns on your USDT` | `Our product has a 10x zoom lens` |

If `10x` / `100x` coverage matters, add `\b(10|100|1000)x (returns?|gains?|your (money|investment))\b` as its own rule. [tested]

### P0-C. Fix: one-time code (Phishing, 20)

Bug: fires on safety advice such as `We will never ask for your verification code`. Combined with the brand rule, the Coinbase warning `Never share your seed phrase or verification code with anyone. Coinbase will never ask for it.` scored **Suspicious (29)**. With the guard it scores 12.

```js
['Phishing', 20, /(?<!\b(never|not|don'?t|do not|won'?t|will not|nobody|no one)\b[^.!?\n]{0,40})\b(one[- ]time|otp|verification|2fa|security) code\b/i, 'Mentions a one-time / verification code (never share these)'],
```

| Should match | Should not match |
|---|---|
| `Send me the verification code you just received` | `We will never ask for your verification code` |
| `Read me the 6-digit security code` | `Do not share this one-time code with anyone` |

JavaScript supports variable-length lookbehind (V8, SpiderMonkey, JavaScriptCore since Safari 16.4). [tested]

### P0-D. Tighten: affection plus money (Romance, 18)

`/\b(dear|my love|honey|...)\b.{0,80}\b(money|send|help|...)\b/is` matches `Dear customer, we will send your order tomorrow`. Drop `dear` from the first group, or require `dear` to be followed by a non-business word: replace `dear` with `dear(est)? (?!customer|sir|madam|user|member|client|valued)\w+`. [tested: the false positive; the replacement is untested]

### P0-E. Tighten: off-platform move (14)

`contact (me |us )?(on|via)` matches `Contact us on Monday about the invoice`. Make the platform group mandatory after `contact ... on|via`: `contact (me |us )?(on|via) (whats ?app|telegram|signal|wechat|line|kik)`. [tested: the false positive]

### P1-A. New rules

All [tested] against the phrases shown. Weights assume the "signature" change in P1-B. Without it, give the four rules marked **sig** a weight of at least 30 so that one hit reaches Suspicious.

| # | Category | Weight | Label |
|---|---|---|---|
| 1 | Job / recruitment | 20 | Task-scam jargon (product boosting / app optimisation / combination orders) |
| 2 | Advance-fee | 28 **sig** | Must pay a deposit, tax or fee before you can withdraw (pay-to-withdraw) |
| 3 | Phishing | 32 **sig** | Asks for a wallet seed / recovery phrase (whoever has it controls the wallet) |
| 4 | Phishing | 22 | Wallet "validation / sync / connect to claim" request (wallet-drainer pattern) |
| 5 | Recovery scam | 22 | Fund-recovery firm or "list of victims" approach (targets past victims) |
| 6 | Family-emergency impersonation | 32 **sig** | "Hi Mum / Dad, this is my new number" impersonation |
| 7 | Phishing | 20 | Unpaid toll / parking / fine text (smishing lure) |
| 8 | Phishing | 18 | Undeliverable-parcel / redelivery-fee lure |
| 9 | Tech support | 22 | Asks you to install a remote-access tool |
| 10 | Payment rails | 20 | Directs you to a crypto ATM / kiosk |
| 11 | Extortion | 32 **sig** | Claims compromising material and demands crypto (sextortion) |
| 12 | Investment / crypto | 18 | Celebrity "reveals new trading platform" (deepfake-ad pattern) |

`Family-emergency impersonation` and `Extortion` are new category names. They are deliberately not called `Impersonation`, which is excluded from scheme categories.

**1. Task-scam jargon.** Source: [FTC Data Spotlight, Dec 2024](https://www.ftc.gov/news-events/data-visualizations/data-spotlight/2024/12/paying-get-paid-gamified-job-scams-drive-record-losses) ("product boosting", "app optimization", tasks in sets, "double task").
```js
/\b(product boosting|boost(ing)? (products|orders|merchants?)|app optimi[sz]ation|data optimi[sz]ation|order grabbing|grab orders|double (task|order)s?|combination (task|order)s?|lucky order)\b/i
```
Match: `Our job is product boosting for merchants, 40 tasks per set` · `You got a combination order today, big commission` · `We are hiring for app optimization work`.
No match: `We optimised our app performance` · `Please review the products in our catalogue`.

**2. Pay-to-withdraw.** Sources: FTC (task scams), FinCEN pig-butchering alert, IC3 2025 (fake profits then fees).
```js
/\b(deposit|recharge|top[- ]?up|pay)\b[^.!?\n]{0,50}\b(to|before (you|u) can|in order to|so (you|u) can)\s+(withdraw|unfreeze|unlock|release|cash out)\b|\b(withdrawal|account)\b[^.!?\n]{0,30}\b(frozen|locked|suspended)\b[^.!?\n]{0,60}\b(tax|fee|deposit|margin|insurance|verification)\b/i
```
Match: `You must deposit 500 USDT to withdraw your profits` · `Your withdrawal is frozen, pay the 20% tax to release funds` · `Recharge your account so you can withdraw the commission` · `Pay the fee to unlock your account`.
No match: `You can withdraw cash from any ATM` · `I will transfer the money to withdraw later from savings`.

**3. Seed-phrase request.**
```js
/(?<!\b(never|not|don'?t|do not|won'?t|will not|nobody|no one)\b[^.!?\n]{0,25})\b(enter|share|send|provide|type|submit|confirm|validate|sync|import|give)\b[^.!?\n]{0,30}\b(seed|recovery|secret|mnemonic|backup) ?(phrase|words|key)\b/i
```
Match: `Please enter your 12 word seed phrase to verify` · `Support: send us your recovery phrase so we can sync`.
No match: `Never share your seed phrase with anyone` · `We will not ask you to enter your recovery phrase` · `Write down your recovery phrase and keep it offline`.

**4. Wallet drainer.**
```js
/\b(validate|synchroni[sz]e|sync|rectify|re-?activate|connect) (your )?wallet\b[^.!?\n]{0,40}\b(to (claim|receive|fix|restore|avoid|unlock)|airdrop|reward)\b|\bwallet (validation|synchroni[sz]ation|rectification)\b/i
```
Match: `Connect your wallet to claim the airdrop` · `Wallet validation required within 24h`.
No match: `Connect your wallet to the dapp to view your balance`.

**5. Recovery firm.** Source: [IC3 PSA250813, Aug 2025](https://www.ic3.gov/PSA/2025/PSA250813). Complements the existing recovery rule.
```js
/\b(crypto(currency)? (fund |asset )?recovery (law )?(firm|agency|agent|service|specialist)s?|asset recovery (agent|specialist|firm)|(list|database|registry) of (scam |fraud )?victims|recovered (your|the) (stolen|lost|scammed) funds)\b/i
```
Match: `We are a cryptocurrency recovery law firm working with the FBI` · `Your name is on a list of scam victims eligible for compensation` · `Asset recovery specialist can help you`.
No match: `The police recovered the stolen car`.

**6. "Hi Mum" new number.** `[^]` matches across newlines.
```js
/\b(hi|hey|hello)\s+(mum|mom|mam|mummy|mommy|dad|daddy)\b[^]{0,120}?\b(new (number|phone|mobile)|lost my phone|broke my phone|phone (is |got )?(broken|smashed|lost)|this is my new)\b/i
```
Match: `Hi Mum, this is my new number, my phone broke` · `hey dad lost my phone, text me here`.
No match: `Hi mum, see you at dinner`.

**7. Toll and fine smishing.**
```js
/\b(unpaid|outstanding|overdue)\s+(toll|parking|traffic|road|congestion)\s+(balance|fee|charge|fine|invoice|bill)s?\b/i
```
Match: `E-ZPass: You have an unpaid toll balance of $4.15. Pay now`. No match: `Toll roads are expensive`.

**8. Parcel lure.**
```js
/\b(package|parcel|shipment|delivery)\b[^.!?\n]{0,40}\b(could not be delivered|undeliverable|is on hold|held at (our|the) (depot|warehouse)|address (is )?(incomplete|incorrect|invalid)|redelivery fee)\b/i
```
Match: `USPS: Your package could not be delivered due to incomplete address` · `Your parcel is on hold, pay the redelivery fee`.
No match: `The package was delivered to your porch`.

**9. Remote-access install.** Broadens the existing tech-support rule, which only names AnyDesk and TeamViewer and fires on any mention.
```js
/\b(install|download|open)\b[^.!?\n]{0,30}\b(rustdesk|ultraviewer|screenconnect|connectwise|quick ?assist|quicksupport|supremo|airdroid|ammyy|anydesk|teamviewer)\b/i
```
Match: `Please download AnyDesk so our technician can help` · `Install RustDesk and tell me the code`.
No match: `I use TeamViewer at work`.
Then remove `remote access|anydesk|teamviewer` from the existing rule to avoid double counting.

**10. Crypto kiosk.** Source: [IC3 kiosk PSA, May 2026](https://www.ic3.gov/PSA/2026/PSA260515-2); FinCEN red flags. Overlaps the existing `crypto ?atm|bitcoin atm` alternatives in `Payment rails`; remove those from the existing rule.
```js
/\b(bitcoin|crypto(currency)?|btc)\s+(atm|kiosk|machine)s?\b|\b(scan|use) (the|this) qr code\b[^.!?\n]{0,60}\b(deposit|kiosk|atm|machine)\b/i
```
Match: `Withdraw cash and go to the nearest Bitcoin ATM` · `Scan the QR code at the kiosk to deposit`.
No match: `Scan the QR code to see the menu`.

**11. Sextortion.**
```js
/\b(recorded you|hacked (your|ur) (device|phone|computer|camera|webcam)|(intimate|nude|explicit|compromising) (video|photos?|images?|recording)s?)\b[^]{0,200}?\b(bitcoin|btc|crypto|usdt|wallet)\b/i
```
Match: `I have recorded you through your webcam. Send 1500 USD in bitcoin to this wallet` · `I hacked your camera and have an explicit video. Pay 0.05 BTC`.
No match: `We have new photos of the trip, I sent them to your wallet app`.
Advice text for this category must be supportive, must say not to pay, and must point to [NCMEC Take It Down](https://takeitdown.ncmec.org/) or [StopNCII](https://stopncii.org/) where minors or intimate images are involved. [verify the links]

**12. Celebrity platform.** Source: [NY AG deepfake alert, Aug 2024](https://ag.ny.gov/press-release/2024/investor-alert-attorney-general-james-warns-new-yorkers-investment-scams-using). Keep the name list short and global. Localise it per market through translations rather than growing it.
```js
/\b(elon musk|musk|jeff bezos|warren buffett?|bill gates|martin lewis|mark cuban|zuckerberg|cristiano ronaldo)\b[^.!?\n]{0,60}\b(new|secret|revolutionary|his|own|exclusive)\s+(ai |crypto |trading |investment |quantum )?(trading )?(platform|app|system|bot)\b/i
```
Match: `Elon Musk reveals his new AI trading platform` · `Martin Lewis exclusive investment app pays 3000 a day`.
No match: `Elon Musk bought Twitter in 2022`.

**Integration results** with all of the above applied (scratch copy, verdict and score):

| Input | Verdict |
|---|---|
| Task-scam message (product boosting, combination order, recharge to withdraw, WhatsApp) | Scam 100 |
| `Your withdrawal is frozen. Pay the 20% tax to release funds within 24 hours` | Suspicious 37 |
| `I hacked your camera and have an explicit video. Send 1500 USD in BTC ...` | Likely scam 58 |
| `Hi Mum, this is my new number, my phone broke. Can you pay a bill for me today?` | Suspicious 39 |
| `Satisfaction guaranteed or your money back. Free shipping on orders over $50` | No strong red flags 0 (was 20) |
| Coinbase-style safety warning about seed phrases and codes | No strong red flags 12 (was Suspicious 29) |
| All five existing `test/run.js` cases | Unchanged pass |

### P1-B. Engine change: signature rules

Several scams are identifiable from one sentence ("enter your seed phrase", "pay the tax to withdraw", "Hi Mum, new number"). The current arithmetic needs about 59 raw weight for "Likely scam" (50 / 0.85), so a single diagnostic rule tops out at "Suspicious".

Proposal: add an optional fifth element to a rule, `{ signature: true }`. If any signature rule fires and the message also contains a payment or credential ask (any `Payment rails`, wallet entity, money amount or link), set `score = max(score, 55)` so the verdict reaches "Likely scam". Signature rules: 2, 3, 6, 11 above, plus the existing gift-card rule. Add a test for each.

### P1-C. Entity-extraction fixes (feed the offender index)

These are correctness problems, because extracted entities become offender indicators in `public/app.js` `indicators()`.

1. **Phones [tested].** `/\+?\d[\d\s().-]{8,}\d/` extracts `2024-11-26 10`, `2024 11 26 1030` and `1234567890` from ordinary text, and `indicators()` keeps any value with 9 or more digits. Two cases mentioning the same timestamp are then reported as a repeat offender. Fix: filter candidates through `phoneOk()` from `validators.js`. It rejects ISO and day-month-year dates, repeated or sequential digits, and bare digit runs with no `+`, leading `0` or separators. Normalise to E.164 where a `+` country code is present, and keep `slice(-10)` only as a fallback key.
2. **Wallets [tested].** Validate before accepting:
   - Bitcoin legacy and P2SH (`1…`, `3…`): Base58Check (double SHA-256, 4-byte checksum).
   - Bitcoin `bc1…`: Bech32 (BIP-173) or Bech32m (BIP-350) checksum.
   - Tron `T…`: Base58Check, and the decoded first byte must be `0x41`.
   - EVM `0x…`: format only. EIP-55 mixed-case checksums need Keccak-256, which is not worth adding without a dependency. Record unchecked EVM addresses as "format-valid, checksum not verified".
   `validators.js` contains a synchronous SHA-256 (about 25 lines) so `scam.js` can stay synchronous. In the browser, `crypto.subtle.digest` is the async alternative.
   Also replace the wallet in `test/run.js` with a checksum-valid one, because the current fixture would be rejected. `TNXoiAJ3dct8Fjg4M9fkLFh9S2v9TXc32G` is valid and has real public USDT activity, so prefer a synthetic valid address generated for the test.
3. **High-activity wallets.** If a lookup is available (section ii), do not treat an address with very high transaction counts as identifying. Exchange hot wallets and token contracts are shared by thousands of users. For example, the USDT contract `TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t` currently scores Suspicious (30) on its own.
4. **Domains.** Extend `NOT_IDENTIFYING` with shared-hosting parents and link services when the host is the parent itself: `github.io`, `pages.dev`, `vercel.app`, `netlify.app`, `web.app`, `firebaseapp.com`, `blogspot.com`, `wixsite.com`, `square.site`, `carrd.co`, `notion.site`, `linktr.ee`, `beacons.ai`, `bio.link`. Subdomains of these (`scam-x.vercel.app`) remain identifying.
5. **Handles.** Keep handles as weak indicators only. They must never trigger the "confirmed repeat offender" escalation, which is already the case. Document this in code.

### P2. Rule hygiene

- Add a unit test per rule: at least two should-match and two should-not-match phrases, as above. Make `npm test` fail if any rule lacks them.
- Run every rule against a small benign corpus (newsletters, bank safety notices, recruiter emails, dating-app small talk) and report rules with more than a 1% hit rate.
- Translations: start with Spanish, Portuguese, French, Arabic, Hindi and Indonesian versions of rules 1, 2, 3 and 6. They are the most template-like.

---

## (ii) Free, no-key APIs worth integrating

All calls must be opt-in per case (README promise: nothing leaves the machine unless the user chooses). Route through `server.js` so the existing SSRF guard applies, with a per-host token bucket and a cache keyed on `(endpoint, indicator)`. Back off on 429 and 5xx. Never hard-code limits as business logic. TronGrid explicitly asks clients not to.

### 1. Wayback Machine CDX: earliest capture of a URL [tested]

Use: date a page or image URL (upper bound on "existed by"), first sighting of a scam domain, detect content changes via `digest`.

```
GET https://web.archive.org/cdx/search/cdx?url=<url>&output=json&fl=timestamp,original,statuscode,digest,mimetype&limit=3
```

Real response (example.com):
```json
[["timestamp","original","statuscode","digest","mimetype"],
 ["20020120142510","http://example.com:80/","200","HT2DYGA5UKZCPBSFVCV3JOBXGW2G5UUA","text/html"],
 ["20020328012821","http://www.example.com:80/","200","UY3I2DT2AMWAY6DECFCFYMT5ZOTFHUCH","text/html"]]
```
- The first row is a header. Results are oldest first, so `limit=1` gives the earliest capture. `limit=-1` gives the latest.
- Useful parameters ([CDX README](https://github.com/internetarchive/wayback/blob/master/wayback-cdx-server/README.md)): `matchType=exact|prefix|host|domain`, `from`/`to` (`yyyyMMddhhmmss`, any prefix), `filter=statuscode:200` (prefix `!` to negate), `collapse=digest` (one row per distinct content), `collapse=timestamp:8` (one per day), `showNumPages`, `page`.
- `timestamp` is UTC `yyyyMMddhhmmss`. A replay URL is `https://web.archive.org/web/<timestamp>/<original>`.
- Free, no key. Rate limit not published. The `wayback` Python library defaults to 1 CDX call per second ([edgi-govdata-archiving/wayback#12](https://github.com/edgi-govdata-archiving/wayback/issues/12)); use that. 429 means back off.
- Availability API (simpler, one result): `GET https://archive.org/wayback/available?url=<url>&timestamp=<yyyyMMdd>` returns `{"archived_snapshots":{"closest":{"available":true,"url":"…","timestamp":"…","status":"200"}}}`. [verify]
- Save Page Now: `GET https://web.archive.org/save/<url>` works anonymously at low volume; the SPN2 API uses account keys. [verify] An "Archive this evidence" button should at minimum open this URL in a new tab.

### 2. RDAP via rdap.org: domain registration date [tested]

```
GET https://rdap.org/domain/<domain>
```
rdap.org redirects to the authoritative registry server (here `rdap.verisign.com`), so follow redirects and re-run `assertPublicUrl` on each hop. Paths: `/domain/`, `/ip/`, `/autnum/`, `/entity/` ([about.rdap.org](https://about.rdap.org/)).

Real response fields used (example.com):
```json
{"ldhName":"EXAMPLE.COM",
 "status":["client delete prohibited","client transfer prohibited","client update prohibited"],
 "entities":[{"roles":["registrar"],"publicIds":[{"type":"IANA Registrar ID","identifier":"376"}],
              "vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","RESERVED-Internet Assigned Numbers Authority"]]]}],
 "events":[{"eventAction":"registration","eventDate":"1995-08-14T04:00:00Z"},
           {"eventAction":"expiration","eventDate":"2027-08-13T04:00:00Z"},
           {"eventAction":"last changed","eventDate":"2026-08-14T08:01:43Z"}],
 "nameservers":[{"ldhName":"ELLIOTT.NS.CLOUDFLARE.COM"},{"ldhName":"HERA.NS.CLOUDFLARE.COM"}]}
```
- Extract `registration` date, registrar `fn`, nameservers and status. Show domain age in days.
- Suggested grading: registered under 30 days ago and impersonating a brand counts as strong; under 30 days alone counts as moderate; old domains count as nothing (compromised old sites host phishing too).
- Limit: Cloudflare caps rdap.org at **10 requests per 10 seconds**, returning 429 above that. Bulk users should use the IANA bootstrap file (`https://data.iana.org/rdap/dns.json`) and query registries directly. Many ccTLDs have no RDAP service and return 404; handle it and show "no RDAP for this TLD".
- Free, no key.

### 3. crt.sh: certificate-transparency first seen [tested]

```
GET https://crt.sh/?q=<domain>&output=json
```
Real response fields: `[{issuer_ca_id, issuer_name, common_name, name_value ("\n"-separated SANs), id, not_before, not_after, serial_number, result_count}]`.
- `min(not_before)` is when the domain first had a public TLS certificate, a good proxy for "went live". It also reveals sibling subdomains (`name_value`) such as `login-paypal.<domain>`.
- Add `&exclude=expired` only if you want current certificates; omit it for history.
- No key. Frequently slow, and returns 502 or times out under load. Use a 20-second timeout, cache for 24 hours, and degrade gracefully. Do not call it on every case automatically.

### 4. mempool.space: Bitcoin address activity [tested]

```
GET https://mempool.space/api/address/<address>
```
Real response:
```json
{"address":"1wiz18xYmhRX6xStj2b9t1rwWX4GKUgpv",
 "chain_stats":{"funded_txo_count":11,"funded_txo_sum":15007688098,"spent_txo_count":5,"spent_txo_sum":15007599040,"tx_count":13},
 "mempool_stats":{"funded_txo_count":0,"funded_txo_sum":0,"spent_txo_count":0,"spent_txo_sum":0,"tx_count":0}}
```
- Sums are in satoshis. Received = `funded_txo_sum`; balance = `funded - spent`.
- First and last activity: `GET /api/address/<address>/txs` (Esplora API; newest first; paginate with `/txs/chain/<last_txid>`). Use `status.block_time` (Unix seconds). [docs]
- Show "received N BTC across M transactions since <date>". Very high `tx_count` (over 10,000, say) suggests an exchange or service wallet: do not index it as identifying.
- No key; limit not published. Use 1 request per second.

### 5. TronGrid: USDT-TRC20 transfers [tested]

Tronscan's `apilist.tronscanapi.com` returned **401 without a key** today. Tronscan announced mandatory API keys on 30 June 2025 ([announcement](https://support.tronscan.org/hc/en-us/articles/48411600548121-Announcement-on-Mandatory-Requirement-of-API-Key-for-All-Requests)). TronGrid still answered without a key:

```
GET https://api.trongrid.io/v1/accounts/<address>/transactions/trc20?limit=20&only_confirmed=true
```
Real response:
```json
{"data":[{"transaction_id":"2be2bc1d…","token_info":{"symbol":"USDT","address":"TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t","decimals":6,"name":"Tether USD"},
          "block_timestamp":1794878313000,"from":"TPtKNQuP9goF725MLLvtF3smX9SaAs2SuR","to":"TNXoiAJ3dct8Fjg4M9fkLFh9S2v9TXc32G","type":"Transfer","value":"2000000"}],
 "success":true,
 "meta":{"at":1795690851766,"fingerprint":"…","links":{"next":"https://api.trongrid.io/…&fingerprint=…"},"page_size":1}}
```
- `value` is a string in base units (divide by 10^`decimals`). `block_timestamp` is in milliseconds. Paginate with `meta.links.next`.
- An invalid address returns HTTP 400 `{"error":"A valid account address is required.","statusCode":400,"success":false}`.
- Without a key, TronGrid says to expect "strict rate limiting or rejection" ([rate limits](https://developers.tron.network/reference/rate-limits)). Support an optional `TRON_PRO_API_KEY` env var sent as the `TRON-PRO-API-KEY` header. Update the Tron explorer link in `scam.js` only if `tronscan.org/#/address/` stops working for humans (it is a web page, not the API).

### 6. Blockscout: EVM address activity without Etherscan [tested]

Etherscan requires a key (free tier 3 calls per second, 100,000 per day; [docs](https://docs.etherscan.io/rate-limits)). Blockscout answered without one:

```
GET https://eth.blockscout.com/api/v2/addresses/<address>/counters
```
Real response: `{"transactions_count":"3270","token_transfers_count":"8376192","gas_usage_count":"100867063","validations_count":"0"}` (numbers are strings).
- `GET /api/v2/addresses/<address>` returns balance and contract flags. [docs] That call timed out once in testing, so use a 15-second timeout.
- Other chains use other hosts (for example `base.blockscout.com`, `optimism.blockscout.com`). [verify] A wallet regex match does not tell you the chain, so query Ethereum mainnet first and label the result as Ethereum only.

### 7. Open-Meteo historical weather [tested]

Use: check claimed weather against the date and place (GPS or user-entered).

```
GET https://archive-api.open-meteo.com/v1/archive?latitude=38.7&longitude=-9.17&start_date=2020-11-22&end_date=2020-11-22&daily=weather_code,precipitation_sum,cloud_cover_mean,sunrise,sunset&timezone=UTC
```
Real response:
```json
{"latitude":38.69947,"longitude":-9.196167,"timezone":"GMT",
 "daily_units":{"time":"iso8601","weather_code":"wmo code","precipitation_sum":"mm","cloud_cover_mean":"%","sunrise":"iso8601","sunset":"iso8601"},
 "daily":{"time":["2020-11-22"],"weather_code":[2],"precipitation_sum":[0.00],"cloud_cover_mean":[3],"sunrise":["2020-11-22T07:27"],"sunset":["2020-11-22T17:18"]}}
```
- For a capture time, request `hourly=cloud_cover,precipitation,snowfall,snow_depth,weather_code` instead.
- No key. Free for non-commercial use up to 10,000 calls per day. Data is CC BY 4.0, so **show attribution** ("Weather data by Open-Meteo.com") wherever it is displayed ([open-meteo.com](https://open-meteo.com/)). Reanalysis is gridded (about 9 to 25 km), so a sunny grid cell does not disprove a local shower. Grade matches as supporting (C3) and stark contradictions (heavy snow claimed, 25 °C and clear recorded) as strong.

### 8. Sun position: compute locally, no API

Port the SunCalc algorithm (Vladimir Agafonkin, BSD-2-Clause; about 100 lines) into `public/forensics.js`. With EXIF GPS and `DateTimeOriginal` (or user-entered values), show sun azimuth and elevation and the expected shadow length ratio (`1 / tan(elevation)`), plus a deep link `https://www.suncalc.org/#/<lat>,<lon>,17/<yyyy.mm.dd>/<hh:mm>/1/3`. Remember EXIF time has no time zone unless `OffsetTimeOriginal` is present: show the assumption. [verify the link format against suncalc.org]

### 9. ScamSniffer phishing-domain list (no key, GPL-3.0) [docs]

```
GET https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json
```
A `string[]` of crypto-phishing hostnames, updated daily ([repo](https://github.com/scamsniffer/scam-database)). The address list (`address.json`) has not been updated since February 2024; do not use it. The data is **GPL-3.0**. Fetch it at runtime and cache it in memory or the user's browser. Do not vendor it into this MIT repository. A hit is graded C2 (community-maintained).

### Needs a key (free account) or is paid: support as optional env vars only

| Service | Access | Notes |
|---|---|---|
| Google Fact Check Tools API | Free; API key from a Google Cloud project ([docs](https://developers.google.com/fact-check/tools/api)) | `GET https://factchecktools.googleapis.com/v1alpha1/claims:search?query=…&languageCode=en&maxAgeDays=…&pageSize=10&key=…` returns `{claims:[{text, claimant, claimDate, claimReview:[{publisher:{name,site}, url, title, reviewDate, textualRating, languageCode}]}], nextPageToken}` [docs for the endpoint; claim fields from memory, verify]. There is also an image-query method (`claims:imageSearch`) [verify]. Best single addition for the Fact Checker agent: `FACTCHECK_API_KEY` |
| Chainabuse | Free account, API key sent as HTTP Basic auth (key as both username and password) ([docs](https://chainabuse.readme.io/docs/get-reports-parameters)) | Get Reports filtered by `address`, `chain`, `category`, `checked`, `trusted`, up to 50 per page. Returns category, report date, description, reported loss and other IOCs. Show only the count and categories, and grade C (user reports) or B3 if `checked=true` |
| URLhaus (abuse.ch) | Free `Auth-Key` now required ([docs](https://urlhaus.abuse.ch/api/)) | Malware-distribution URLs. Less relevant to scams than phishing feeds |
| Etherscan | Free key, 3 calls per second, 100,000 per day | Prefer Blockscout |
| Tronscan API | Key mandatory since mid-2025 | Prefer TronGrid |
| Have I Been Pwned | Email search needs a paid key; Pwned Passwords range API is free ([docs](https://haveibeenpwned.com/API/V3)) | Not relevant to scam detection; do not add |
| ScamAdviser, ScamSniffer API | Commercial | Not for a zero-dependency open tool |

### Reverse-image deep links (no API, improves current UX)

`reverseLinks()` in `public/forensics.js` links to engine home pages, so the user must re-upload. When the case has a public image URL, link straight to results [verify each pattern]:

- Google Lens: `https://lens.google.com/uploadbyurl?url=<enc>`
- TinEye: `https://tineye.com/search?url=<enc>&sort=crawl_date&order=asc` (oldest first)
- Bing: `https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:<enc>`
- Yandex: `https://yandex.com/images/search?rpt=imageview&url=<enc>`
- Google Fact Check Explorer: `https://toolbox.google.com/factcheck/explorer/search/<enc query>`

For local files, add "Copy flipped image" and "Copy crop" buttons (canvas `scale(-1,1)`), as the InVID magnifier does. Mirrored re-uploads defeat most engines.

---

## (iii) Features the professional tools have that Scam Bunker lacks

Ordered by priority. Each cites the tool or practice it is modelled on.

### P1-1. Verification checklist panel (First Draft five pillars)
A tab showing Provenance, Source, Date, Location and Motivation, each with status `not started | partial | done | not possible`, the evidence attached, and a free-text note. Pre-fill from automation (for example Date is "partial" if EXIF has `DateTimeOriginal`). Include it in exports. Model: [First Draft](https://firstdraftnews.org/long-form-article/verifying-online-information/); Meedan Check's per-item verification status ([meedan.org/check](https://meedan.org/check)).

### P1-2. Evidence grading (Admiralty A to F, 1 to 6)
Each observation gets `sourceGrade` (A to F, default F) and `credibility` (1 to 6, default 6), editable in the UI. Map the engine's `proof/strong/weak` to defaults as in METHODOLOGY section 3.1. Add the two fields to the Lead Investigator JSON schema in `server.js` (`observations[].grade`). Enforce in code that nothing is labelled "confirmed" without at least two items graded 1 or 2 from different sources.

### P1-3. Estimative verdict language and analytic confidence
Add `likelihood` (one of the seven ICD 203 terms) and `analytic_confidence` (`high | moderate | low`) to the verdict, and render the headline as, for example, "Very likely a task scam (moderate confidence)". Replace the opaque `confidence` integer in the UI. The integer can remain internally. Model: [ICD 203](https://www.dni.gov/files/documents/ICD/ICD-203.pdf).

### P1-4. Evidence locker, case log and hashed export (chain of custody)
- On intake: SHA-256 of every file (already done for images; add text, as UTF-8 normalised NFC), capture time in UTC, source URL, user-entered "where I got this".
- Append-only case log: `{ts, action, input, outputDigest, prevHash, hash}` where `hash = sha256(prevHash + canonicalJSON(entry))`. Any edit to history breaks the chain.
- "Export evidence package": a JSON file (case, observations with grades, log, hashes), the original files, the HTML report, and a `SHA256SUMS` manifest, all in one download. A zero-dependency ZIP writer (store-only, no compression) is about 80 lines, or offer separate downloads.
- Redaction option: replace the victim's own name, phone and email with placeholders in the report and export.
- Model: [Berkeley Protocol](https://www.ohchr.org/sites/default/files/2024-01/OHCHR_BerkeleyProtocol.pdf).

### P1-5. Perceptual hash (dHash) for image matching
Compute a 64-bit dHash in `forensics.js`: draw to a 9×8 grayscale canvas, compare each pixel with its right neighbour, giving 64 bits ([Krawetz, 2013](https://www.hackerfactor.com/blog/?/archives/529-Kind-of-Like-That.html)). Store it as an `imagep` indicator. Match by Hamming distance: 0 to 4 is strong ("same image, re-encoded"), 5 to 10 is weak ("possibly the same; review"), above 10 is no match ([Krawetz, 2011](https://www.hackerfactor.com/blog/index.php?/archives/432-Looks-Like-It.html)). Also hash the horizontally flipped image to catch mirrored reuse. Skip near-uniform images (hash `0x0000…` or `0xffff…`). The matching UI must say that the person shown is probably a victim of photo theft (METHODOLOGY section 7).

### P1-6. Dating timeline that merges external evidence
Extend the existing Timeline tab with sourced events beyond EXIF: Wayback first capture, RDAP registration, first certificate, first blockchain transaction, and user-entered "earliest copy found on <engine> dated <date>". Show the earliest-possible and latest-possible bounds as an interval with the grade of each bound. Model: Bellingcat chronolocation timelines.

### P1-7. Existing fact-check lookup (Fact Checker agent)
With `FACTCHECK_API_KEY` set, run `claims:search` on the top extracted claims before the agent runs, and pass the results as "prior fact-checks" in the case file. Display publisher, rating and link. Without a key, show a deep link to Fact Check Explorer. Model: Google Fact Check Tools; Full Fact and Meedan claim matching.

### P2-1. Template and claim matching across local cases
Compute word 5-gram shingles (or MinHash) per case and flag earlier cases with Jaccard similarity of 0.6 or more as "same script". This catches scam templates that rotate wallets and handles, which is the most common evasion. Keep it local. Model: [Full Fact AI](https://fullfact.org/ai/) and [Meedan](https://meedan.org/post/claim-matching-global-fact-checks-at-meedan) claim matching.

### P2-2. Link graph view for the offender index
A small SVG force layout or a plain adjacency table: cases as nodes, shared indicators as labelled edges coloured by strength. Clusters get pseudonymous IDs. This replaces the flat "Repeat offenders across your cases" list.

### P2-3. Video keyframes
Accept MP4 or WebM, seek a `<video>` element at intervals or on scene change (frame-difference threshold), draw frames to canvas, and offer each frame for reverse search and the vision agent. Zero-dependency. Model: InVID keyframes.

### P2-4. "What would change this verdict" and limitations
Add two fields to the Lead Investigator schema: `limitations[]` and `would_change_if[]`. Show both in reports. Model: DFRLab attribution criteria ("acknowledges relevant limitations"); IFCN transparency.

### P2-5. Reporting routes
After a scam verdict, show where to report based on platform and the user's selected country: IC3, ReportFraud.ftc.gov, Action Fraud (UK), the platform's report flow, the user's bank, and Chainabuse for wallets. Prefill a copyable summary with the hashed evidence list.

### P2-6. Corrections log
If a user later re-labels a saved case (for example "turned out legitimate"), record it and feed it back: count false positives per rule locally and surface "this rule has been wrong N times in your cases". This is the IFCN corrections principle applied to rules.

---

## (iv) Things to avoid

1. **Treating ELA, noise statistics or AI-detector scores as proof.** Grade them C3 at best when alone. The InVID-WeVerify deepfake tool's documentation says its scores are leads, not calibrated probabilities.
2. **Treating missing EXIF as suspicious.** Almost every platform strips it. Remove the `+5` suspicion for empty EXIF in `forensics.js`, or keep it only as a provenance note that does not feed the score.
3. **Trusting `file.lastModified`.** It is the download time. It is already labelled low trust; keep it out of `earliest`.
4. **Calling string matches "C2PA verified".** Searching for `jumb|c2pa` only shows a manifest might exist. Label it "Content Credentials present (not validated)" until signatures are checked, or link to contentcredentials.org/verify.
5. **Username enumeration and people search.** Do not add Sherlock-style or WhatsMyName-style lookups, face search or people-search APIs. They create doxxing and stalking risk and are outside the tool's purpose. WhatsMyName's dataset is CC BY-SA 4.0, so bundling it would impose ShareAlike terms, and the project was archived in November 2026 ([repo](https://github.com/webbreacher/whatsmyname)).
6. **Indexing the person in the photo.** Never label a face or a stolen profile photo as "the scammer". Reused images link campaigns, not people.
7. **Shared infrastructure as identifiers.** Cloudflare or other CDN IPs, registrars, hosting providers, TLDs, exchange hot wallets, token contracts, platform domains and URL shorteners identify nobody.
8. **Publishing or syncing the offender index.** Keep it local. A shared public list of phone numbers or handles would carry defamation and data-protection risk and would include spoofed numbers belonging to innocent people.
9. **Broad single-word rules.** "guaranteed", "dear", "urgent", "verified", "admin", "10x". Every rule needs should-not-match tests drawn from safety notices and ordinary marketing.
10. **Silent third-party calls.** Every lookup sends an indicator (and possibly the user's IP, via the server) to a third party. Make lookups opt-in and say which service receives what. Never send images to reverse-search or AI services without explicit consent.
11. **Building on dead or closed services.** CrowdTangle shut down on 14 August 2024. Meta Content Library is for approved academic and non-profit researchers only and excludes commercial newsrooms. Hoaxy was retired in July 2025 (replaced by OSoMeNet). Tronscan's API now needs a key. Do not design features that depend on them, and do not scrape logged-in platform content.
12. **Hard-coded rate limits as logic.** rdap.org allows 10 requests per 10 seconds; Wayback, mempool.space and TronGrid publish no fixed limits. Implement back-off and caching instead.
13. **Vendoring GPL data.** ScamSniffer's list is GPL-3.0; fetch it at runtime.
14. **Advice that re-victimises.** Never suggest a "recovery service". Flag them as the known follow-on scam (IC3 2025: 10,516 complaints, $1.4 billion lost).

---

## Source index (accessed 2026-11-26)

Primary sources used for this backlog. See `docs/METHODOLOGY.md` for the full set.

- FBI IC3 2025 Annual Report: https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf
- IC3 PSA, fictitious law firms (13 Aug 2025): https://www.ic3.gov/PSA/2025/PSA250813
- IC3 PSA, crypto kiosks (May 2026): https://www.ic3.gov/PSA/2026/PSA260515-2
- FTC, 2025 fraud and imposter data (June 2026): https://www.ftc.gov/news-events/news/press-releases/2026/06/ftc-data-show-people-reported-losing-3-point-5-billion-imposter-scams-2025
- FTC Data Spotlight, task scams (12 Dec 2024): https://www.ftc.gov/news-events/data-visualizations/data-spotlight/2024/12/paying-get-paid-gamified-job-scams-drive-record-losses
- FinCEN FIN-2023-Alert005 (pig butchering): https://www.fincen.gov/system/files/shared/FinCEN_Alert_Pig_Butchering_FINAL_508c.pdf
- FinCEN FIN-2026-Alert005 (scam centers, 3 Sep 2026): https://www.fincen.gov/system/files/2026-08/FinCEN-Alert-Scam-Centers.pdf
- GASA Global State of Scams 2025 (7 Oct 2025): https://gasa.org/knowledge-base/blog/global-scams-on-the-rise-over-half-of-adults-worldwide-report-scam-encounters
- Wayback CDX server README: https://github.com/internetarchive/wayback/blob/master/wayback-cdx-server/README.md
- rdap.org: https://about.rdap.org/
- TronGrid rate limits: https://developers.tron.network/reference/rate-limits
- Tronscan API key announcement: https://support.tronscan.org/hc/en-us/articles/48411600548121-Announcement-on-Mandatory-Requirement-of-API-Key-for-All-Requests
- Etherscan rate limits: https://docs.etherscan.io/rate-limits
- Open-Meteo: https://open-meteo.com/ and https://open-meteo.com/en/docs/historical-weather-api
- Google Fact Check Tools API: https://developers.google.com/fact-check/tools/api/reference/rest/v1alpha1/claims/search
- Chainabuse API: https://chainabuse.readme.io/docs/get-reports-parameters
- ScamSniffer scam-database: https://github.com/scamsniffer/scam-database
- URLhaus API: https://urlhaus.abuse.ch/api/
- HIBP API v3: https://haveibeenpwned.com/API/V3
- Hacker Factor perceptual hashing: https://www.hackerfactor.com/blog/index.php?/archives/432-Looks-Like-It.html
- C2PA implementation guidance: https://spec.c2pa.org/specifications/specifications/2.4/guidance/Guidance.html
- Berkeley Protocol: https://www.ohchr.org/sites/default/files/2024-01/OHCHR_BerkeleyProtocol.pdf
- WhatsMyName: https://github.com/webbreacher/whatsmyname
- Sherlock: https://github.com/sherlock-project/sherlock
- arXiv 2503.20821 (pig-butchering lifecycle): https://arxiv.org/html/2503.20821v1
