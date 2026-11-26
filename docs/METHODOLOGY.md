# Scam Bunker Methodology

How Scam Bunker verifies content, grades confidence, dates images, classifies scams and links repeat offenders, and the limits it works within.

This document is for two audiences. **Users** can read it to understand what a verdict means and how far to trust it. **Contributors** can use it as the specification that rules, agents and reports must follow. Where a practice comes from a professional verification or fraud-intelligence organisation, the source is linked inline and credited again in [Lineage](#9-lineage).

Last reviewed: 26 November 2026. Statistics and tool availability change quickly; every dated claim below carries the date of its source.

---

## Contents

1. [Principles](#1-principles)
2. [The verification workflow](#2-the-verification-workflow)
3. [Confidence and source grading](#3-confidence-and-source-grading)
4. [Dating an image and finding the original](#4-dating-an-image-and-finding-the-original)
5. [Scam typology and indicators](#5-scam-typology-and-indicators)
6. [Repeat-offender profiling](#6-repeat-offender-profiling)
7. [Ethical and legal guardrails](#7-ethical-and-legal-guardrails)
8. [Evidence preservation and chain of custody](#8-evidence-preservation-and-chain-of-custody)
9. [Lineage](#9-lineage)
10. [Known gaps](#10-known-gaps)

---

## 1. Principles

1. **Separate observation from inference.** Every finding records what was seen (the fact) and what it suggests (the inference), each with its own strength. This mirrors the [DFRLab attribution criterion](https://dfrlab.org/2024/10/23/dfrlab-launches-fiat-2024/) that an assessment "clearly distinguishes factual information from argumentative analysis".
2. **Grade the source and the information separately.** A reliable source can relay a false claim, and an unknown source can relay a true one. Section 3 explains the two-axis grading.
3. **Absence of evidence is not evidence.** Missing EXIF does not mean an image is AI-generated. A message with no matched pattern is not thereby legitimate.
4. **Prefer the original.** Provenance is checked first, because if you are not looking at the original, every later judgement about who, when and where may be wrong ([First Draft](https://firstdraftnews.org/long-form-article/verifying-online-information/)).
5. **Replicability.** Sources are recorded in enough detail that another person can repeat the work, except where that would endanger someone. This follows principle 2 of the [IFCN Code of Principles](https://ifcncodeofprinciples.poynter.org/the-commitments).
6. **Corroborate before concluding.** [AFP Fact Check](https://factcheck.afp.com/How-we-work) requires at least two independent sources for the central claim of a fact-check. Scam Bunker applies the same bar to any statement that something is "confirmed".
7. **Do no harm.** Scam Bunker identifies schemes and infrastructure. It does not identify private people. See section 7.

---

## 2. The verification workflow

Every case moves through the same seven stages. The local engine automates parts of stages 1 to 4; the agent team and the investigator do the rest.

### Stage 0. Stop and preserve

Before analysis, capture the evidence as received: the file, the text, the URL, a screenshot, and the time of capture in UTC. Hash the files (SHA-256). Archive public URLs while they are still live. Scam posts and phishing pages are often deleted within hours. See section 8.

This is the "Stop" move of Mike Caulfield's [SIFT method](https://hapgood.us/2019/06/19/sift-the-four-moves/): pause before reacting or sharing.

### Stage 1. Provenance: is this the original?

- Look for earlier or higher-quality copies (section 4).
- Check whether the text is a known template, copied from earlier scam reports or from earlier cases in the local index.
- For a claim, search existing fact-checks first. Google's [Fact Check Explorer](https://toolbox.google.com/factcheck/explorer) and the [Fact Check Tools API](https://developers.google.com/fact-check/tools/api) index fact-checks published with [ClaimReview](https://www.claimreviewproject.com/) markup, and Fact Check Explorer also accepts images ([Google, 2023](https://blog.google/products-and-platforms/products/search/google-search-new-fact-checking-features/)). Re-used false claims are the norm: [Full Fact's](https://fullfact.org/ai/) and [Meedan Check's](https://meedan.org/post/claim-matching-global-fact-checks-at-meedan) claim-matching systems exist because the same falsehood keeps resurfacing with small variations.

### Stage 2. Source: who created it, and who is spreading it?

Distinguish the **capturer** (who took the photo or wrote the original text) from the **poster** (who shared this copy). First Draft calls the capturer the primary source.

Investigate the source **laterally**: leave the page and read what other, independent sources say about the account, domain or organisation, rather than judging it by its own presentation. Stanford researchers found professional fact-checkers outperform experts by doing exactly this ([Wineburg and McGrew, 2019](https://doi.org/10.1177/016146811912101102)). It is also the "Investigate the source" move in SIFT.

For accounts and domains, record: account or domain age (RDAP registration date, first certificate, first archive capture), naming pattern (lookalikes, digit suffixes), off-platform redirection, and whether it impersonates a brand, agency or person.

### Stage 3. Date: when was it created?

Establish an interval, not a point: the **earliest possible** date (from content and context) and the **latest possible** date (the earliest verified publication). Section 4 gives the method. Bellingcat's [chronolocation guide](https://www.bellingcat.com/resources/2023/05/08/chronolocation-determining-when-a-photo-was-taken-using-facebook-google-street-view-and-assorted-tiny-details/) shows how this interval narrows with each verified clue.

### Stage 4. Location: where was it created?

Use embedded GPS only as a lead; it can be forged and is usually stripped. Confirm or eliminate candidate locations from visible features, sun and shadow geometry ([Bellingcat, 2020](https://www.bellingcat.com/resources/2020/12/03/using-the-sun-and-the-shadows-for-geolocation/); [Shadow Finder, 2024](https://www.bellingcat.com/resources/2024/08/22/shadow-geolocate-geolocation-locate-image-tool-open-source-bellingcat-measure/)) and weather history. Sanad, Al Jazeera's verification agency, stresses verifying both the temporal and spatial context, because content can be accurate yet misleading when moved out of context ([Al Jazeera Media Institute, April 2025](https://institute.aljazeera.net/en/ajr/article/3122)).

For scams, "location" also means the infrastructure: where the domain is registered and hosted, and which payment rail and blockchain the money moves on.

### Stage 5. Motivation: why does it exist?

For disinformation: political, commercial (engagement farming), or ideological. For scams the motive is almost always money, so the question becomes **which stage of which playbook** this message represents (hook, trust-building, urgency, payment ask, or re-victimisation). Section 5 lists the playbooks.

### Stage 6. Corroborate and decide

"Find better coverage" (SIFT): look for independent reporting on the same claim, scheme, wallet or domain. Grade each piece of evidence (section 3), then reach a case verdict. Record what evidence would change the verdict.

### Stage 7. Report, act and correct

The report states the verdict, the grade of each supporting item, the limitations, and the next pivots. It ends with advice for the person: stop paying, preserve evidence, report to the platform and to the relevant authority (for example [IC3](https://www.ic3.gov/) in the US, [ReportFraud.ftc.gov](https://reportfraud.ftc.gov/), or the national fraud reporting service elsewhere). If a verdict is later shown to be wrong, the case is corrected visibly, in line with IFCN principle 5.

### The checklist

Each case should be able to answer these questions, or state that it cannot:

| Pillar | Question | Typical evidence |
|---|---|---|
| Provenance | Is this the original? Has it been fact-checked before? | Reverse image search, earliest copy, fact-check search, template match |
| Source | Who made it? Who is spreading it? | Account and domain age, lateral reading, impersonation checks |
| Date | Earliest and latest possible dates? | Metadata, earliest indexed copy, archive captures, chronolocation |
| Location | Where was it made? Where is the infrastructure? | Visual geolocation, shadows, weather, RDAP, hosting, chain |
| Motivation | Why does it exist? Which playbook stage? | Scam typology, payment ask, engagement pattern |

The five pillars are First Draft's ([Verifying Online Information](https://firstdraftnews.org/long-form-article/verifying-online-information/)).

---

## 3. Confidence and source grading

Scam Bunker uses three layers of grading. They must not be collapsed into a single number.

### 3.1 Evidence items: the Admiralty (NATO) system

Each piece of evidence is graded on two independent axes, as in the Admiralty Code, formalised by NATO in AJP-2.1 ([summary of AJP-2.1, 2016 edition](https://pangearesearch.substack.com/p/the-admiralty-code-nato-6x6-system); [overview](https://en.wikipedia.org/wiki/Admiralty_code)).

**Source reliability (letter)**

| Grade | Meaning | Scam Bunker examples |
|---|---|---|
| A | Completely reliable. No doubt about authenticity, trustworthiness or competency; history of complete reliability | A cryptographically valid C2PA manifest; a blockchain record; an RDAP response from the registry |
| B | Usually reliable. Minor doubts; mostly valid history | An established fact-checking organisation's published finding; the Wayback Machine capture record |
| C | Fairly reliable. Some doubt; has provided valid information before | Community scam-report databases; a reputable news report |
| D | Not usually reliable. Significant doubt | Anonymous forum posts; a single unverified victim report |
| E | Unreliable. History of invalid information | The scammer's own claims; a known disinformation outlet |
| F | Reliability cannot be judged | Any new or unknown source. This is the default |

**Information credibility (number)**

| Grade | Meaning |
|---|---|
| 1 | Confirmed by other independent sources; logical; consistent with other information |
| 2 | Probably true. Not confirmed, but logical and consistent |
| 3 | Possibly true. Not confirmed; reasonably logical; agrees with some other information |
| 4 | Doubtful. Possible but not logical; nothing to compare against |
| 5 | Improbable. Not logical; contradicted by other information |
| 6 | Truth cannot be judged |

A grade is written as a pair, for example **B2** or **F6**. The two axes are judged separately. The most common analytic error is letting the source's reputation pull the credibility grade along with it.

Note on sources: some secondary summaries of the Admiralty Code swap the meaning of E and F. Scam Bunker follows AJP-2.1, where **E is unreliable** and **F is cannot be judged**.

**Mapping to Scam Bunker's existing labels.** The engine labels each automated finding `proof`, `strong` or `weak`. These describe the diagnostic power of the signal, not its source. Use them as follows:

| Engine label | Meaning | Typical Admiralty pair |
|---|---|---|
| proof | An explicit declaration or a cryptographic fact (C2PA AI assertion, IPTC `trainedAlgorithmicMedia`, embedded diffusion parameters, a wallet reused from a confirmed case) | A1 to B2 |
| strong | Highly diagnostic but forgeable or circumstantial (generator signature string, typosquat domain, request for a seed phrase) | B2 to C3 |
| weak | Consistent with the hypothesis but common in innocent content (urgency wording, canvas size, missing EXIF) | C3 to F6 |

### 3.2 Case verdict: estimative language

A verdict must say how likely it is, in words with fixed meanings. Scam Bunker adopts the probability scale of US Intelligence Community Directive 203 ([ICD 203, 2015](https://www.dni.gov/files/documents/ICD/ICD-203.pdf)):

| Term | Probability |
|---|---|
| Almost no chance | 1 to 5% |
| Very unlikely | 5 to 20% |
| Unlikely | 20 to 45% |
| Roughly even chance | 45 to 55% |
| Likely | 55 to 80% |
| Very likely | 80 to 95% |
| Almost certain | 95 to 99% |

The existing verdict labels map to this scale: **Scam** means "very likely" or above, **Likely scam** means "likely", **Suspicious** means "roughly even chance" or a weak signal set worth checking, and **No strong red flags** means no known pattern matched. That last label is never a statement that content is safe.

### 3.3 Analytic confidence

Separately from probability, state confidence in the analysis itself: **high** (several independent, well-graded items agree), **moderate** (credible but limited or single-source), or **low** (fragmentary, untested, or dependent on the scammer's own claims). A verdict can be "likely scam, low confidence", meaning the indicators point one way but there is little of them.

### 3.4 Rules for combining evidence

- Two or more independent items graded 1 or 2 are required before a finding is called **confirmed**.
- Signals that share a root cause are not independent. Five pressure phrases in one message are one signal, not five.
- A single strong, scheme-specific signal (for example a demand for a seed phrase, or "pay a tax to withdraw your profits") can justify "likely scam" on its own. Generic signals (urgency, a brand name, crypto vocabulary) cannot.
- Statistical AI-image detectors and error-level analysis are graded no better than C3 when used alone. The [InVID-WeVerify deepfake tool's own documentation](https://bellingcat.gitbook.io/toolkit/more/all-tools/invid) warns that its scores are investigative leads, not calibrated probabilities.

---

## 4. Dating an image and finding the original

The aim is a defensible date interval and the best available copy, with the reasoning shown.

### 4.1 How far embedded metadata can be trusted

EXIF, XMP and IPTC fields are plain data. Anyone can edit them with free tools, so they are evidence of what the file claims, not of what happened.

- **Social platforms strip or rewrite metadata.** Facebook, Instagram, X, Reddit and Discord remove EXIF (including GPS) from the copy other users download, and re-encode the image. Signal strips everything. WhatsApp strips metadata in normal photo mode but, according to recent testing, preserves it when a photo is sent as a document. Telegram and email preserve the original file when it is sent as a file. ([Secondary testing, 2026](https://www.sammapix.com/blog/which-apps-strip-photo-metadata); platform behaviour changes without notice, so contributors should verify against fresh test files before encoding any rule.)
- **Consequence.** Stripped metadata is normal for anything that passed through a platform. It is a provenance clue (this copy is not the camera original), never evidence of AI generation or fraud.
- **Trust ranking used by Scam Bunker.** `DateTimeOriginal` and GPS date stamps are high trust if the camera fields are internally consistent; `DateTime`, XMP and PNG `tIME` record the last software write and are medium trust; the filesystem modification time is the download or save time and is low trust. A modification date earlier than the capture date indicates clock error or tampering.
- **Content Credentials (C2PA).** A valid C2PA manifest is cryptographically signed and records the asset's creation and edit actions. It is the strongest provenance evidence a file can carry, graded A when the signature validates. But manifests are commonly stripped in distribution. The C2PA specification therefore defines "soft bindings" (invisible watermarks and perceptual fingerprints) that let a stripped manifest be recovered from a repository ([C2PA implementation guidance](https://spec.c2pa.org/specifications/specifications/2.4/guidance/Guidance.html); [Durable Content Credentials](https://opensource.contentauthenticity.org/docs/durable-cr/)). The absence of a manifest proves nothing. Validate signatures with a C2PA verifier such as [contentcredentials.org/verify](https://contentcredentials.org/verify); string-matching for `c2pa` in the file only shows that a manifest may be present.

### 4.2 Finding the earliest and best copy

1. **Reverse image search across several engines.** Each index is different. Use Google Lens, TinEye, Bing Visual Search and Yandex at minimum, as the [InVID-WeVerify plugin](https://weverify.eu/verification-plugin/) does. TinEye can sort results by oldest. Google's [About this image](https://blog.google/products-and-platforms/products/search/about-this-image-google-search/) reports when Google first indexed the image and similar images, and whether it detects IPTC AI metadata or a SynthID watermark ([Google DSA risk assessment, 2024](https://storage.googleapis.com/transparencyreport/report-downloads/dsa-risk-assessment_2024-8-28_2024-8-28_en_v1.pdf)).
2. **Search variants.** Crop to the subject, flip horizontally (mirrored re-uploads evade matching), and search individual video keyframes rather than platform thumbnails, as the InVID keyframe tool does ([InVID](https://www.invid-project.eu/tools-and-services/invid-verification-plugin/)).
3. **Check archive captures.** For any URL where the image or page appeared, the Wayback Machine CDX API returns every capture with its timestamp. The earliest capture is an upper bound on when the content existed online. Endpoint and parameters are documented in the [CDX server README](https://github.com/internetarchive/wayback/blob/master/wayback-cdx-server/README.md); the service is free and needs no key.
4. **Apply the best-copy heuristic.** Among matching copies, the one closest to the original is usually the one with the highest resolution, the least compression, the widest crop, no overlaid text or watermark from a re-poster, and surviving camera metadata. A copy that is larger and less compressed than the "earliest" one may be closer to the source even if it was indexed later. Treat this as a heuristic for where to look next, not as proof.
5. **Compare copies with perceptual hashes.** Cryptographic hashes (SHA-256) change when an image is re-encoded, so they only find byte-identical copies. Perceptual hashes (aHash, dHash, pHash) survive resizing and recompression. For 64-bit hashes, Neal Krawetz's guidance is: Hamming distance 0 is very likely the same picture, around 5 is probably still similar, and 10 or more is probably a different picture ([Looks Like It, 2011](https://www.hackerfactor.com/blog/index.php?/archives/432-Looks-Like-It.html); [Kind of Like That, 2013](https://www.hackerfactor.com/blog/?/archives/529-Kind-of-Like-That.html)). Scam Bunker treats distance 0 to 4 as a match (strong), 5 to 10 as a candidate for human review (weak), and above 10 as no match. Perceptual hashes produce false positives on simple or uniform images and can be defeated by cropping or flipping.

### 4.3 Chronolocation: dating from the content

When metadata and search fail, the image itself can bound the date:

- **Sun and shadows.** Given a location, the sun's azimuth and elevation are fixed for each moment. Measuring shadow direction and length against an object of known height constrains the time of day and season. [SunCalc](https://www.suncalc.org/) performs this calculation; Bellingcat's [toolkit entry](https://bellingcat.gitbook.io/toolkit/more/all-tools/suncalc) notes that the tool is accurate but measurements taken from images are often not, so results should be expressed as ranges and used to confirm or eliminate candidates.
- **Weather.** If the image shows snow, rain, clear skies or cloud, compare against historical weather for the claimed place and date. [Open-Meteo's historical weather API](https://open-meteo.com/en/docs/historical-weather-api) provides reanalysis data from 1940 onwards, free for non-commercial use without a key.
- **Changing details.** Signage, posters, construction, vehicles, shopfronts and Street View imagery from different years can bound the date, as in Bellingcat's [Prague and Istanbul examples](https://www.bellingcat.com/resources/2023/05/08/chronolocation-determining-when-a-photo-was-taken-using-facebook-google-street-view-and-assorted-tiny-details/).

### 4.4 Reporting the date

State the result as an interval with its basis, for example:

> Earliest possible: 18 October 2016 (banner colours first visible in dated livestreams). Latest possible: 10 November 2016 (banners replaced). Basis: chronolocation against dated reference footage. Grade: B2.

When nothing survives, say so: "No embedded timestamp survived; earliest indexed copy found 3 March 2024 (TinEye). The image existed by that date; it may be older."

---

## 5. Scam typology and indicators

### 5.1 The scale of the problem

- **FBI IC3, 2025 report.** 1,008,597 complaints and $20.877 billion in reported losses. Investment fraud was the largest category at $8.65 billion, followed by business email compromise ($3.05 billion) and tech and customer support scams ($2.13 billion). Losses with a cryptocurrency nexus were $11.37 billion. People over 60 reported $7.75 billion. IC3 logged 22,364 AI-related complaints ($893 million) and 10,516 recovery-scam complaints ($1.4 billion) ([IC3 2025 Annual Report](https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf)). Crypto-kiosk complaints rose to more than 13,400 with over $388 million lost ([IC3 PSA, May 2026](https://www.ic3.gov/PSA/2026/PSA260515-2)).
- **FTC Consumer Sentinel.** Consumers reported about $16 billion lost to fraud in 2025, a record and roughly 25% above 2024. Imposter scams were the most reported category, with $3.5 billion lost ([FTC, June 2026](https://www.ftc.gov/news-events/news/press-releases/2026/06/ftc-data-show-people-reported-losing-3-point-5-billion-imposter-scams-2025)). In 2024, investment scams were the largest loss category at $5.7 billion, and email was the most common first contact ([FTC, March 2025](https://www.ftc.gov/news-events/news/press-releases/2025/03/new-ftc-data-show-big-jump-reported-losses-fraud-125-billion-2024)).
- **Global Anti-Scam Alliance.** In its survey of 46,000 adults in 42 markets, 57% had experienced a scam in the past year and 23% had lost money. Shopping scams were the most common ([GASA and Feedzai, Global State of Scams 2025, October 2025](https://gasa.org/knowledge-base/blog/global-scams-on-the-rise-over-half-of-adults-worldwide-report-scam-encounters)).

These are reported losses; all three bodies note that most fraud goes unreported.

### 5.2 Typology

Scam Bunker classifies schemes into the categories below. Each lists the playbook and the high-precision indicators. Generic pressure, secrecy and brand mentions are supporting signals only.

| Scheme | Playbook | High-precision indicators |
|---|---|---|
| **Investment / pig-butchering** | Unsolicited contact (often a "wrong number" text), weeks of trust-building, move to WhatsApp or Telegram, introduction to a trading app or "mentor", small early withdrawals, then larger deposits, then a "tax" or "fee" to withdraw | "Wrong number" opener (69% of victims in one study: [arXiv 2503.20821](https://arxiv.org/html/2503.20821v1)); guaranteed or fixed daily returns; a new contact directing a crypto-kiosk deposit to an address they supply ([FinCEN FIN-2023-Alert005](https://www.fincen.gov/system/files/shared/FinCEN_Alert_Pig_Butchering_FINAL_508c.pdf)); **pay-to-withdraw** demands. Many operations run from industrial scam compounds using trafficked labour ([FinCEN FIN-2026-Alert005, September 2026](https://www.fincen.gov/system/files/2026-08/FinCEN-Alert-Scam-Centers.pdf)) |
| **Task / gamified job scam** | Unexpected text or WhatsApp job offer with no specifics; "tasks" such as rating products in an app; small payouts; then you must deposit (usually crypto) to finish a set and unlock earnings; group chats of fake successful workers | Jargon such as "product boosting" and "app optimization"; tasks in sets; "double" or "combination" tasks; deposit-to-withdraw ([FTC Data Spotlight, December 2024](https://www.ftc.gov/news-events/data-visualizations/data-spotlight/2024/12/paying-get-paid-gamified-job-scams-drive-record-losses)). Task scams rose from 0.6% of sampled job-scam reports in 2021 to 38.8% in the first half of 2024 |
| **Recovery scam** | Targets people who have already lost money. Fake law firms, fake government agents or "ethical hackers" promise to recover funds for an upfront fee | Knowledge of the victim's past transfers; claims the victim is on a government list of scam victims; referral to a "crypto recovery law firm"; payment in crypto or gift cards ([IC3 PSA, August 2025](https://www.ic3.gov/PSA/2025/PSA250813)) |
| **Deepfake investment ads** | Paid social ads or videos in which a manipulated celebrity, news presenter or official endorses a trading platform | A public figure "revealing" a new platform; returns claims; links to a sign-up funnel ([NY Attorney General, August 2024](https://ag.ny.gov/press-release/2024/investor-alert-attorney-general-james-warns-new-yorkers-investment-scams-using)) |
| **Romance** | Stolen-photo profile, rapid intimacy, a backstory that explains why they cannot meet (military, oil rig, overseas doctor), then a money request | Affection paired with a money request; travel, customs or medical emergency |
| **Phishing and smishing** | A message impersonating a bank, platform, courier or toll agency leads to a credential or payment page | Account-threat wording plus a link; unpaid toll or undeliverable parcel lures; requests for one-time codes; lookalike or very new domains |
| **Crypto wallet drainer** | Fake airdrop, mint or "wallet validation" page asks you to connect a wallet or enter a seed phrase | Requests for a seed or recovery phrase; "connect your wallet to claim" |
| **Tech support** | Pop-up or call claims a virus; asks you to install remote-access software | Named remote-access tools; "call Microsoft support" |
| **Government / business impersonation** | Caller or message claims to be a tax agency, police, bank fraud team | Threat of arrest or account closure plus an unusual payment method |
| **Family-emergency impersonation** | "Hi Mum, this is my new number" followed by an urgent bill | New-number claim from a relative plus a payment request |
| **Advance-fee and prize** | Inheritance, lottery or prize requires a fee to release | Processing, customs or release fee |
| **Marketplace** | Overpayment, fake courier, fake escrow or payment-confirmation links | "Send back the difference", courier collection |
| **Sextortion** | Claims of compromising video or webcam access; demand in crypto | Compromising-material claim plus a crypto demand |

### 5.3 Behavioural and linguistic indicators that generalise

- **The payment rail is the strongest signal.** Gift cards, crypto (especially USDT on Tron), crypto kiosks, wire transfers and "friends and family" payments are chosen because they are hard to reverse. A request for any of these from a new contact is significant on its own.
- **Pay-to-get-paid.** Any demand to pay in order to receive money (earnings, an inheritance, a refund, recovered funds) is diagnostic across typologies.
- **Moving off-platform** to WhatsApp, Telegram or Signal removes the platform's fraud controls.
- **Isolation and secrecy** ("don't tell your bank", "keep this between us").
- **Manufactured urgency** combined with a payment or credential ask. Urgency alone is common in legitimate marketing.
- **Asymmetric knowledge.** A recovery "agent" who knows exactly what you lost obtained that information from the original scammers or from leaked reports.

Rules in `public/scam.js` must be precise. A rule that fires on ordinary marketing ("satisfaction guaranteed", "10x zoom") or on safety advice ("never share your verification code") damages trust in every other result. Each new rule needs test phrases that should and should not match (see `CONTRIBUTING.md`).

---

## 6. Repeat-offender profiling

Scammers rotate stories and accounts but reuse infrastructure: wallets, phone numbers, domains, templates, images. Linking cases through that infrastructure is powerful evidence that a new message belongs to a known campaign. It is also where the risk of harm is highest, so the method is conservative.

### 6.1 What is being profiled

Scam Bunker profiles **campaigns and infrastructure**, recorded as pseudonymous clusters (for example "Cluster 7: USDT-TRC20 wallet + two Telegram handles + domain"). It does not attempt to establish the real-world identity of any person. That is a matter for law enforcement.

### 6.2 Indicator types and their strength

| Indicator | Strength as a link | Caveats |
|---|---|---|
| Crypto wallet address | Strong | Validate the checksum first. Exclude exchange hot wallets and high-volume service addresses, which serve many unrelated users. A wallet links payments, not people |
| Domain (registrable, non-platform) | Strong | Exclude platforms, shorteners, free hosting parents and link-in-bio services. Record RDAP registration date, registrar and nameservers |
| Phone number (E.164-normalised) | Strong to moderate | Numbers are recycled and spoofed. Validate that the string is a phone number and not a date or ID |
| Email address | Strong to moderate | Free-mail addresses are cheap to rotate |
| Exact image hash (SHA-256) | Strong for linking campaigns | The person shown is usually a victim of photo theft, not the scammer (section 7) |
| Perceptual image hash | Moderate (distance 0 to 4) or weak (5 to 10) | False positives on simple images |
| Camera serial number | Strong | Rare in scam images; identifies a device, which may be stolen or second-hand |
| Payment-instruction template, distinctive phrasing | Moderate | Templates are sold and shared between unrelated groups |
| Handle or username | Weak | Common names collide; lookalikes are deliberate. Never sufficient alone |
| Registrar, hosting provider, IP, TLD | Weak | Shared by millions of legitimate sites. Use only in combination |

### 6.3 Linking rules

1. **Entity resolution before linking.** Normalise every indicator (lowercase domains, strip `www.`, E.164 phones, checksum-validated wallets) so that the same entity is recognised in different spellings, and different entities are not merged.
2. **One strong link suggests; two independent strong links support.** A single shared wallet is strong evidence that two messages belong to the same payment operation. Calling two cases "the same actor" needs at least two independent strong links, or one strong link plus corroborating moderate ones.
3. **Weak links never stand alone.** A shared handle or hosting provider alone is not a link.
4. **Time matters.** Phone numbers and domains change hands. Record when each indicator was observed; links across long gaps are weaker.
5. **Show the graph, not just the conclusion.** Reports list each shared indicator, its type and strength, and the cases it connects, so the user can judge the link themselves. This is standard link-analysis practice and it makes errors visible.

### 6.4 External corroboration

Indicators can be checked against public sources, always as an opt-in step because each lookup reveals the indicator to a third party:

- **Blockchain explorers** for wallet activity and first-seen date (mempool.space for Bitcoin, TronGrid for Tron, Blockscout for EVM chains).
- **Scam-report databases**: [Chainabuse](https://docs.trmlabs.com/guides/chainabuse/welcome-to-chainabuse-api) (community reports, free API key required), [ScamSniffer's open phishing-domain list](https://github.com/scamsniffer/scam-database) (GPL-3.0; its address list has not been updated since February 2024).
- **Domain history**: RDAP via [rdap.org](https://about.rdap.org/), certificate transparency via crt.sh, archive captures via the Wayback CDX API.
- **Existing fact-checks** via the Google Fact Check Tools API (free, API key required).

A match in a community database is graded C (fairly reliable) at best, because reports are user-submitted. Chainabuse itself distinguishes reports "checked" by its moderators from unchecked ones.

---

## 7. Ethical and legal guardrails

These rules are binding on contributors and on the agent prompts.

1. **No doxxing.** Scam Bunker does not attempt to identify, locate or publish details of private individuals. It does not run username enumeration across sites, face searches, or people-search lookups. Tools such as [Sherlock](https://github.com/sherlock-project/sherlock) (MIT) and [WhatsMyName](https://github.com/webbreacher/whatsmyname) (CC BY-SA 4.0; archived November 2026) exist for trained investigators who have a lawful purpose. They are out of scope here.
2. **Victims in the evidence are victims.** Profile photos in romance and investment scams are usually stolen from real people. A reused image links scam campaigns; it says nothing bad about the person pictured. Reports must say so, and must never present that person as a suspect.
3. **Presumption of innocence and defamation.** A verdict is an assessment of content, not a finding of guilt about a person. Reports use calibrated language ("this message matches the pattern of a task scam") and avoid asserting that a named individual or business committed a crime. Publishing an unproven accusation against an identifiable person or company can be defamatory in most jurisdictions. The README's warning stands: verify before you accuse anyone publicly.
4. **Data protection.** Case files contain personal data: the victim's messages, and phone numbers, emails and handles that may belong to real people, including innocent ones whose details were spoofed or stolen. Under the GDPR, any processing needs a lawful basis (for most users, legitimate interests in protecting themselves, [Article 6(1)(f)](https://gdpr-info.eu/art-6-gdpr/)); journalistic and research exemptions vary by member state ([Article 85](https://gdpr-info.eu/art-85-gdpr/)). Scam Bunker's design minimises risk: case data stays in the user's browser by default, external lookups are opt-in, the offender index is local and never shared or published, and exports can be redacted.
5. **Minimise what leaves the machine.** Uploading a victim's image to a reverse search engine or an AI provider shares it with that provider. The user is told before any such transfer.
6. **Respect platform terms and access regimes.** Meta shut down CrowdTangle on 14 August 2024 ([Meta Transparency Center](https://transparency.meta.com/researchtools/other-data-catalogue/crowdtangle/)). Its replacement, the Meta Content Library and API, is open only to researchers at academic or non-profit research institutions after an application, with data analysed inside a controlled environment ([Meta, eligibility](https://developers.facebook.com/documentation/meta-content-library/get-access); [Bellingcat toolkit](https://bellingcat.gitbook.io/toolkit/more/all-tools/meta-content-library)); commercial news organisations are excluded ([Tech Policy Press, 2024](https://www.techpolicy.press/researchers-consider-the-impact-of-metas-crowdtangle-shutdown/)). Scam Bunker does not scrape logged-in platform content or work around these restrictions. Users paste the content they can see.
7. **Do not re-victimise.** Advice to victims never suggests paying anyone to recover funds, and flags recovery offers as a known follow-on scam.
8. **Corrections.** Wrong verdicts are corrected openly. Rules that cause false positives are fixed or removed.

---

## 8. Evidence preservation and chain of custody

The [Berkeley Protocol on Digital Open Source Investigations](https://www.ohchr.org/sites/default/files/2024-01/OHCHR_BerkeleyProtocol.pdf) (UN OHCHR and UC Berkeley Human Rights Center) sets the professional standard for collecting and preserving online evidence so that its authenticity and chain of custody can be established. Scam Bunker applies a lightweight version suitable for individuals:

1. **Capture as received.** Keep the original file, not a re-saved copy. Record the source URL, the platform, the account, and the capture time in UTC.
2. **Hash on intake.** Compute SHA-256 for every file at the moment it enters the case (Scam Bunker already does this for images). The hash lets anyone later confirm the file has not changed.
3. **Archive public pages** through the Wayback Machine or archive.today, and record the archive URL alongside the original.
4. **Log every action.** Each analysis step (lookup, reverse search, agent run) is appended to the case log with a timestamp. Hashing each log entry together with the previous entry's hash makes later tampering detectable.
5. **Export with a manifest.** A case export includes the files, their hashes, the log and the report, so a platform trust-and-safety team, a bank or the police receive a verifiable package.
6. **Never alter originals.** Annotated, cropped or enhanced versions are saved as new, separately hashed items that reference the original.

---

## 9. Lineage

Scam Bunker's method is assembled from established practice. Credit where it is due:

| Scam Bunker practice | Source |
|---|---|
| Five-pillar checklist (provenance, source, date, location, motivation); provenance first; capturer versus poster | First Draft, [Verifying Online Information](https://firstdraftnews.org/long-form-article/verifying-online-information/) |
| Stop, investigate the source, find better coverage, trace to the original | Mike Caulfield, [SIFT](https://hapgood.us/2019/06/19/sift-the-four-moves/) |
| Lateral reading | Wineburg and McGrew, Stanford History Education Group ([2019](https://doi.org/10.1177/016146811912101102)) |
| Two-axis grading of source reliability and information credibility | Admiralty Code / NATO AJP-2.1 |
| Fixed-meaning probability language for verdicts | US ODNI, [ICD 203](https://www.dni.gov/files/documents/ICD/ICD-203.pdf) |
| Separating fact from analysis; stating limitations; replicable, archived evidence in attributions | DFRLab, [Foreign Interference Attribution Tracker scoring](https://dfrlab.org/2024/10/23/dfrlab-launches-fiat-2024/) |
| Replicable sourcing, published methodology, open corrections | IFCN, [Code of Principles](https://ifcncodeofprinciples.poynter.org/the-commitments) |
| Two independent sources for the central claim | AFP Fact Check, [How we work](https://factcheck.afp.com/How-we-work) |
| Temporal and spatial context checks; verification as an ethical, not only technical, practice | Al Jazeera's Sanad verification agency ([Al Jazeera Media Institute, 2025](https://institute.aljazeera.net/en/ajr/article/3122); [on open-source investigation](https://institute.aljazeera.net/en/ajr/article/2162)) |
| Chronolocation, sun-and-shadow analysis, date intervals | Bellingcat ([2020](https://www.bellingcat.com/resources/2020/12/03/using-the-sun-and-the-shadows-for-geolocation/), [2023](https://www.bellingcat.com/resources/2023/05/08/chronolocation-determining-when-a-photo-was-taken-using-facebook-google-street-view-and-assorted-tiny-details/), [2024](https://www.bellingcat.com/resources/2024/08/22/shadow-geolocate-geolocation-locate-image-tool-open-source-bellingcat-measure/)); [Bellingcat Online Investigation Toolkit](https://bellingcat.gitbook.io/toolkit) |
| Multi-engine reverse search, keyframes, flip and magnify, metadata viewer, deepfake scores as leads only | InVID, WeVerify and vera.ai [verification plugin](https://weverify.eu/verification-plugin/) (AFP Medialab and partners) |
| Search existing fact-checks first; ClaimReview; image fact-check search; first-indexed dates | Google News Initiative: [Fact Check Tools](https://newsinitiative.withgoogle.com/resources/trainings/google-fact-check-tools/), [About this image](https://blog.google/products-and-platforms/products/search/about-this-image-google-search/), [Pinpoint](https://journaliststudio.google.com/pinpoint/about) for document collections |
| Matching new content against previously checked claims | [Full Fact AI](https://fullfact.org/ai/); [Meedan Check](https://meedan.org/check) claim matching |
| Network-spread analysis of claims (historical reference; Hoaxy retired July 2025, replaced by OSoMeNet) | Indiana University OSoMe ([Bellingcat toolkit note](https://github.com/bellingcat/toolkit/blob/main/gitbook/tools/hoaxy/README.md)) |
| Public-content monitoring (historical reference; shut down 14 August 2024) | CrowdTangle, now Meta Content Library for eligible researchers |
| Provenance credentials, soft bindings | [C2PA](https://spec.c2pa.org/) and the Content Authenticity Initiative |
| Perceptual-hash thresholds | Neal Krawetz, Hacker Factor ([2011](https://www.hackerfactor.com/blog/index.php?/archives/432-Looks-Like-It.html), [2013](https://www.hackerfactor.com/blog/?/archives/529-Kind-of-Like-That.html)) |
| Scam typologies and red flags | FBI IC3, FTC Consumer Sentinel, FinCEN, GASA (sources in section 5) |
| Evidence preservation and chain of custody | [Berkeley Protocol](https://www.ohchr.org/sites/default/files/2024-01/OHCHR_BerkeleyProtocol.pdf) |
| Lead-investigator reasoning: observe, infer, eliminate | Arthur Conan Doyle's Sherlock Holmes, as a framing device only |

---

## 10. Known gaps

Scam Bunker currently implements parts of this methodology. The gaps below are tracked as engineering work:

- Source grading (section 3.1) is not yet recorded per evidence item; the engine's `proof` / `strong` / `weak` labels stand in for it.
- Verdicts do not yet use the estimative-language scale (section 3.2).
- Image matching across cases uses SHA-256 only, so re-encoded copies of the same image are missed (section 4.2).
- Wallet addresses and phone numbers are matched by pattern without checksum or format validation, which can create false links in the offender index (section 6.3).
- There is no append-only case log or hashed export manifest yet (section 8).
- Archive, RDAP, certificate and blockchain lookups are suggested as next steps but not performed (section 6.4).
- Video is not supported.
