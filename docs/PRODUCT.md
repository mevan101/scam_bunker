# Product spec: simple first, deep when needed

Read [MISSION.md](MISSION.md) first. This document turns it into concrete product decisions for everyone building Scam Bunker (Claude Code agents, Devin sessions, human contributors).

## The problem with the current UI

The engines are strong but the experience is built for analysts: a long form beside a dense report, 13 report sections, jargon ("Local forensics", "Agents via claude.ai", "B3", "Provenance", "Custody log"), and expert tools at the same level as the answer. A first-time visitor does not know where to start or what the result means.

## Two modes

| | **Simple** (default) | **Investigator** |
|---|---|---|
| For | Anyone checking one suspicious thing | Fact-checkers, journalists, moderators |
| Shows | One input → one plain answer → what to do → how to check it yourself | Everything: all report sections, Subjects, Events, Checklist, Custody log, grading codes |
| Language | Plain words, no codes or acronyms | Professional terms allowed, with tooltips |

A clearly labelled switch in the top bar changes mode and is remembered (localStorage, try/catch). Every Simple result has an "Open full investigation" link that switches to Investigator mode on the same case.

## Simple mode, screen by screen

**1. Home: one smart input.** A single large box: "Paste a message, link, phone number or email, or drop a screenshot, photo, video or QR code." One button: **Check it**. Under it: example chips ("Bank SMS", "Job offer", "Crypto DM", "Viral photo", "QR code"), and one line: "Free. Private: checked on your device." No other form fields: the platform is auto-detected and can be corrected after the result.

The input auto-detects what was given: URL, phone number, email address, raw email headers, plain text, image (photo or screenshot), video, QR code. Each type goes to the right engine through the intake adapter contract below.

**2. Result: answer first.**
- **Verdict card:** a large plain sentence ("This is very likely a scam", "We found warning signs", "This image is older than the post claims", "No warning signs found, but stay careful"), colour plus icon plus words (never colour alone), and the risk as a simple Low / Medium / High / Very high label (the number stays available on hover and in Investigator mode).
- **Why we think so:** 3–5 plain-language reasons, strongest first, each quoting the exact words or showing the exact detail it is about. Example: "It asks you to pay a 'training fee' before you start a job. Real employers never do this."
- **What to do now:** a short checklist tailored to the scam type (don't pay, don't click, block and report on that platform, call your bank's real number, report in your country), with links.
- **Check it yourself:** one-click actions that teach: reverse image search buttons, "look up this domain's age", "search this phone number", "see existing fact-checks for this claim".
- **Hidden in this file** (only when relevant): "This photo still contains the location where it was taken", in plain words.
- Footer: "Open full investigation" · "Copy a summary to share" · "Ask Claude about this" (the handoff).

**3. Empty and error states** say what happened and what to do, never a stack trace or a stuck spinner.

## Investigator mode

The current report, reorganised: Summary · Evidence (links, entities, claims) · Media (image, video, provenance) · Timeline · Tools (Corroborate, Events, Checklist, Custody log) · Subjects (top bar). Grading codes, estimative language and the risk number are shown here.

## The tour

On the first visit (and from "Take the tour" in the top bar at any time), a short, skippable, keyboard-accessible tour:
1. "Paste anything suspicious here" (points at the input).
2. "Or try an example" (points at the chips, loads one when clicked).
3. "Here is the answer and why" (points at the verdict and reasons).
4. "Here is what to do now" (points at the checklist).
5. "Need more? Switch to Investigator mode" (points at the switch).
Remembered with localStorage (try/catch); never blocks the page; respects reduced motion.

## Inputs to support (priority order)

1. Text (messages, posts, emails, SMS), in English, Bangla and Banglish.
2. Links, including shorteners and redirects (server mode), structure and lookalike checks everywhere.
3. **Screenshots**: most scams arrive as screenshots. Extract the text on device (OCR, English + Bangla) and analyse it like pasted text; keep the image forensics.
4. **QR codes**: decode on device (BarcodeDetector where available, small fallback), then check the link inside.
5. Photos and video: dating, provenance, AI signals (existing).
6. Phone numbers and email addresses: format, country, known patterns, search links.
7. Raw email headers: sender spoofing (From vs Return-Path vs Reply-To), SPF/DKIM/DMARC results, received hops.

## Module contracts (for Devin and other contributors)

Keep using `window.ScamBunker`, the `sb:case` / `sb:case-complete` / `sb:ready` events and `ScamBunker.isStatic()` (see AGENTS.md). The Simple-mode shell adds:

- `ScamBunker.registerIntake({ id, label, detect(input) -> confidence 0..1, async extract(input) -> { text?, url?, notes?: string[], attachments? } })`: input adapters (OCR, QR, email headers, phone). `input` is `{ text, file }`. The shell runs the best-matching adapter, merges its output into the case, then runs the normal engines.
- `ScamBunker.addReasons(case, [{ text, weight, source }])` and `ScamBunker.addActions(case, [{ text, href? }])`: modules contribute plain-language reasons and to-do items to the Simple result.
- `ScamBunker.mode()` returns `'simple' | 'investigator'`; `sb:mode` fires on change. Investigator-only UI must hide in Simple mode.

## Lessons we take from the field

| Organisation / tool | What we adopt |
|---|---|
| **InVID / WeVerify plugin** (AFP, DW, CERTH and partners) | Small single-purpose tools (keyframes, magnifier, image flip, multi-engine reverse search) with a short tutorial beside each; video keyframe search |
| **DW Innovation** (KID verification project, KID Toolbox "Learn to verify", vera.ai) | Teach while checking; plain explanations of types of false content; responsible AI-detection claims |
| **Google News Initiative** (Fact Check Explorer, ClaimReview, "About this image") | Reuse existing fact-checks first; show an image's earliest known appearance and context |
| **CrowdTangle** (Meta, shut down Aug 2024) | Spread and coordination signals matter, but build on open, durable data; never depend on one platform's API |
| **Al Jazeera Sanad** and newsroom verification desks | A disciplined workflow: preserve, source, date, locate, corroborate, then publish with corrections |
| **First Draft / Bellingcat** | Provenance, source, date, location, motivation; chronolocation from shadows and weather |
| **IFCN Code of Principles** | Transparency of sources and methods, open corrections, non-partisanship |

## Definition of done for any user-facing change

- A first-time visitor understands it without reading docs (test it on a phone at 390px).
- Plain language in Simple mode; no codes or acronyms without explanation.
- Works in server mode and static mode (GitHub Pages); no errors, no stuck spinners.
- WCAG 2.2 AA in light and dark; keyboard and screen reader usable.
- Tests added; `npm test` passes; verified in a real browser.
