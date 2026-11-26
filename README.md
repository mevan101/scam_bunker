# Scam Bunker

**An open-source lab for identifying scams, profiling repeat offenders, and debunking disinformation and manipulated images.**

Drop in an image, a post, a DM or a link. Scam Bunker dates the image, checks whether AI generated it, pulls out the information hidden in the file, takes the links apart, and classifies the scheme. With an API key it also hands the evidence to a team of AI specialists. A lead investigator, modelled on Sherlock Holmes's method, cross-examines their reports and delivers the verdict.

![Scam Bunker agents room](docs/screenshot.png)

## What it does

| Capability | How |
|---|---|
| **Dates an image** | EXIF `DateTimeOriginal`/`Digitized`, XMP create/modify, Photoshop edit history, PNG `tIME`, GPS date stamps. Each is ranked by how far it can be trusted and shown on a timeline |
| **Detects AI generation** | C2PA / Content Credentials, IPTC `DigitalSourceType = trainedAlgorithmicMedia`, embedded Stable Diffusion / ComfyUI prompts, and signatures from Midjourney, DALL·E, Firefly, Imagen, FLUX, Ideogram, Leonardo and others. Generator canvas sizes and noise statistics count only as weak signals |
| **Exposes hidden data** | GPS (with map), camera serial number, owner and author fields, original-document IDs, embedded prompts and comments |
| **Detects manipulation** | Error-level analysis heatmap with hotspot statistics, editing-software traces, impossible timestamp orderings |
| **Finds the original source** | Provenance tab: fetches copies you found by reverse image search, compares them with perceptual hashes (dHash + pHash, crop and mirror aware), ranks which copy is closest to the original, and dates them via EXIF, `Last-Modified` and the Wayback Machine. Flags recycled images (archived years before the claimed event) and forged capture dates. Optional automatic reverse search with `SERPAPI_API_KEY` |
| **Traces where it's been** | Facebook `FBMD` markers, platform resize dimensions (Instagram, Facebook, X, WhatsApp), stripped EXIF, recompression quality |
| **Classifies scams** | Phishing, investment/crypto, romance/pig-butchering, job/task, giveaway, advance-fee, impersonation, tech support, recovery scams, marketplace fraud |
| **Detects coordination** | Copy-paste comment rings, hashtag stuffing, mass-tagging, "my advisor" testimonial networks |
| **Dissects links** | Typosquats, punycode homographs, brand-in-subdomain tricks, `@` tricks, shorteners, high-abuse TLDs, redirect chains, tracking parameters |
| **Profiles repeat offenders** | Every case adds the scammer's wallets, handles, phone numbers, emails, domains, image hashes and camera serials to a local offender index. New cases are matched against it automatically, and reuse is flagged as strong evidence |
| **Investigates a subject** | **Subjects** opens a workspace for one suspected actor. It checks an exact username on about 60 public platforms (found / not found / unknown / blocked, never guessed), reads domain age and registrar from RDAP, and summarises wallets from public ledgers (BTC via mempool.space, TRON via TronGrid, ETH with an Etherscan key). It does no people-search, address or relatives lookups |
| **Builds offender dossiers** | Union-find entity resolution links every saved case that shares a wallet, handle, phone, email, domain, image or camera serial into one actor profile with aliases, identifiers (first and last seen), platforms, linked cases and a timeline. Exports a printable report with a SHA-256 for chain of custody |
| **Extracts entities** | Crypto wallets (with block-explorer links), phone numbers, handles, emails, money amounts |
| **Agent team** | Image Forensics (vision), Fraud Analyst, OSINT & Platform Analyst and Fact Checker run in parallel. The Lead Investigator then reconciles their reports and returns a structured verdict |

Every finding is labelled **proof**, **strong** or **weak**. Missing metadata is never treated as proof of AI.

## Quick start

Requires Node.js 22 or later. There are no dependencies to install.

```bash
git clone https://github.com/mevan101/scam_bunker.git
cd scam_bunker
cp .env.example .env    # optional — works with no keys at all
npm start               # → http://localhost:4400
```

## Running the agent team: no API key required

| Mode | Setup | Cost |
|---|---|---|
| **Investigate with Claude** | None. The button packs the case and all five agent roles into one prompt and opens claude.ai | Your existing Claude plan |
| **Ollama (local)** | Install [Ollama](https://ollama.com), then run `ollama pull gemma3`. Scam Bunker detects it on start | Free, offline, private |
| **OpenAI-compatible API** | `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL` (Groq, OpenRouter, LM Studio and others) | Free tiers available |
| **Anthropic API** | `ANTHROPIC_API_KEY` | Pay per use |

With a vision-capable model (Gemma 3, Llama 3.2 Vision, Qwen-VL, Claude), the Image Forensics agent looks at the image itself as well as the metadata. Text-only models fall back to the metadata automatically. Add `FIRECRAWL_API_KEY` to fetch pages and search the web for corroboration. See `.env.example`.

## Make it your investigator

Open **Investigator profile** and describe who you are, what you investigate and how you want the reasoning done. You can paste in the instructions of an existing assistant, such as your own "Sherlock" bot. Every agent reads this profile before it starts.

## Privacy

Images are parsed **in your browser**. Nothing leaves your machine unless you choose to. With Ollama, nothing ever leaves it. With a cloud provider or the claude.ai handoff, the extracted findings (and, for vision models, a downscaled copy of the image) go to that provider. Case history lives in your browser's localStorage.

## Architecture

```
public/forensics.js   image container parsers (JPEG/PNG/WebP/HEIC), EXIF/XMP/IPTC/C2PA, ELA, AI signatures
public/scam.js        rule engine: scam patterns, link analysis, entity extraction, coordination signals
public/app.js         case orchestration, local reasoning, UI
public/provenance.js  original-source trace: perceptual hashing, copy comparison, provenance verdict, Provenance tab
public/osint.js       subject workspace, username sweep UI, dossiers, export, domain-age observations
public/dossier.js     pure entity-resolution (union-find), risk scoring, SHA-256
server/osint.js       /api/osint/username · /api/osint/domain (RDAP) · /api/osint/wallet
data/sites.json       username-check definitions (CC BY-SA 4.0, see data/README.md)
server.js             zero-dependency Node server: static files + /api/agent, /api/lead, /api/fetch, /api/search
server/provenance.js  /api/provenance/* : SSRF-guarded image fetch, Wayback CDX, page publish date, optional SerpApi reverse search
server/net-guard.js   shared SSRF guard (checks the address actually connected to, on every redirect)
test/run.js           npm test (heuristics)
test/provenance.test.js  npm test (hashing, verdict, Wayback parser, SSRF guard)
```

## Limitations

- Metadata can be forged or stripped. Scam Bunker reports what the file says and how far to trust it.
- Statistical AI detection is unreliable on its own. Scam Bunker treats it as a weak signal by design.
- Facebook, Instagram and LinkedIn block anonymous page fetches. Paste the post text instead.
- Username sweeps show that a profile with that exact name exists, not who runs it. Many big platforms (Instagram, Facebook, X, LinkedIn, TikTok) block anonymous checks, so they are reported as unknown with a link to check by hand.
- This is an aid to judgement and does not replace it. Verify before you accuse anyone publicly.

## Contributing

New scam patterns, generator signatures and platform fingerprints are the most valuable contributions. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Code: [MIT](LICENSE). `data/sites.json` is CC BY-SA 4.0. Its format is modelled on [WhatsMyName](https://github.com/WebBreacher/WhatsMyName) (CC BY-SA 4.0, archived November 2026). See [data/README.md](data/README.md).
