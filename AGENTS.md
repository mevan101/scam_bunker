# Working on Scam Bunker (for AI agents and human contributors)

Several agents (Claude Code, Devin) and humans work on this repo in parallel. These rules keep that safe.

**Start here:** read [docs/MISSION.md](docs/MISSION.md) (why this exists and who it serves) and [docs/PRODUCT.md](docs/PRODUCT.md) (Simple vs Investigator mode, the tour, input types, module contracts, definition of done). Every change should make Scam Bunker simpler and more useful for an ordinary person checking something suspicious, without losing depth for investigators.

## Ground rules
- **Zero npm dependencies.** Node >= 22, vanilla JS frontend. `npm start` must work on a fresh clone.
- **One branch + one pull request per task.** Branch names: `<agent>/<short-topic>` (e.g. `devin/event-overlap`). Never push to `main` directly.
- **Stay in your lane.** New features go in their own files (`public/<feature>.js`, `server/<feature>.js`) and hook in through the module API instead of editing shared code:
  - `window.ScamBunker` exposes `current`, `esc`, `post`, `toast`, `panel`, `showTab`, `store`, `renderAll`, `server`.
  - `document` events: `sb:case` (after local analysis, `detail` = case) and `sb:case-complete`.
  - **Static mode (GitHub Pages):** there is no `/api` there. `ScamBunker.isStatic()` is true and `sb:ready` fires with `{static:true}`. Every module that calls `/api/*` must check it and either use a browser-direct fallback (only CORS-enabled, no-key public APIs) or show a clear "needs the local app" state. Never throw or leave a spinner running.
  - Agent briefs and the handoff prompt live in `public/shared/prompt.js`, which both the server and the browser load. Edit them there.
  - Keep edits to `public/app.js`, `public/index.html`, `server.js` minimal (a script tag, a route line, a tab button).
- **Design system.** Use the existing CSS custom properties and component classes (see `docs/DESIGN.md` once merged). Do not restyle globally.
- **Security.** Any server-side fetch of a user-supplied URL must go through `assertPublicUrl` (SSRF guard), re-checked on every redirect. Escape all user/remote content with `esc()` before inserting HTML. Only render `http(s)` links.
- **Accessibility.** WCAG 2.2 AA: labels, keyboard access, visible focus, 4.5:1 contrast in both themes.
- **Tests.** Add zero-dependency tests under `test/` and make sure `npm test` passes. Verify UI changes in a real browser (Playwright) before opening a PR.

## Investigation ethics (non-negotiable)
- **No real people's personal data in the repo** — not in code, tests, fixtures, docs, screenshots or issues. Use invented examples.
- Only public profiles and public ledgers. No people-search, home addresses, family, or private-account scraping.
- Findings are **leads, not verdicts**. Every claim must be labelled verified / contradicted by its own source / unverifiable, and motive must never be inferred.
- Every signal carries an honest strength (proof / strong / moderate / weak). False accusations cause real harm.

## Methodology
See `docs/METHODOLOGY.md` for the verification workflow, source grading and image-dating method the product implements.
