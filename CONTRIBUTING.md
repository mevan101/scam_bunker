# Contributing to Deduce

Thanks for helping people spot deception.

## Most wanted
- **Scam patterns.** Add a rule to `RULES` in `public/scam.js` (category, weight, regex, plain-English label), then add a test case to `test/run.js`.
- **AI generator signatures.** Add to `AI_SIGNATURES` in `public/forensics.js`. Mark a signature `proof` only if it is an explicit declaration, such as C2PA or IPTC source type.
- **Platform fingerprints.** Add resize dimensions, IPTC markers or filename conventions for each platform.
- **Translations** of the rules for non-English scams.

## Rules
1. Keep it dependency-free and runnable with `node server.js`.
2. Every signal needs an honest strength. False accusations cause real harm.
3. Never commit real victims' personal data in examples or tests. Redact it.
4. Run `npm test` before opening a PR.
