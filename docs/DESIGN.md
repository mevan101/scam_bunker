# Scam Bunker design system

The UI should read like a structured investigation document in a professional tool. People use it to make decisions that affect others, so it should look calm, precise and trustworthy, not "magical". Everything lives in `public/app.css`, and there are no dependencies besides Google Fonts.

## Principles

- **Paper and ink.** Neutral surfaces, near-black text, hairline borders, 4–6px radii and almost no shadow. Group content with rules and whitespace before reaching for a box.
- **One accent, used only for interaction.** Blue (`--accent`) marks links, the primary action, the selected tab and focus. It never decorates.
- **Colour means severity.** Red, amber, green and violet appear only for verdicts, risk and evidence weight, and always alongside a label or shape. Colour is never the only cue.
- **Data looks like data.** Use mono for evidence (quotes, hosts, hashes, timestamps) and tabular numbers for scores, counts and dates.

## Tokens (`:root`)

Light is the primary theme. Dark is defined twice: under `@media (prefers-color-scheme: dark)` guarded by `:root:not([data-theme="light"])`, and under `:root[data-theme="dark"]`. The top-bar toggle sets `data-theme` on `<html>` (or removes it for "system") and persists the choice in `localStorage['scambunker.theme']`.

| Group | Tokens |
|---|---|
| Neutrals | `--bg` canvas · `--surface` sheets/inputs · `--subtle` wells, table heads · `--subtle-2` pressed/selected · `--line` hairline · `--line-2` control border · `--ink` · `--ink-2` · `--muted` (≥ 4.5:1 on every surface) · `--on-ink` |
| Accent | `--accent` `--accent-hover` `--accent-soft` `--on-accent` `--focus`; primary button fill `--btn` `--btn-hover` `--on-btn` |
| Semantic | `--red` `--amber` `--green` `--blue` `--violet`, each with `-soft` (tinted background; the base colour stays ≥ 4.5:1 on it), plus `--on-red` |
| Legacy aliases | `--bg-2`, `--surface-2` (= `--subtle`), `--serif` (= `--sans`) |
| Type | `--sans` IBM Plex Sans · `--mono` IBM Plex Mono |
| Space | `--s1` 4 · `--s2` 8 · `--s3` 12 · `--s4` 16 · `--s5` 24 · `--s6` 32 · `--s7` 48 |
| Shape | `--radius` 6px · `--radius-sm` 4px · `--shadow` (none in dark) · `--shadow-overlay` (dialogs, toast) |

Verdict colour is passed to `#verdict` as `--v` (see `VERDICT_COLOR` in `app.js`). It drives the verdict marker and the risk meter fill.

## Type scale

`--fs-xs` 11 · `--fs-sm` 12 · `--fs-md` 13 · `--fs-base` 14 (body) · `--fs-lg` 16 · `--fs-xl` 20 · `--fs-2xl` 24 (verdict) · `--fs-3xl` 28 (risk number). Weights are 400, 500 and 600. Small uppercase labels (11px, 600, +0.06em) are reserved for section labels such as "New case", "Samples" and "Case report".

## Layout

- **Top bar** (52px, sticky on desktop): brand, connection status (dot + text), actions, theme toggle.
- **Shell:** a 384px intake sidebar on the left and the report sheet on the right (max 1160px). Below 1020px they stack. Below 640px every multi-column component collapses to one column, with 16px gutters.
- **Report sheet (`#report`):** a toolbar (`.report-bar`), then the verdict summary (`.verdict`: source line, verdict, one-line finding, category · confidence · platform, risk meter), then tabs, then the panel.

## Components

| Class | Use |
|---|---|
| `.card` | Bordered surface with a 6px radius. Inside `#report`, `.verdict.card` and `.panel.card` lose their chrome so the report reads as one document. |
| `.panel` | Tab panel body (24px padding). `section + section` gets 32px; `h3` is the section heading. |
| `.box` | Bordered stat/summary cell: `.k` label, `.big` value, `p` explanation. |
| `.grid2` | Two equal columns (one on mobile). |
| `.list` | Bordered list with hairline separators and square bullets. Add `.red` for exposures and anomalies. |
| `.kv` | Two-column key/value table. Keys in mono on `--subtle`. |
| `.tag` | Small neutral label (platform, entity type). In the verdict block, tags render as a plain `·`-separated meta line. |
| `.w.proof / .strong / .moderate / .weak / .ok` | Evidence weight: an uppercase label, a 4-step signal-bar glyph (proof 4, strong 3, moderate 2, weak 1; `ok` is a check) and colour. `proof` is solid red; the others are tinted. Also used for link risk and "N× before". |
| `.obs` / `.ob` (`.ob-head`) | Evidence table: weight, observation (mono), inference. The `.k` labels are visually hidden on desktop and shown on mobile, where rows stack. |
| `.linkcard` | Bordered block for a URL or identifier: `.top` row (code + tags/weight) and a `ul` of findings. Inside `.offender` it gets a red left rule. |
| `.callout` | Neutral note on `--subtle`. `.callout.handoff` is the accent-tinted call to action. |
| `.advice` | Guidance for the potential victim: `--subtle` with a 3px ink left rule. |
| `.ghost` | Secondary button, 32px. |
| `.primary` | Primary button, 40px, full width (`.sm` = auto width, 32px). One per view. |
| `.chip` | Small rectangular button for samples and quick filters. |
| `.agent` (`.lead`) | Agent report: `.av` glyph, `h3` name, `.role`, `.st` status (`run`/`done`/`err`/`off`) and a focusable scrollable `.body`. `.lead` spans the row and has an ink top rule. |
| `.tl` / `.tl-item` (`.low`) | Timeline as a dated log: mono timestamp column, event, then source · trust. |
| `.hit` | Matched language pattern: amber left rule, label, category · weight, mono excerpt with `<mark>`. |
| `.meter` | 6px bar; set `--v` for the fill colour and an inline `width` on the inner `<i>`. |
| `.rev` | Grid of external-tool links. |
| `.ent` | Grid of `.box` entity groups (wallets, handles, phones…). |
| `.empty` | One-line muted empty message inside a panel. |
| `.drawer` | Modal `<dialog>` with header, body and footer. |

The risk meter (`#gauge`) is a segmented scale. Its bands (Low 0–24, Elevated 25–49, High 50–69, Critical 70–100) match the rule engine's verdict thresholds. `app.js` fills it by setting `stroke-dashoffset` on `#g-fg`, a 314-unit line.

## Accessibility

- Text contrast is ≥ 4.5:1 in both themes, checked with axe-core: zero violations across all tabs, samples, an image case and both dialogs, at 1440 and 390, under system and forced themes.
- Every interactive element gets a 2px `--focus` outline on `:focus-visible`.
- `prefers-reduced-motion` disables all animation and transitions.
- `forced-colors` keeps badge outlines and the meter visible.
- Tabs follow the ARIA tab pattern (roving `tabindex`, arrow keys, Home/End) in `index.html` and `app.js`.
