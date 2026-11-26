# data/

## sites.json: username sweep definitions

`POST /api/osint/username` uses these definitions to check whether a profile with an exact username exists on public platforms.

| Field | Meaning |
|---|---|
| `name` | Platform name shown in the UI |
| `category` | Rough grouping (social, payments, marketplace, developer…) |
| `url` | Public profile URL. `{username}` is replaced by the name being checked. The investigator opens this link |
| `probeUrl` | Optional. A public endpoint that answers more reliably than the profile page, such as a public JSON API. Defaults to `url` |
| `checkType` | `status`: HTTP 2xx means found, 404/410 (or `notFoundStatus`) means not found. `message`: the body is searched for `errorMsg` (not found) and `okMsg` (found). `redirect`: a redirect away from the profile means not found |
| `errorMsg` / `okMsg` | Strings for `message` checks. `{username}` is substituted and matching ignores case. If neither string matches, the result is `unknown`, never a guess |
| `absentOkMeansNotFound` | Optional, for `message` checks. A 2xx page without `okMsg` counts as not found (Telegram renders a title block only for real accounts) |
| `notFoundStatus` | Optional extra HTTP codes that mean "no such user" (Bluesky answers 400) |
| `regex` | Optional. Usernames the platform allows. Names that don't fit are reported `not_found` without a request |
| `probe` | `false` means the platform blocks anonymous checks (login walls, HTTP 999, "200 for everything" apps). The result is always `unknown` and the investigator verifies the link by hand |
| `notes` | Caveats for the investigator |

Results are `found`, `not_found`, `unknown` (timeouts, inconclusive pages, platforms that can't be checked) or `blocked` (401/403/429/999, captcha or bot-check pages). A `found` only means that a profile with that name exists. It does not mean that the profile belongs to your subject. Usernames are not unique across platforms.

Only public profile pages and public APIs are queried. Scam Bunker does not use people-search, address, phone-owner or family lookup services.

### Licence and attribution

`sites.json` is licensed under **CC BY-SA 4.0**, separately from the MIT-licensed code. Its format and detection approach are modelled on the [WhatsMyName](https://github.com/WebBreacher/WhatsMyName) project by Micah Hoffman and contributors (CC BY-SA 4.0; the repository was archived in November 2026, and its data remains under that licence). Some detection strings reflect knowledge shared by that project and similar open projects such as Sherlock. If you redistribute or modify this file, keep this notice and share it under the same licence.

Entries use only platform URL patterns and generic page strings. The file holds no personal data, and the tests use invented usernames.

Platforms change their pages often. If a check goes stale, fix the entry and run `npm test`. The schema test catches malformed entries.
