> [!WARNING]
> **WARNING:** This project is under active development. Breaking changes may occur without notice. This plugin may not work as intended.

# OWASP CRS - Plex Hardening Plugin

![Integration tests](https://github.com/davidscarth/plex-hardening-plugin/actions/workflows/integration.yml/badge.svg) ![Plugin lint](https://github.com/davidscarth/plex-hardening-plugin/actions/workflows/lint.yml/badge.svg)

## Description

Hardening for [Plex Media Server](https://www.plex.tv/) behind an OWASP CRS 4.x reverse-proxy WAF (Coraza or ModSecurity). It includes the rule exclusions Plex needs to run behind CRS at all, plus detection rules for CVE-2026-9665x and the Zenofex PoC classes.

The plugin consists of three complementary parts:

- **Rule exclusions** (9530100-9530199) remove the false positives that otherwise break playback, search and thumbnails at paranoia level 1 (PL1). Every exclusion is scoped to one endpoint and one parameter using `ctl:ruleRemoveTargetById`.
- **Detection rules** (9530200-9530299) cover Plex-specific attack classes that pass CRS at PL1: CVE-2026-96651, -96652, -96654, -96655, -96656 and the Zenofex `Plex_Vuln_PoCs` findings.
- **Endpoint denies** (9530300-9530399, on by default) drop owner-only management endpoints that a shared user's client never calls.

The CRS plugin documentation can be found on the [website](https://coreruleset.org/docs/configuring/plugins/).

## Requirements

- OWASP CRS 4.25.1 or newer. Verified against 4.25.x (the CI harness's LTS target) and 4.29.0 (production, at PL1).
- ModSecurity 2.9 / 3.x or Coraza v3 (tested with coraza-caddy)

The endpoint denies assume the owner administers Plex on localhost or the LAN, not through the proxied hostname, and that only shared users' clients arrive through the proxy. Read [Endpoint denies](#endpoint-denies) before deploying anywhere that isn't true, or turn them off (see Configuration).

## How to install the plugin

Please see https://coreruleset.org/docs/concepts/plugins/#how-to-install-a-plugin

Copy the two files into the CRS `plugins/` directory:

```
plugins/plex-hardening-config.conf
plugins/plex-hardening-before.conf
```

## Disabling the plugin

The plugin can be disabled by uncommenting rule 9530010 inside `plugins/plex-hardening-config.conf` or by removing the includes for this plugin.

## Configuration

Defaults are set in the before-file and only apply when the variable is not already set, so uncommenting the corresponding `SecAction` in `plugins/plex-hardening-config.conf` overrides them.

| Variable | Default | Config rule | Effect |
|---|---|---|---|
| `tx.plex-hardening-plugin_endpoint_deny_enabled` | `1` | 9530020 | Drop requests to owner-only endpoints (rules 9530300-9530399). Set to `0` if you administer Plex through the proxy. |
| `tx.plex-hardening-plugin_xfh_tripwire_enabled` | `0` | 9530021 | Log a WARNING-scored event when a client supplies `X-Forwarded-Host`. Only enable at a first-hop proxy. |

Endpoint denies use `drop`. To return a 403 instead, add to an after-file:

```
SecRuleUpdateActionById 9530300-9530399 "deny,status:403"
```

## Rule ID map

The plugin uses the allocated block **9530000-9530999**, laid out per the template convention (000-099 initialisation, 100-499 request rules, 500-999 response rules):

| Range | Purpose |
|---|---|
| `9530010` | Plugin disable switch (commented, in config) |
| `9530020`-`9530021` | Config-knob `SecAction`s (commented, in config) |
| `9530030`-`9530031` | Default-value setters (in before) |
| `9530098` | Endpoint-deny sub-gate (removes 9530300-9530399) |
| `9530099` | Plugin gate (removes 9530100-9530999) |
| `9530100`-`9530150` | Rule exclusions (phase 1) |
| `9530200`-`9530280` | Detection rules (phase 2, anomaly-scored) |
| `9530300`-`9530370` | Owner-only endpoint denies (phase 1, `drop`) |
| `9530500`-`9530999` | Unused, reserved for response rules |

## Rule exclusions

| Rule | Endpoint | Excluded target | From rule(s) | Why |
|---|---|---|---|---|
| 9530100 | `/video\|music/:/transcode/universal/*` | `ARGS:X-Plex-Client-Profile-Extra` | 932235, 932370 | client-profile DSL: `protocol=dash&` matches 932235, `&replace` in `add-limitation(...)` matches 932370 |
| 9530110 | `/photo/:/transcode` | `ARGS:url` | 931100, 934110 | thumbnails are fetched via `url=http://127.0.0.1:32400/...` |
| 9530120 | `/log` | `ARGS:message` | 932370 | client log lines are free text |
| 9530130 | `/media/grabbers/tv.plex.grabbers.hdhomerun/devices` | `ARGS:uri` | 931100 | tuner LAN address (moot while endpoint denies are on) |
| 9530140 | `/library/search`, `/tv.plex.providers.*/library/search` | `ARGS:query` | 932230, 932250 | free-text search matches wrapper + 2-3 char command shape (932230) and direct command shape, including type-ahead fragments like `sh movie` (932250) |
| 9530150 | `/status/sessions/terminate` | `ARGS_NAMES:sessionId` | 943110, 943120 | playback key, not an auth session; endpoint is owner-only |

Tuned at PL1. The before-file lists the PL2 siblings likely to need the same targets.

Test evidence (CRS 4.29.0, 2026-09-26):

- 932230 and 932250 on `/library/search?query=time to go then sh into the box`: fire without the plugin, silent with it. With only 932230 excluded, 932250 fires on the same request; `ls la la` typed into the Plex app crashed the client until 932250 was excluded (observed in production). `Dog & Cat Show`: never fires.
- 943110 / 943120 on `/status/sessions/terminate?sessionId=…`: fires from Plex Web (Referer `app.plex.tv`) and from the mobile app (no Referer); silent with the plugin.

## Detection rules

| Rule | Covers | Trigger |
|---|---|---|
| 9530200 | CVE-2026-96651, Zenofex `metadata-file-read` | `file:` scheme in `ARGS:url` (any endpoint) |
| 9530210 | observed attack signature | traversal inside `url=media://…` on `/library/metadata/{id}/file` (backstop to 930100) |
| 9530220 | Zenofex `profile-extra-rce` | any `*Flags=` setting in `X-Plex-Client-Profile-Extra`, header or query |
| 9530230 | CVE-2026-96655 | any URL scheme or protocol-relative `//host` in transcoder `path=` (clients send library references only) |
| 9530240 | CVE-2026-96652, Zenofex `companion-proxy-ssrf` | `protocol=` on `/player/timeline/subscribe` not `http`/`https` |
| 9530250 | CVE-2026-96656, Zenofex `network-transcoder-preference`, `legacy-pth-rce` | path separator or line break in `Transcoder*Options*` on `/:/prefs`, catching any file-naming x264 option (backstop; endpoint is denied by default) |
| 9530260 | CVE-2026-96654, Zenofex `framework-rpc-injection`, `legacy-pth-rce` | `/`, `\` or `#` in `identifier=` under `/system/agents/` (backstop) |
| 9530270 | reconnaissance signal | client-supplied `X-Forwarded-Host` (opt-in, WARNING score) |
| 9530280 | CVE-2026-96651, Zenofex `metadata-file-read` (allowlist form) | `url=` on `/library/metadata/{id}/file` not a `media://`, `metadata://` or `upload://` reference |

9530220 tracks known dangerous settings by shape (`*Flags=`); it is defence-in-depth on a patched CVE, not a substitute for the patch, because Plex's fix is an allowlist whose full contents are not observable from outside.

Detection rules run in phase 2, score CRITICAL into `tx.inbound_anomaly_score_pl1` (one hit meets the default threshold) and respect `SecDefaultAction` through `block`. They are phase 2 even where phase 1 would do, because rules in a before-file run ahead of CRS 901 initialisation in phase 1, where `tx.critical_anomaly_score` is not yet defined, so any score referenced there is empty.

Rules 9530200-9530270 are converted from rules that ran in production behind Coraza during and after a 2026 shared-user token compromise, with endpoint scope and parameter shapes taken from the Zenofex findings and Plex's fix strings. One rule is additional and untested against traffic: **9530280**, the reference-scheme allowlist. `media://` is what clients send on this endpoint; `metadata://` and `upload://` are included defensively. Trim if your traffic shows only `media://`.

## Endpoint denies

Direct conversion of a reverse-proxy abort list. Everything else is forwarded for the shared-client API (browsing, playback, search, sync).

| Rule | Paths | Why |
|---|---|---|
| 9530300 | `/` with `Accept: text/html` | Plex 302s browsers to `/web/index.html`; API clients never send `text/html` |
| 9530310 | `/web` | Plex Web UI bundle (XSS surface, plex.tv auth redirect) |
| 9530320 | `/myplex`, `/connections` | return the owner token (CVE-2025-69414/69415 class), blocks `/myplex/account` escalation chain |
| 9530330 | `/:/prefs`, `/updater`, `/transcode/sessions`, `/butler`, `/system/notification`, `/diagnostics`, `/services/browse`, `/log/networked`, `/activities`, `/media/grabbers`, `/servers` | server management |
| 9530340 | `/system/agents` | answers **without a token**; Fix Match search + art fetch |
| 9530350 | `/system/proxy` | server-side URL fetch (CVE-2014-9304 SSRF) |
| 9530360 | any path, `X-Plex-Url` header present | the CVE-2014-9304 proxy's target-URL header; no current client sends it, so its presence is a probe |
| 9530370 | any path containing `..` or `\`, raw or encoded (query string excluded) | no legitimate Plex path has either; closes `/library/../web`-style bypasses for every deny above |

Deliberately **not** denied, because Plex enforces owner-only or per-account access itself. Verified 2026-09-26 by calling each on localhost with a managed-user token (`admin=0`, one library granted) in the same session as the owner:

| Path | Shared token | Owner use |
|---|---|---|
| `/status/sessions` | 403 | Now Playing / History |
| `/accounts` | 403 | History detail (user name) |
| `/devices` | 403 | History detail (device name) |
| `/statistics/bandwidth` | 200, empty¹ | Dashboard; per-account filtered |

¹ Empty for the managed user while the owner token, at the same moment, returned data (bandwidth rows; a running library scan). Plex filters these per account.

The owner's mobile app Server section requests `/:/prefs`, `/updater/status` and `/activities` but it appears fully functional without them.

The path denies match `REQUEST_URI` with `t:urlDecodeUni,t:lowercase`, so anchors tolerate a trailing `?query` and `/WEB` is caught (Plex on Windows serves `/web` from a case-insensitive filesystem). They do not use a path-normalising transform: on a Windows Coraza build those emit backslashes and a forward-slash regex silently fails open. Traversal is handled by 9530370 instead, which drops any request whose path carries `..` or a backslash, raw or percent-encoded (the query string is not inspected, since search text and log messages legitimately contain both). Denies are phase 1 and issue `drop` directly rather than scoring, which the plugin guidelines permit.

## Interactions

- **Exclusions vs. detection:** 9530100 removes `ARGS:X-Plex-Client-Profile-Extra` from 932235 only and 9530110 removes `ARGS:url` from 931100/934110 only. Detection rules 9530200 and 9530220 still inspect those targets.
- **Coraza:** all regexes are RE2-compatible (no lookaround or backreferences); no persistent collections are used. Do not add a path-normalising transform to the endpoint denies (see Endpoint denies). Check how your Coraza connector maps `drop`, or use the `SecRuleUpdateActionById` line above.
- **Tags:** the plugin's rules carry `plex-hardening-plugin` (and `plex-hardening-plugin/endpoint-deny` on the denies), not `OWASP_CRS`. A tag-wide exclusion such as `ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS` therefore leaves this plugin's rules active on that path - intended, so a broad CRS exclusion on an unrelated application does not silently switch off Plex protection. To exclude the plugin's rules on a path, target the plugin's own tag or its ID range: `ctl:ruleRemoveByTag=plex-hardening-plugin` or `ctl:ruleRemoveById=9530200-9530299`.

## Testing

Tests use the go-ftw YAML format under `tests/regression/plex-hardening-plugin/`, one file per rule, and run through the shared [crs-plugin-test-action](https://github.com/coreruleset/crs-plugin-test-action) workflows (`.github/workflows/integration.yml`, `lint.yml`). That pipeline runs Apache + ModSecurity 2 and nginx + ModSecurity 3 in `DetectionOnly` at paranoia level 4 against CRS `main` and the current LTS, so assertions are on logged rule IDs; `drop` is never exercised there. Coraza is not part of the shared pipeline.

Every exclusion test's payload was checked against the CRS 4.29.0 regex of the rule it targets, so the `no_expect_ids` assertion only holds because the exclusion is in place, and each file also has a scope-control case on an unrelated path asserting the CRS rule still fires. 9530130's exclusion is exercised in the harness (DetectionOnly does not drop). In production with endpoint denies on, `/media/grabbers` is dropped in phase 1 before 931100 runs, so the exclusion is moot there.

## Reporting false positives

If you find a false positive that this plugin does not cover then please open a new issue or pull request, including:

1. CRS version
2. ModSecurity / Coraza version
3. WAF audit or error log lines for the request
4. The Plex client and action that caused it

## License

Apache-2.0
