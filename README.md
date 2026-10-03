# OWASP CRS - Plex Hardening Plugin

![Integration tests](https://github.com/davidscarth/plex-hardening-plugin/actions/workflows/integration.yml/badge.svg) ![Plugin lint](https://github.com/davidscarth/plex-hardening-plugin/actions/workflows/lint.yml/badge.svg)

## Description

Hardening for [Plex Media Server](https://www.plex.tv/) behind an OWASP CRS 4.x reverse-proxy WAF (Coraza or ModSecurity): detection rules for CVE-2026-9665x and the Zenofex PoC classes, plus owner-only endpoint denies.

**Requires [plex-rule-exclusions-plugin](https://github.com/davidscarth/plex-rule-exclusions-plugin).** Without it, CRS at paranoia level 1 breaks Plex playback and search before any rule here matters. Install both.

The plugin has two parts:

- **Detection rules** (9531200-9531399) cover Plex-specific attack classes that pass CRS at PL1: CVE-2026-96651, -96652, -96654, -96655, -96656 and the Zenofex `Plex_Vuln_PoCs` findings.
- **Endpoint denies** (9531400-9531499, on by default) drop owner-only management operations that a shared user's client never performs. Three endpoints that clients do poll routinely are split by method: `GET /activities`, `GET /updater/status` and `GET /transcode/sessions/{id}` are allowed and every verb other than `GET`, `HEAD` or `OPTIONS` on those paths is denied; `/updater/check|apply` and the bare `/transcode/sessions` list are denied outright.

The CRS plugin documentation can be found on the [website](https://coreruleset.org/docs/4-about-plugins/4-1-plugins/).

## Requirements

- OWASP CRS 4.25.2 or newer. Verified against 4.25.x (the CI harness's LTS target) and 4.30.0 (production, at PL1).
- ModSecurity 2.9 / 3.x or Coraza v3 (tested with coraza-caddy)

The endpoint denies assume the owner administers Plex on localhost or the LAN. This includes Plex Web at app.plex.tv: off the LAN it connects through the proxied hostname and is treated like any other remote client. Dashboard, Now Playing, History and stopping playback still work there (Plex gates those per account itself); server settings, updates and the other management operations in the deny table do not, by design. Read [Endpoint denies](#endpoint-denies) before deploying anywhere that isn't acceptable, or turn them off (see Configuration).

## How to install the plugin

Please see https://coreruleset.org/docs/4-about-plugins/4-1-plugins/#how-to-install-a-plugin

Install plex-rule-exclusions-plugin first, then copy the two files into the CRS `plugins/` directory:

```
plugins/plex-hardening-config.conf
plugins/plex-hardening-before.conf
```

## Disabling the plugin

The plugin can be disabled by uncommenting rule 9531010 inside `plugins/plex-hardening-config.conf` or by removing the includes for this plugin.

## Deployment prerequisite

Plex clients use `PUT` and `DELETE` (`PUT /:/prefs`, `DELETE /activities/{id}`,
`PUT /log`). CRS 911100 allows only `GET HEAD POST OPTIONS` by default, so a
Plex deployment must either extend the list in `crs-setup.conf` (rule 900200):

```
SecAction "id:900200,phase:1,pass,t:none,nolog,setvar:'tx.allowed_methods=GET HEAD POST PUT DELETE OPTIONS'"
```

or not load `REQUEST-911-METHOD-ENFORCEMENT.conf` at all and enforce method
policy in front of the WAF (for example a Caddy `method` matcher with `abort`).
The CI harness keeps CRS's default method list; tests that send `PUT` or `DELETE` assert only this plugin's rule IDs, so 911100 firing alongside does not affect them.

## Configuration

Defaults are set in the before-file and only apply when the variable is not already set, so uncommenting the corresponding `SecAction` in `plugins/plex-hardening-config.conf` overrides them.

| Variable | Default | Config rule | Effect |
|---|---|---|---|
| `tx.plex-hardening-plugin_endpoint_deny_enabled` | `1` | 9531020 | Drop requests to owner-only endpoints (rules 9531400-9531499). Set to `0` if you administer Plex through the proxy. |
| `tx.plex-hardening-plugin_xfh_tripwire_enabled` | `0` | 9531021 | Log a WARNING-scored event when a client supplies `X-Forwarded-Host`. Only enable at a first-hop proxy. |
| `tx.plex-hardening-plugin_hosts` | unset | 9531023 | Scope the plugin to listed hosts and/or ports. Space-separated, slash-wrapped entries: `/name/` (any port), `/name:port/`, `/ip:port/`, or `/:port/` (any name on that port). Unset applies the plugin to every request. |
| trusted source allowlist | commented | 9531022 | A commented `@ipMatch` rule in the config file; uncomment and list the networks you administer from to exempt them from the endpoint denies (detection rules still apply). `@ipMatch` cannot read a variable, so this is edited in place rather than set as `tx.`. |

### Scoping to Plex on a shared WAF

The plugin sees every request the WAF sees. On a WAF dedicated to Plex that is correct and `tx.plex-hardening-plugin_hosts` stays unset, whether Plex is reached by domain, dynamic-DNS name or bare IP. On a WAF pipeline shared with other applications, leaving it unset applies the endpoint denies to the neighbors too (their `/` and `/web/` get dropped), so set it to the least specific entry that tells Plex apart: `/plex.example.com/` when apps differ by hostname; `/plex.example.com:8443/` or `/203.0.113.5:8443/` when they differ by port on a fixed name or address; `/:8443/` when they differ by port on a dynamic IP with no names. Names match case-insensitively; IPv6 literals keep their brackets, `/[2001:db8::1]/`. A wrong value silently disables the plugin for Plex, which is why unset is the default: its failure mode is loud (denies on the wrong hostname in the log).

Endpoint denies use `drop`. To return a 403 instead, add to an after-file:

```
SecRuleUpdateActionById 9531400-9531499 "deny,status:403"
```

## Rule ID map

The plugin uses the allocated block **9531000-9531999**, laid out per convention (000-099 initialization, 100-499 request rules, 500-999 response rules):

| Range | Purpose |
|---|---|
| `9531010` | Plugin disable switch (commented, in config) |
| `9531020`-`9531021`, `9531023` | Config-knob `SecAction`s (commented, in config) |
| `9531022` | Trusted-source allowlist rule (commented, in config) |
| `9531030`-`9531031` | Default-value setters (in before) |
| `9531089`-`9531093`, `9531096` | Scope flag default, tokens, flag, and gate (in before) |
| `9531098` | Endpoint-deny sub-gate (removes 9531400-9531499) |
| `9531099` | Plugin gate (removes 9531100-9531999) |
| `9531100`-`9531199` | Unassigned. The companion plex-rule-exclusions-plugin keeps its exclusions at 9530100-9530199, so the two plugins merge by suffix |
| `9531200`-`9531399` | Detection rules (phase 2, anomaly-scored); 9531200-9531290 in use |
| `9531400`-`9531499` | Owner-only endpoint denies (phase 1, `drop`); 9531400-9531490 in use |
| `9531500`-`9531999` | Unused, reserved for response rules |

## Detection rules

| Rule | Covers | Trigger |
|---|---|---|
| 9531200 | CVE-2026-96651, Zenofex `metadata-file-read` | `file:` scheme in `ARGS:url` (any endpoint) |
| 9531210 | observed attack signature | traversal in `url=` on `/library/metadata/{id}/file` (backstop to 930100) |
| 9531220 | Zenofex `profile-extra-rce` | any `*Flags=` setting in `X-Plex-Client-Profile-Extra`, header or query |
| 9531230 | CVE-2026-96655 | any `scheme:/` or `//host` in transcoder `path=` (clients send library references only) |
| 9531240 | CVE-2026-96652, Zenofex `companion-proxy-ssrf` | `protocol=` on `/player/timeline/subscribe` not `http`/`https` |
| 9531250 | CVE-2026-96656, Zenofex `network-transcoder-preference`, `legacy-pth-rce` | path separator or line break in `Transcoder*Options` or `Transcoder*OptionsOverride` on `/:/prefs`, catching any file-naming x264 option (backstop; endpoint is denied by default) |
| 9531260 | CVE-2026-96654, Zenofex `framework-rpc-injection`, `legacy-pth-rce` | `/`, `\` or `#` in `identifier=` under `/system/agents/` (backstop) |
| 9531270 | reconnaissance signal | client-supplied `X-Forwarded-Host` (opt-in, WARNING score) |
| 9531280 | CVE-2026-96651, Zenofex `metadata-file-read` (allowlist form) | `url=` on `/library/metadata/{id}/file` not a `media://`, `metadata://` or `upload://` reference |
| 9531290 | any file read of Plex credentials | `Preferences.xml` (holds `PlexOnlineToken`) or `.LocalAdminToken` in the path or any parameter, however the read is delivered |

9531220 tracks known dangerous settings by shape (`*Flags=`); it is defense-in-depth on a patched CVE, not a substitute for the patch, because Plex's fix is an allowlist whose full contents are not observable from outside.

Detection rules run in phase 2, score CRITICAL (9531270: WARNING) into `tx.inbound_anomaly_score_pl1` (one hit meets the default threshold) and respect `SecDefaultAction` through `block`. They are phase 2 even where phase 1 would do, because rules in a before-file run ahead of CRS 901 initialization in phase 1, where `tx.critical_anomaly_score` is not yet defined, so any score referenced there is empty.

The endpoint denies ran as reverse-proxy rules before being converted. 9531200 and 9531220 ran in production as standalone rules during and after a 2026 shared-user token compromise. The remaining detection rules (9531230-9531280) were written from the Zenofex findings and Plex's fix strings and confirmed to fire on their target shapes, but have less production runtime; they match published exploit shapes and are not a substitute for updating Plex. 9531290 matches the credential files themselves, however a read is delivered. On 9531280, `media://` is what clients send on that endpoint; `metadata://` and `upload://` are included defensively. Trim if your traffic shows only `media://`.

## Endpoint denies

Everything else is forwarded for the shared-client API (browsing, playback, search, sync). Where a path carries both a harmless read and a privileged write, the deny is scoped by method rather than dropping the path.

| Rule | Paths | Why |
|---|---|---|
| 9531400 | `/` with `Accept: text/html` | Plex 302s browsers to `/web/index.html`; API clients never send `text/html` |
| 9531410 | `/web` | Plex Web UI bundle (XSS surface, plex.tv auth redirect) |
| 9531420 | `/myplex`, `/connections` | return the owner token (CVE-2025-69414/69415 class), blocks `/myplex/account` escalation chain |
| 9531430 | `/:/prefs`, `/updater/check`, `/updater/apply`, `/transcode/sessions` (bare list only), `/butler`, `/system/notification`, `/diagnostics`, `/services/browse`, `/log/networked`, `/media/grabbers`, `/servers` | server management |
| 9531440 | `/system/agents` | answers **without a token**; Fix Match search + art fetch |
| 9531450 | `/system/proxy` | server-side URL fetch (CVE-2014-9304 SSRF) |
| 9531460 | any path, `X-Plex-Url` header present | the CVE-2014-9304 proxy's target-URL header; no current client sends it, so its presence is a probe |
| 9531470 | any path containing `..`, `\` or a `/./` segment, raw or encoded (query string excluded) | no legitimate Plex path has any of these; closes `/library/../web`-style bypasses for every deny above |
| 9531480 | any method other than `GET`, `HEAD` or `OPTIONS` on `/activities[/{id}]`, `/transcode/sessions/{id}`, `/updater/status` | these paths are read by ordinary clients (progress poll, own-session poll, update state) so they are not path-denied; their owner-only writes (`DELETE` cancels a task or kills a transcode) and any other verb are denied. Plex defines no other verbs here and none has been observed; HEAD is allowed as a bodiless GET for health probes; OPTIONS because PMS answers it with CORS headers only and a browser preflight must not be dropped |
| 9531490 | `POST`/`PUT` on `/library/sections/all`, `/library/sections/{id}`, `/playlists/upload`, `/media/providers` | these take a server filesystem path (`locations[]`, `path`) or a URL the server reverse-proxies (`url`), the input shape behind every real Plex CVE; no client calls them; `GET` on the same paths is ordinary client traffic and passes; `/{id}/refresh`, `/{id}/all` and `POST /playlists` stay open |

Deliberately **not** denied, because Plex enforces owner-only or per-account access itself. Verified 2026-09-26 by calling each on localhost with a managed-user token (`admin=0`, one library granted) in the same session as the owner:

| Path | Shared token | Owner use |
|---|---|---|
| `/status/sessions` | 403 | Now Playing / History |
| `/accounts` | 403 | History detail (user name) |
| `/devices` | 403 | History detail (device name) |
| `/statistics/bandwidth` | 200, empty [1] | Dashboard; per-account filtered |
| `GET /activities` | 200, empty [1] | progress poll made by Plex Web and desktop clients every session |
| `GET /updater/status` | 403 | polled by Plex Web every session |
| `GET /transcode/sessions/{id}` | n/a | a client's own transcode status; polled during playback by Android TV. The bare `/transcode/sessions` list stays denied: no client has been observed calling it |

[1] Empty for the managed user while the owner token, at the same moment, returned data (bandwidth rows; a running library scan). Plex filters these per account.

The owner's mobile app Server section requests `/:/prefs` (denied) and works without it.

The path denies match `REQUEST_URI` with `t:urlDecodeUni,t:lowercase`, so anchors tolerate a trailing `?query` and `/WEB` is caught (Plex on Windows serves `/web` from a case-insensitive filesystem). They do not use a path-normalizing transform: on a Windows Coraza build those emit backslashes and a forward-slash regex silently fails open. Traversal is handled by 9531470 instead, which drops any request whose path carries `..`, a backslash or a `/./` segment, raw or percent-encoded (the query string is not inspected, since search text and log messages legitimately contain both). Denies are phase 1 and issue `drop` directly rather than scoring, which the plugin guidelines permit.

## Interactions

- **Exclusions vs. detection:** plex-rule-exclusions-plugin removes `ARGS:X-Plex-Client-Profile-Extra` from 932235/932370 (9530100) and `ARGS:url` from 931100/934110 for loopback URLs only (9530110). Detection rules 9531200 and 9531220 here still inspect those targets.
- **Coraza:** all regexes are RE2-compatible (no lookaround or backreferences); no persistent collections are used. Do not add a path-normalizing transform to the endpoint denies (see Endpoint denies). Check how your Coraza connector maps `drop`, or use the `SecRuleUpdateActionById` line above.
- **Tags:** the plugin's rules carry `plex-hardening-plugin` (and `plex-hardening-plugin/endpoint-deny` on the denies), not `OWASP_CRS`. A tag-wide exclusion such as `ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS` therefore leaves this plugin's rules active on that path - intended, so a broad CRS exclusion on an unrelated application does not silently switch off Plex protection. To exclude the plugin's rules on a path, target the plugin's own tag or its ID range: `ctl:ruleRemoveByTag=plex-hardening-plugin` or `ctl:ruleRemoveById=9531100-9531999`.

## What the owner can and cannot do through the proxy

The endpoint denies (9531400-9531499) are an owner-only surface. Through the
proxy, with denies on and no trusted-source allowlist:

- Works: browse, play, search, filter, edit item metadata (titles, posters,
  Fix Match), scan a library, playlists, downloads.
- Blocked by design: Settings, updater, agents, and library administration
  (create, edit or rename a library, playlist import from a server path,
  media providers). Do these from localhost or the LAN, or list a trusted
  address in 9531022.

Editing a library from Plex Web fails at the dialog, not at Save: the dialog
loads the agent list from `/system/agents`, which 9531440 denies.

Where observed client behavior differs from the Plex OpenAPI spec, the rules
follow the traffic; the deltas are listed in the plex-rule-exclusions-plugin
README ("Observed deltas from the spec").

## Testing

Tests use the go-ftw YAML format under `tests/regression/plex-hardening-plugin/`, one file per rule, and run through the shared [crs-plugin-test-action](https://github.com/coreruleset/crs-plugin-test-action) workflows (`.github/workflows/integration.yml`, `lint.yml`). That pipeline runs Apache + ModSecurity 2 and nginx + ModSecurity 3 in `DetectionOnly` at paranoia level 4 against CRS `main` and the current LTS, so assertions are on logged rule IDs; `drop` is never exercised there. Coraza is not part of the shared pipeline.


## Reporting false positives

If you find a false positive that this plugin does not cover then please open a new issue or pull request, including:

1. CRS version
2. ModSecurity / Coraza version
3. WAF audit or error log lines for the request
4. The Plex client and action that caused it

## License

Apache-2.0
