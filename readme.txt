=== Thessley Security Hardening ===
Contributors: martinlundstrom, opseceagleeye, shieldcoresecurity, thessleysecurity
Tags: security, firewall, malware, geo-blocking, brute-force
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.0.18
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Modular WordPress security hardening — IP/country blocking, request inspection, file integrity, malware scanning, and real-time alerting.

== Description ==

Thessley Security Hardening is a modular security plugin. Each feature is a self-contained module you can enable, configure, and put into log-only or enforcing mode independently — nothing is all-or-nothing.

**Perimeter**

* **IP Blocklist** — blocks traffic from public IP-reputation feeds (CINS, DShield, Spamhaus DROP, FireHOL), merged and compiled into a single range list, plus a local list other modules can escalate into.
* **Geo Blocker** — blocks or allows traffic by country, using a compiled IP-to-country dataset (DB-IP Country Lite) checked before WordPress finishes loading.
* **Geo Login** — restricts wp-login.php specifically to an allow-list of countries, independent of the site-wide Geo Blocker.
* **Rate Limiter** — throttles requests per IP site-wide, escalating sustained floods into the shared local blocklist.

**Request inspection**

* **Query Guard** — inspects query strings and request bodies for SQL injection, XSS, path traversal, command injection, and obfuscated-payload signatures.
* **Login Guard** — rate-limits failed logins per IP, with a configurable lockout window.

**Detection**

* **File Integrity** — verifies core files against WordPress.org's published checksums, and plugins/themes against a local baseline you take yourself.
* **Malware Scanner** — scans plugin, theme, and upload files for webshell markers, obfuscated eval/assert chains, and injected-spam patterns.
* **Vulnerability Scan** — flags outdated, removed, and unmaintained plugins/themes.
* **User Watchdog** — watches privileged accounts for the changes a backdoor actually makes: new admin accounts, role escalation, hidden users.

**Hardening**

* **Security Headers** — standard hardening response headers, including opt-in HSTS for sites behind a TLS-terminating proxy.
* **User Enumeration** — blocks anonymous username harvesting via author-scan URLs and the REST users endpoint.
* **Hardening** — disables the file editor, blocks PHP execution in uploads, and flags hidden/disguised plugins.

**Overview**

* **Event Log** — a filterable, searchable record of everything every module has seen, with a 1–20 severity score per event.
* **Event Map** — blocked/logged events tinted on a world map by country.
* **Activity Log** — the mundane admin audit trail: who published, deleted, installed, or changed what.

**Ops**

* **Auto Updates** — per-plugin auto-update control, including a "flagged only" mode driven by the Vulnerability Scan's findings.
* **Alerts** — a real-time Telegram message and/or email when an event crosses a severity threshold you set, independently per channel.

= Bundled third-party assets =

* World map outline used by the Event Map module: [flekschas/simple-world-map](https://github.com/flekschas/simple-world-map), CC BY-SA 3.0.

== Installation ==

1. Upload the plugin files to `/wp-content/plugins/thessley-security-hardening`, or install directly through the WordPress plugins screen.
2. Activate the plugin.
3. Each module starts in log-only mode where applicable — review the Event Log for a few days before switching any module to Block.

== Frequently Asked Questions ==

= Will this lock me out of my own site? =

Every blocking module exempts your LAN, reserved/private IP space, and anything in the trusted-networks list, before it ever looks at the rest of its rules. Geo Blocker and Geo Login specifically cannot lock out your own network regardless of which countries you select.

= Does this slow down every page load? =

The early-request checks (IP Blocklist, Geo Blocker, Geo Login, Rate Limiter, Query Guard's query-string scan) run as a must-use plugin before WordPress finishes bootstrapping, using compiled binary-search lookups rather than database queries — no per-request network calls, no per-request external API hits.

= Where does the geo data come from? =

DB-IP's free Country Lite database (CC BY 4.0), refreshed automatically on a schedule.

== External services ==

This plugin connects to third-party services to power its blocking, geolocation, vulnerability-lookup and alerting features. **Activating the plugin makes no external request.** Every service below is contacted only after the site admin acts on the module that owns it: saving that module's settings, clicking its refresh/test button, or entering credentials for it. The one exception is WordPress.org's own API (api.wordpress.org), which File Integrity and Vulnerability Scan query on their scheduled scans.

For every service the entry says what it is, which server is contacted, whether an account is needed, what is sent and when, and links its Terms and Privacy Policy.

**How requests identify themselves.** Requests to the feed, Jetpack, trusted-networks, unwantedip, WPScan and Telegram servers are sent with the User-Agent `wp-thessley/<version>` (or `wp-thessley`) so this site's address is not leaked in WordPress' default User-Agent. The DB-IP download and the api.wordpress.org calls use WordPress' standard User-Agent, which includes the site address, exactly as WordPress core's own update checks do.

= IP-reputation feeds (IP Blocklist module) =

Plain-text lists of malicious IP addresses and ranges. The plugin downloads the chosen lists once a day (and when you click Refresh) and compiles them into a local blocklist that is checked on each request. Each is a single anonymous HTTP GET for a public text file. No account is needed, and nothing about this site or its visitors is sent. All feeds are opt-in: the source list starts empty and is only populated when you save the IP Blocklist settings.

* **CINS Army list** — server `cinsscore.com` (`https://cinsscore.com/list/ci-badguys.txt`), operated by Sentinel IPS / Nomic Networks. Terms: https://sentinelips.com/terms — Privacy: https://sentinelips.com/privacy
* **SANS DShield block list** — server `feeds.dshield.org` (`https://feeds.dshield.org/block.txt`), operated by the SANS Internet Storm Center. About: https://www.dshield.org/about.html — Privacy: https://www.dshield.org/privacy.html
* **Spamhaus DROP** — server `www.spamhaus.org` (`https://www.spamhaus.org/drop/drop.txt`). Fair Use Policy: https://www.spamhaus.org/blocklists/drop-fair-use-policy/ — Terms: https://www.spamhaus.org/terms-conditions/ — Privacy: https://www.spamhaus.org/privacy-notice/
* **FireHOL blocklist-ipsets (levels 1 and 2) and the ET Tor exit-node list** — server `raw.githubusercontent.com` (path `/firehol/blocklist-ipsets/master/`, three files). These are the FireHOL project's own published data lists, distributed from GitHub. Each is a plain-text list of IP addresses and CIDR ranges: no scripts, stylesheets, images or other code. They are downloaded server-side, parsed as text into a local range table, and never executed or loaded by a visitor's browser. GitHub Terms: https://docs.github.com/en/site-policy/github-terms/github-terms-of-service — Privacy: https://docs.github.com/en/site-policy/privacy-policies/github-privacy-statement

= unwantedip.eagleeye-intelligence.com (IP Sharing module and IP Blocklist feed) =

A self-hosted IP-reputation tracker run by this plugin's author. Server: `unwantedip.eagleeye-intelligence.com`. It is used in three ways, all opt-in:

* **IP Sharing** requires an API key. **An account is needed, but it collects nothing personal:** clicking "Sign up for an API key" on the IP Sharing page creates one automatically from the IP address the request comes from (no name, email, site name or domain is asked for or sent). Once enabled, each time this site actually blocks a request it sends the blocked IP address, a short category (for example "WordPress Login Brute Force Attempt") and a severity label, with your API key, at most once per IP per hour. Nothing about this site, its domain, its users or its visitors' other activity is sent. **Reported IPs are public by design**: each reported address gets a public page on unwantedip, so only enable sharing if you are comfortable with that. The service's Privacy Policy explains this in full.
* **Feed** (optional source in IP Blocklist): `https://unwantedip.eagleeye-intelligence.com/api/v1/feed/wordpress` is a read-only GET of the list of WordPress-targeting IPs. It requires the same API key, which is sent as a request header; nothing else is sent.
* **Links**: the IP column of the Event Log and Bot Log links to `https://unwantedip.eagleeye-intelligence.com/ip/<ip>` in a new tab. Nothing is sent unless an admin clicks the link.

Terms: https://unwantedip.eagleeye-intelligence.com/terms.html — Privacy: https://unwantedip.eagleeye-intelligence.com/privacy-policy.html

= wp-opsec.eagleeye-intelligence.com (Whitelist module: trusted-networks list) =

A service run by this plugin's author that publishes `crawler-nets.conf`, a plain-text list of the IP ranges used by legitimate search-engine, AI and monitoring crawlers (Google, Bing, DuckDuckGo, OpenAI, Cloudflare and others), updated automatically from those operators' own published ranges. The Whitelist module uses it so genuine crawlers are not blocked by the other modules.

* **Server contacted:** `wp-opsec.eagleeye-intelligence.com`, one file: `https://wp-opsec.eagleeye-intelligence.com/wp-content/uploads/wp-opsec/crawler-nets.conf`
* **Account needed:** No.
* **When:** opt-in. The Whitelist page pre-fills the URL field with this address as a suggestion only; nothing is fetched until you save the page. It is then refreshed daily and when you click Refresh. Clear the field to turn remote fetching off, or replace it with your own URL.
* **Data sent:** none. It is a single anonymous GET request for a static file, with the `wp-thessley/<version>` User-Agent. Nothing about this site, its users or its visitors is sent. The server's standard web-server access log records the requesting IP address and time.
* **Terms / Privacy:** the file is static and no account or personal data is collected, so there is no separate policy page. Contact for any question or removal request: martin.lundstrom@gmail.com

= DB-IP Country Lite (Geo Blocker and Geo Login modules) =

A compiled IP-to-country dataset. Server: `download.db-ip.com` (`https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.csv.gz`). It is downloaded when you first save the Geo Blocker settings or click its Refresh button (Geo Login uses the same dataset), then refreshed weekly, and looked up locally, so no visitor IP address is ever sent to DB-IP. No account is needed. Nothing is sent beyond the download request itself. Source: https://db-ip.com — Privacy: https://db-ip.com/privacy.php — Dataset licensed CC BY 4.0: https://creativecommons.org/licenses/by/4.0/

= api.wordpress.org (File Integrity and Vulnerability Scan modules) =

WordPress.org's own API. No account is needed.

* **File Integrity** fetches WordPress core's official checksums from `https://api.wordpress.org/core/checksums/1.0/` to compare against this site's core files. It sends this site's WordPress version and locale, the same two values core itself sends for its own update checks.
* **Vulnerability Scan** queries `https://api.wordpress.org/plugins/info/1.0/<slug>.json` for each installed plugin to see whether it is still listed, closed or long unmaintained. It sends the slug of each installed plugin being checked, and nothing else about this site.

Terms/Privacy: https://wordpress.org/about/privacy/

= Jetpack IP list (Query Guard module) =

Opt-in, only when XML-RPC blocking is enabled. Fetches Automattic's published Jetpack IP range list (`https://jetpack.com/ips-v4.txt`, server `jetpack.com`) so xmlrpc.php requests genuinely coming from Jetpack's own servers can be exempted. No account is needed and nothing is sent beyond the request for the list. Terms: https://automattic.com/tos/ — Privacy: https://automattic.com/privacy/

= WPScan API (Vulnerability Scan module) =

Opt-in. Adds known-CVE data for installed plugins and themes. Server: `wpscan.com` (`https://wpscan.com/api/v3/`). **An account is needed**: a free WPScan API token that you obtain yourself at https://wpscan.com/api and enter on the Vulnerability Scan page. Sent: the slug of each installed plugin/theme being checked and your API token, once per plugin/theme per 24 hours (results are cached). No other site data is sent. Terms: https://wpscan.com/terms/ — Privacy: https://automattic.com/privacy/

= Telegram Bot API (Alerts module) =

Opt-in. Sends a message to a Telegram chat you control when a security event exceeds the severity threshold you configure. Server: `api.telegram.org`. **An account is needed**: a Telegram bot token (from @BotFather) and a chat ID that you provide. Sent, only when a qualifying event fires (or when you press "Send test"): the site name and domain, the module and event name, the action taken, the offending IP address, a short detail string and a timestamp. Terms: https://telegram.org/tos — Privacy: https://telegram.org/privacy

= Email alerts (Alerts module) =

Opt-in. Uses this site's own mail system, not a third-party service, so nothing is sent to any server listed here.

== Changelog ==

= 1.0.18 =
* The local blocklist is no longer mirrored into a generated PHP range file under wp-content/mu-plugins. That file only ever held exact single IPs already keyed by address in the thessley_local_blocklist option, so the early gate now checks the option directly (autoloaded, no extra query) and the plugin no longer writes any generated executable PHP from the request path at all. A leftover copy from an earlier version is removed once on upgrade.
* Request URIs and the Local Blocklist search box/hidden fields now pass through sanitizers (esc_url_raw(), sanitize_text_field(), sanitize_key()) wherever the value is only compared, logged, or displayed; the early-gate signature scans still read the raw request, since sanitizing it would alter the string being detected.
* readme: stated explicitly that the GitHub-hosted FireHOL/ET Tor feeds are plain-text data lists fetched server-side, not code or assets.

= 1.0.17 =
* Fixed a remaining activation fatal: if the early-request mu-plugin couldn't be written (host where WP_Filesystem can't initialize, or a read-only mu-plugins directory), activation unconditionally required the missing file. It now falls back to the identical copy bundled in the plugin, produces no PHP warnings, and shows an admin notice explaining that early blocking is inactive until the directory is writable.
* Event Log's stored request URI now passes through esc_url_raw() (percent-encoded payloads preserved for forensics; raw angle brackets and quotes stripped). Detection itself still reads the raw request.
* readme: added CINS Army's real Terms/Privacy links (Sentinel IPS / Nomic Networks), and corrected the External services section — nothing is contacted on activation or enabled by default; File Integrity and Vulnerability Scan's use of api.wordpress.org is now disclosed with exactly what they send.

= 1.0.16 =
* unwantedip.eagleeye-intelligence.com now has a real Terms of Service and Privacy Policy page — linked from the External services section below.

= 1.0.15 =
* Fixed an activation-fatal risk: on a host where WP_Filesystem can't initialize without credentials, every raw filesystem() dereference across the plugin (mu-plugin deploy, compiled-data writers, the legacy migration) could fatal instead of degrading gracefully. All routed through safe wrappers now. Also extended a phpcs suppression that only covered its next line instead of the whole flagged block, and added the thessleysecurity Contributors entry.

= 1.0.14 =
* Silenced 10 Plugin Check warnings on the legacy-identifier migration's DB queries — the refactor into a reusable helper (1.0.13) lost the justification annotations covering table-identifier renames and prefix-based option lookups. Verified with a fresh Plugin Check run: 0 errors, 1 warning (the expected, unfixable "Plugin Updater detected" notice for the Auto Updates module's own advertised feature).

= 1.0.13 =
* Fixed a data-loss bug in the legacy-identifier migration: the old-checks-directory cleanup was deleting compiled runtime data (Geo Blocker's country index, IP Blocklist's compiled ranges) along with the stale files it was meant to remove, with no automatic way to regenerate it. Compiled data now survives the migration.

= 1.0.12 =
* Renamed from ShieldCore Security to Thessley Security Hardening at WordPress.org's request — "ShieldCore" conflicts with existing security-industry products and is too close to the established "Shield Security" plugin. No functional changes. Internal identifiers renamed from `shieldcore` to `thessley` with an automatic one-time migration on upgrade, chained after the existing wpopsec->shieldcore migration so a site on either historical prefix ends up fully migrated in one pass; Config Import/Export's file-format identifier changed again as well.

= 1.0.11 =
* Purged remaining "Opsec" strings from plugin/infra code (test messages, alert text, uploads-guard marker, outbound email From header) and fixed a bug where Config Import/Export's own file-format check rejected every file it had just exported. Renamed the plugin's directory and main file (opsec/opsec.php -> shieldcore-security/shieldcore-security.php) to match.

= 1.0.10 =
* Local Blocklist and Login Guard's IP columns no longer wrap/shrink to near-nothing on narrow screens — missing `white-space:nowrap` let the browser squeeze that column instead of letting the table scroll horizontally as intended.

= 1.0.9 =
* Every module's data table (Dashboard recent-events, Geo Map, Vulnerability Scan, Login Guard, Activity Log, Scan All, User Watchdog, Bot Log, Malware Scanner, IP Blocklist, Security Headers) now scrolls horizontally on narrow screens instead of overflowing off-screen — 1.0.8 only fixed this for Event Log specifically.

= 1.0.8 =
* Fixed Event Log table overflowing off-screen on narrow/mobile viewports — now scrolls horizontally inside its own container instead of clipping.
* Admin CSS/JS assets are now cache-busted by their own file-modified time instead of the plugin version, so a style/script edit alone can no longer get stuck behind a stale browser cache.
* Two leftover "Opsec" references in this readme (description opener, install path) updated to ShieldCore Security.

= 1.0.7 =
* Internal identifiers (PHP classes, functions, hooks, options, the three custom database tables, mu-plugin file/folder names, admin-page slugs, CSS classes) renamed from the old `wpopsec`/`WPOpsec` prefix to `shieldcore`, matching the public rename to ShieldCore Security. An automatic one-time migration on upgrade renames the existing tables and options in place so no data is lost; sites are not required to deactivate/reactivate first. Config Import/Export's file-format identifier also changed, so a config file exported before this version can no longer be re-imported.

= 1.0.6 =
* Renamed from EagleEye Opsec to ShieldCore Security at WordPress.org's request — "EagleEye" and "Opsec" both conflict with existing registered/in-use security-industry marks. No functional changes.

= 1.0.5 =
* Query Guard: added signatures for SQLi numeric-context comment bypass, stacked destructive queries, MSSQL/xp_cmdshell probes, PHP object-injection payloads, CRLF/header-splitting injection, cloud-metadata SSRF probes, and data:text/html XSS; expanded the remote-wrapper signature to cover phar://, zip://, glob:// and file:// alongside expect:// and data://.

= 1.0.4 =
* Cleared Plugin Check's remaining warnings (286 -> 1, the last being an informational-only notice): settings fields now go through proper sanitizers instead of a bare trim(), a missing file-upload existence check was added, and every other finding was verified safe and documented inline.

= 1.0.3 =
* Silenced Plugin Check's remaining 19 false-positive errors (verified safe table-name/query-template SQL patterns, and server-side threat-feed URLs misidentified as front-end assets) with justified inline annotations, rather than rewriting already-safe code.

= 1.0.2 =
* Removed a debug error_log() call that fired on every logged security event, duplicating the Event Log's own database record on every request.
* Scoped the early-gate's check-dispatch variables out of the global PHP namespace.

= 1.0.1 =
* Verified against the official Plugin Check tool: added missing direct-file-access guards on 6 files, replaced date() with gmdate() at 3 sites, escaped two output sites (Event Map's SVG, paginate_links() calls), and moved 20 file writes/renames/deletes to the WP_Filesystem API.

= 1.0.0 =
* First release prepared for the WordPress.org plugin directory.
* Fixed a text-domain mismatch (translation strings used 'wp-opsec', the plugin header declares 'opsec').
* Documented the bundled world-map graphic's license (CC BY-SA 3.0) alongside the existing external-services disclosures.

= 0.1.9 =
* New Import/Export tab (Other): back up or restore every module's settings as a single JSON file, with each module optionally left out on either side. API keys/tokens are included by default, with an option to leave them out.
* Query Guard's CVE-2026-63030/CVE-2026-60137 ("wp2shell") signature now also catches the pretty-permalink form of the REST batch endpoint, not just the query-string form — closes a gap confirmed live on a client site.
* User Enumeration's per-plugin REST route list replaced with a general pattern, after real traffic showed a scanner fuzzing dozens of plugin namespaces the list didn't cover.

= 0.1.8 =
* New Query Guard signature for CVE-2026-63030/CVE-2026-60137 ("wp2shell"), the unauthenticated pre-auth RCE chain in WordPress core's REST batch endpoint (CISA KEV, 2026-07-21).
* Admin menu: "Overview" cluster renamed to "Logs", "Ops" cluster renamed to "Other".

= 0.1.7 =
* New Bot Log tab (Overview): a separate record of verified good-bot visits, distinct from the Event Log.
* IP Blocklist Event Log and unwantedip reports now name the actual matched source feed instead of a generic label.
* unwantedip.eagleeye-intelligence.com added as a sixth IP Blocklist source (WordPress-targeting IPs, requires the same API key as IP Sharing).
* Trusted-networks canonical source moved to wp-opsec.eagleeye-intelligence.com, with automatic weekly updates from Google, Bing, DuckDuckGo, OpenAI, and Cloudflare's own published IP ranges.
* Query Guard: new always-on path-probe detection (PHPUnit RCE, exposed .env/.git, wp-config backups, backup-archive probes, path traversal), a signature for CVE-2026-76581 (WPMU DEV Dashboard Hub SSO), and its checks now run early enough to be logged even when another module blocks the same request first.
* User Enumeration: new setting to hide WordPress's built-in user sitemap, and blocking extended to WooCommerce, LearnDash, Tutor LMS, Ultimate Member, bbPress, MemberPress, and BuddyPress's own user/customer-listing REST routes.
* Fixed a real opcache-staleness bug across every module's check.php deployment that could serve stale logic to a live request after an update.

= 0.1.6 =
* New Query Guard signature for the php-cgi %ADd argument-injection technique (CVE-2012-1823 / CVE-2024-4577).
* Query Guard's signature scan now runs ahead of the default-priority checks, so its detections get logged even when another module (IP Blocklist, Login Guard, etc.) ultimately blocks the same request first.

= 0.1.5 =
* New IP Blocklist source: unwantedip.eagleeye-intelligence.com's WordPress-targeting IP feed (requires the same API key as IP Sharing).
* IP Blocklist Event Log entries now name the actual source feed(s) that matched, instead of a generic "reputation list".
* Geo Login now runs before Geo Blocker on wp-login.php requests, so its own block (and local-blocklist escalation) is no longer pre-empted by the site-wide check.

= 0.1.4 =
* Telegram Alerts renamed to Alerts, with email added as a second, independently-configured notification channel alongside Telegram.
* Fixed email alerts silently bouncing when the subject line contained non-ASCII characters.
* Dashboard now shows a "not fully protected yet" checklist for core baseline modules, separate from optional integrations.
* WPScan API token field now shows in clear text instead of masked.

= 0.1.3 =
* IP Sharing's API key field now shows in clear text instead of masked, so it can be checked or copied at a glance.

= 0.1.2 =
* New Whitelist tab: individually-listed IPs and the trusted-networks CIDR feed both moved here from IP Blocklist, now exempt from every blocking module (IP Blocklist, Geo Blocker, Geo Login, Rate Limiter, Login Guard, Query Guard, User Enumeration).
* Trusted-networks URL now defaults to the hosted crawler-nets.conf feed and downloads automatically on install.
* Local blocklist table gained pagination, IP/reason search, and newest-first sorting.
* Geo Blocker's country-index refresh rewritten to stream the download and parse line-by-line instead of holding the full dataset in memory — peak memory cut roughly 64% on the ~357k-range DB-IP dataset.
* IP Sharing's enabled toggle now defaults to on, so reporting goes live as soon as an API key is added.

= 0.1.1 =
* Geo Login, Event Map, Activity Log, Rate Limiter, Malware Scanner modules added.
* Admin menu reorganized into clustered tabs (Overview, Perimeter, Inspection, Detection, Hardening, Ops).
* Telegram alerts now include the site's domain alongside its name.

= 0.1.0 =
* Initial modules: IP Blocklist, Query Guard, Login Guard, Headers, User Enumeration, File Integrity, Vulnerability Scan, Auto Updates, User Watchdog, Hardening, Event Log, Telegram Alerts.
