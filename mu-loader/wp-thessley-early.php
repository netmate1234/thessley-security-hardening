<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Thessley Security Hardening — early request gate.
 *
 * Deployed as a must-use plugin so it runs before the rest of WordPress
 * bootstraps. Self-contained: does not depend on the main wp-thessley plugin
 * being loaded (mu-plugins load first). Every enabled module has a check.php
 * inside the plugin's own folder; this file requires each one (see the end
 * of the file) and each calls thessley_register_check() to add itself. This
 * is the only file the plugin places in wp-content. Compiled datasets are
 * read from wp-content/uploads/thessley-security-hardening/ — see
 * thessley_data_file().
 *
 * Kill switch: define('THESSLEY_DISABLE', true) in wp-config.php to bypass
 * the gate below if a check ever misfires.
 *
 * The helper functions below are always defined, even under WP_CLI or the
 * kill switch — regular plugin code (admin UI, cron) calls them too (e.g.
 * to manage the local blocklist), and those callers run in contexts this
 * file can't distinguish from a gated HTTP request at define-time.
 */

if ( ! function_exists( 'thessley_register_check' ) ) {
	/**
	 * @param callable $check    Receives no args, returns null/false to
	 *                           allow, or array{reason:string} to block.
	 * @param int      $priority Lower runs earlier (WP hook-priority
	 *                           convention). Default 10. Checks otherwise
	 *                           run in glob() filesystem order, which is
	 *                           alphabetical by check filename — an
	 *                           accident of naming, not a real ordering
	 *                           guarantee, so anything that actually
	 *                           depends on running before/after another
	 *                           check (e.g. a URL-specific check needing
	 *                           first refusal ahead of a broader one that
	 *                           would otherwise wp_die() first and pre-empt
	 *                           it) should set this explicitly rather than
	 *                           relying on its filename sorting right.
	 */
	function thessley_register_check( callable $check, $priority = 10 ) {
		global $thessley_checks;
		static $seq = 0;
		$thessley_checks[] = array( 'priority' => $priority, 'seq' => $seq++, 'check' => $check );
	}
}

if ( ! function_exists( 'thessley_data_file' ) ) {
	/**
	 * Full path of a compiled data file in the plugin's uploads folder, or ''
	 * when the folder has not been created yet. The folder path is stored
	 * (not recomputed) because this runs before plugins load, when filters
	 * on the uploads location may not be registered yet.
	 *
	 * @param string $name File name inside the folder, e.g. 'geo-country-index.bin'.
	 */
	function thessley_data_file( $name ) {
		$dir = get_option( 'thessley_data_dir', '' );
		if ( ! is_string( $dir ) || '' === $dir || 'thessley-security-hardening' !== basename( $dir ) ) {
			return '';
		}
		return $dir . '/' . $name;
	}
}

if ( ! function_exists( 'thessley_request_uri' ) ) {
	/**
	 * The request URI exactly as sent, un-slashed but otherwise untouched.
	 *
	 * This is the one place the raw value is read for inspection. Attack
	 * signatures have to match the bytes the client actually sent (a
	 * sanitised copy would have the payload stripped out before it was
	 * compared), so nothing here can be sanitised. The value is never echoed
	 * or stored as-is: anything that reaches the event log, an alert or a
	 * report goes through thessley_clean_detail() / esc_url_raw() first.
	 */
	function thessley_request_uri() {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- read for signature matching only; see the docblock above. Sanitised before any storage or output.
		return isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( (string) $_SERVER['REQUEST_URI'] ) : '';
	}
}

if ( ! function_exists( 'thessley_query_string' ) ) {
	/** Raw query string for signature matching only; same reasoning as thessley_request_uri(). */
	function thessley_query_string() {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- read for signature matching only; sanitised before any storage or output.
		return isset( $_SERVER['QUERY_STRING'] ) ? wp_unslash( (string) $_SERVER['QUERY_STRING'] ) : '';
	}
}

if ( ! function_exists( 'thessley_clean_detail' ) ) {
	/**
	 * Makes a snippet of request data safe to store, alert on and report.
	 * Angle brackets become look-alike single quotation marks first, so an
	 * XSS probe stays readable in the log ("‹script›alert(1)‹/script›")
	 * instead of being stripped to nothing by tag removal, then
	 * sanitize_text_field() strips anything else (control characters,
	 * line breaks, percent-octets, invalid UTF-8).
	 */
	function thessley_clean_detail( $text ) {
		return sanitize_text_field( str_replace( array( '<', '>' ), array( '‹', '›' ), (string) $text ) );
	}
}

if ( ! function_exists( 'thessley_client_ip' ) ) {
	function thessley_client_ip() {
		// An IP address contains only digits, dots and (for IPv6) colons/hex,
		// so sanitize_text_field() leaves a genuine one untouched; anything
		// else in this header isn't an address and every caller re-validates
		// the result (ip2long()/filter_var()) before trusting it anyway.
		return isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
	}
}

if ( ! function_exists( 'thessley_events_table' ) ) {
	function thessley_events_table() {
		global $wpdb;
		return $wpdb->prefix . 'thessley_events';
	}
}

if ( ! function_exists( 'thessley_severity_map' ) ) {
	/**
	 * Event severity, 1 (noise) to 20 (treat the site as compromised).
	 *
	 * The scale is about *what the event implies*, not how confident the
	 * detection is. Anything at 18+ means something already succeeded —
	 * a file changed, an admin account exists that shouldn't — as opposed
	 * to an attempt that was stopped, which tops out around 17.
	 *
	 * Rough bands:
	 *   18-20  evidence of compromise; investigate now
	 *   14-17  serious exploitation attempt (RCE, webshell, SQLi)
	 *   10-13  targeted probing / confirmed brute force
	 *    5-9   background scanning and reconnaissance
	 *    1-4   informational, expected activity
	 *
	 * @return array<string,int> "module:event" or "event" => severity
	 */
	function thessley_severity_map() {
		return array(
			// --- Evidence something already happened -------------------
			'file-integrity:core_mismatch'          => 20,
			'user-watchdog:unexplained_privileged_user' => 20,
			'hardening:hidden_plugin'               => 20,
			'user-watchdog:privileged_user_created' => 19,
			'user-watchdog:privilege_escalation'    => 19,
			'file-integrity:baseline_drift'         => 18,
			'user-watchdog:admin_email_changed'     => 18,
			'user-watchdog:privileged_user_changed' => 18,
			'user-watchdog:privileged_user_deleted' => 17,

			// --- Serious exploitation attempts ------------------------
			'passkey-login:signature_invalid'       => 13,
			'passkey-login:match_code_mismatch'     => 12,
			'query-guard:upload_executable_ext'     => 17,
			'query-guard:body_php_open_tag'         => 16,
			'query-guard:body_eval_exec'            => 16,
			'query-guard:body_php_wrapper'          => 16,
			'query-guard:cmdi_shell_functions'      => 15,
			'query-guard:cmdi_command_chain'        => 15,
			'query-guard:cmdi_backtick_exec'        => 15,
			'query-guard:traversal_php_wrapper'     => 15,
			'query-guard:traversal_remote_wrapper'  => 15,
			'query-guard:other_php_object_injection' => 15,
			'query-guard:body_base64_payload'       => 14,
			'query-guard:traversal_etc_passwd'      => 14,
			'query-guard:sqli_union_select'         => 14,
			'query-guard:sqli_extractvalue'         => 14,
			'query-guard:sqli_stacked_query'        => 14,
			'query-guard:other_ssrf_cloud_metadata' => 14,
			'query-guard:sqli_information_schema'   => 13,
			'query-guard:sqli_sleep_benchmark'      => 13,
			'query-guard:sqli_or_equals'            => 13,
			'query-guard:sqli_comment_injection'    => 13,
			'query-guard:sqli_trailing_comment_bypass' => 13,
			'query-guard:sqli_mssql_probe'          => 13,
			'query-guard:body_traversal'            => 13,
			'query-guard:traversal_dotdot'          => 12,
			'query-guard:xss_script_tag'            => 12,
			'query-guard:xss_svg_onload'            => 12,
			'query-guard:other_crlf_injection'      => 12,
			'query-guard:xss_js_protocol'           => 11,
			'query-guard:xss_event_handler'         => 11,
			'query-guard:xss_data_uri_html'         => 11,
			'query-guard:body_null_byte'            => 11,
			'query-guard:other_null_byte'           => 11,

			// --- Targeted probing / confirmed brute force -------------
			'passkey-login:login_denied'            => 10,
			'passkey-login:anonymous_login_blocked' => 10,
			'passkey-login:login_csrf_blocked'      => 10,
			'login-guard:lockout'                   => 12,
			'login-guard:locked_attempt'            => 10,
			'query-guard:xmlrpc_access'             => 10,
			'rate-limiter:probe_flood'              => 10,

			// --- Reconnaissance ---------------------------------------
			'ip-blocklist:listed_ip'                => 8,
			'user-enum:rest_users'                  => 7,
			'user-enum:author_scan'                  => 7,
			'query-guard:path_plugin_theme_readme_probe' => 7,
			'query-guard:path_wlwmanifest_probe'         => 7,
			'query-guard:path_login_pathinfo_recon'      => 7,
			'query-guard:path_debug_endpoint_probe'      => 9,
			'query-guard:ua_known_scanner'               => 8,
			'login-guard:login_failed'              => 5,

			// --- Informational ----------------------------------------
			'vuln-scanner:scan_findings'            => 6,
			'auto-update:update_failed'             => 6,
			'auto-update:updater_disabled'          => 5,
			'login-guard:login_success'             => 2,
			'passkey-login:login_approved'          => 2,
			'passkey-login:enroll_approved'         => 2,
			'passkey-login:device_revoked'          => 4,
			'passkey-login:password_login_blocked'  => 4,
			'passkey-login:password_step_ok'        => 2,
			'passkey-login:attestation_verified'    => 2,
			'passkey-login:attestation_unverified'  => 5,
			'auto-update:updated'                   => 2,
			'file-integrity:baseline_taken'         => 1,
			'user-watchdog:snapshot_taken'          => 1,
		);
	}

	/**
	 * Severity for one event, falling back to a mid-scale default so an
	 * unmapped event from a new module is never silently treated as noise.
	 */
	function thessley_event_severity( $module, $event, $action = 'noted' ) {
		$map = thessley_severity_map();
		$key = $module . ':' . $event;

		if ( isset( $map[ $key ] ) ) {
			$severity = $map[ $key ];
		} elseif ( isset( $map[ $event ] ) ) {
			$severity = $map[ $event ];
		} else {
			// Unknown event: assume it matters more if a module chose to
			// block on it than if it was only noted.
			$severity = 'blocked' === $action ? 12 : 8;
		}

		return max( 1, min( 20, (int) $severity ) );
	}

	/** @return array{0:string,1:string} label and colour for a severity. */
	function thessley_severity_meta( $severity ) {
		$severity = (int) $severity;
		if ( $severity >= 18 ) {
			return array( 'Critical', '#8b0a3e' );
		}
		if ( $severity >= 14 ) {
			return array( 'High', '#c9356a' );
		}
		if ( $severity >= 10 ) {
			return array( 'Medium', '#b26e00' );
		}
		if ( $severity >= 5 ) {
			return array( 'Low', '#2271b1' );
		}
		return array( 'Info', '#646970' );
	}
}

if ( ! function_exists( 'thessley_log_event' ) ) {
	/**
	 * Central event log every module writes to, so the admin has one place
	 * to see what fired instead of grepping error_log on the server. Also
	 * mirrored to error_log, which is what the operator's existing external
	 * tooling (fail2ban-style watchers, log shippers) can consume.
	 *
	 * @param string   $module   module id, e.g. 'query-guard'
	 * @param string   $event    short machine-readable event id
	 * @param string   $action   'blocked' | 'logged' (log-only mode) | 'noted'
	 * @param string   $detail   free-text context (truncated)
	 * @param int|null $severity 1-20; omit to take it from the severity map
	 */
	function thessley_log_event( $module, $event, $action = 'noted', $detail = '', $severity = null ) {
		global $wpdb;

		$ip     = thessley_client_ip();
		$detail = substr( thessley_clean_detail( $detail ), 0, 500 );

		$severity = ( null === $severity )
			? thessley_event_severity( $module, $event, $action )
			: max( 1, min( 20, (int) $severity ) );

		// Never let a logging failure (missing table mid-upgrade, DB hiccup)
		// take down the request it was only meant to annotate.
		$table = thessley_events_table();
		$wpdb->suppress_errors( true );
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- $wpdb->insert() already parameterizes every value (the %s/%d format array); the raw REQUEST_URI is intentional here, since this IS the audit log and stripping "suspicious" characters would defeat its purpose.
		$wpdb->insert(
			$table,
			array(
				'created_at' => current_time( 'mysql' ),
				'module'     => substr( (string) $module, 0, 32 ),
				'event'      => substr( (string) $event, 0, 64 ),
				'action'     => substr( (string) $action, 0, 16 ),
				'severity'   => $severity,
				'ip'         => substr( $ip, 0, 45 ),
				'uri'        => substr( esc_url_raw( wp_unslash( (string) ( $_SERVER['REQUEST_URI'] ?? '' ) ) ), 0, 255 ),
				'detail'     => $detail,
			),
			array( '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s' )
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$wpdb->suppress_errors( false );

		thessley_maybe_telegram_alert( $module, $event, $action, $detail, $severity, $ip );
		thessley_maybe_email_alert( $module, $event, $action, $detail, $severity, $ip );
		thessley_maybe_unwantedip_report( $module, $event, $action, $detail, $severity, $ip );
	}
}

if ( ! function_exists( 'thessley_maybe_telegram_alert' ) ) {
	/**
	 * Fires from thessley_log_event() itself rather than a WP action hook.
	 *
	 * A real block (mode=block) calls wp_die()/exit immediately after
	 * logging, at mu-plugin time, before regular plugins have loaded — so
	 * 'plugins_loaded' never fires and nothing hooked there would ever run
	 * for exactly the events worth alerting on. Being inline in the one
	 * choke-point function is the only way this reaches those requests too.
	 */
	function thessley_maybe_telegram_alert( $module, $event, $action, $detail, $severity, $ip ) {
		if ( ! get_option( 'thessley_telegram_enabled', false ) ) {
			return;
		}

		$threshold = (int) get_option( 'thessley_telegram_threshold', 15 );
		if ( $severity <= $threshold ) {
			return;
		}

		$token   = trim( (string) get_option( 'thessley_telegram_bot_token', '' ) );
		$chat_id = trim( (string) get_option( 'thessley_telegram_chat_id', '' ) );
		if ( '' === $token || '' === $chat_id ) {
			return;
		}

		// A scanner throwing several distinct high-severity payloads in one
		// burst could otherwise fire a message per payload in the same
		// second — a short cooldown keeps the first (most useful) alert
		// immediate without risking Telegram's rate limit on the rest. This
		// only throttles the notification channel; the event log still
		// records every event regardless.
		$lock_key = 'thessley_tg_lock';
		if ( false !== get_transient( $lock_key ) ) {
			return;
		}
		set_transient( $lock_key, 1, 5 );

		list( $label ) = thessley_severity_meta( $severity );
		$site = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );
		$host = wp_parse_url( get_option( 'siteurl' ), PHP_URL_HOST ) ?: '';

		$lines = array(
			// blogname alone reads fine on one site, but with multiple
			// wp-thessley installs alerting into the same chat it's easy to
			// miss which one fired — the domain is what actually
			// disambiguates them at a glance, and doubles as a reminder of
			// which admin to open.
			sprintf( '<b>%s</b>%s — severity %d/20 (%s)', esc_html( $site ), $host ? ' (' . esc_html( $host ) . ')' : '', $severity, esc_html( $label ) ),
			sprintf( '<b>Module:</b> %s   <b>Event:</b> <code>%s</code>', esc_html( $module ), esc_html( $event ) ),
			sprintf( '<b>Action:</b> %s   <b>IP:</b> <code>%s</code>', esc_html( $action ), esc_html( $ip ) ),
		);
		if ( '' !== $detail ) {
			$lines[] = esc_html( $detail );
		}
		$lines[] = current_time( 'mysql' );
		$text    = implode( "\n", $lines );

		wp_remote_post(
			'https://api.telegram.org/bot' . rawurlencode( $token ) . '/sendMessage',
			array(
				'timeout'  => 3,
				// The default WordPress user-agent embeds this site's address.
				'user-agent' => 'wp-thessley',
				// Fire-and-forget: this can run inside the early gate right
				// before wp_die(), and a slow/unreachable Telegram API must
				// never be what makes a blocked request hang.
				'blocking' => false,
				'body'     => array(
					'chat_id'                  => $chat_id,
					'text'                     => $text,
					'parse_mode'               => 'HTML',
					'disable_web_page_preview' => true,
				),
			)
		);
	}
}

if ( ! function_exists( 'thessley_maybe_email_alert' ) ) {
	/**
	 * Same trigger point as thessley_maybe_telegram_alert() and for the same
	 * reason, but can't reuse wp_mail(): mu-plugins load and run (see the
	 * bottom of this file) before wp-includes/pluggable.php does, so
	 * wp_mail() isn't defined yet at this call site — not just on the rare
	 * early-block path, every single call. PHP's own mail() is the only
	 * option that's actually available here, so unlike the Telegram send
	 * this one is synchronous — a slow local MTA can add latency to a
	 * blocked request, which is the accepted tradeoff for having email as
	 * an inline channel at all instead of not offering the fast path here.
	 */
	function thessley_maybe_email_alert( $module, $event, $action, $detail, $severity, $ip ) {
		if ( ! get_option( 'thessley_email_enabled', false ) ) {
			return;
		}

		$threshold = (int) get_option( 'thessley_email_threshold', 15 );
		if ( $severity <= $threshold ) {
			return;
		}

		$to = trim( (string) get_option( 'thessley_email_address', '' ) ) ?: get_option( 'admin_email' );
		if ( '' === $to ) {
			return;
		}

		// Same burst-suppression reasoning as the Telegram lock, separate key
		// so the two channels don't throttle each other.
		$lock_key = 'thessley_email_lock';
		if ( false !== get_transient( $lock_key ) ) {
			return;
		}
		set_transient( $lock_key, 1, 5 );

		list( $label ) = thessley_severity_meta( $severity );
		$site = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );
		$host = wp_parse_url( get_option( 'siteurl' ), PHP_URL_HOST ) ?: '';

		// mail()'s headers must be plain ASCII or RFC 2047 encoded-words —
		// raw UTF-8 bytes in the Subject (e.g. an em dash, or a non-ASCII
		// blogname) make some MTAs auto-negotiate the SMTPUTF8 extension,
		// which not every relay/smarthost supports, silently bouncing the
		// message. mb_encode_mimeheader() only touches the string at all
		// when it actually contains non-ASCII, so this is a no-op for a
		// plain-ASCII subject.
		$subject_raw = sprintf( '[%s] severity %d/20 (%s) - %s', $site, $severity, $label, $event );
		$subject     = mb_encode_mimeheader( $subject_raw, 'UTF-8', 'B', "\r\n" );

		$lines = array(
			sprintf( '%s%s - severity %d/20 (%s)', $site, $host ? " ({$host})" : '', $severity, $label ),
			sprintf( 'Module: %s   Event: %s', $module, $event ),
			sprintf( 'Action: %s   IP: %s', $action, $ip ),
		);
		if ( '' !== $detail ) {
			$lines[] = $detail;
		}
		$lines[] = current_time( 'mysql' );
		$body    = implode( "\n", $lines );

		// The body itself is fine as raw UTF-8 (unlike the Subject, it isn't
		// a header) as long as Content-Type declares the charset.
		$from_domain = $host ?: 'localhost';
		$headers     = "From: Thessley Security Hardening <wordpress@{$from_domain}>\r\n"
			. "MIME-Version: 1.0\r\n"
			. 'Content-Type: text/plain; charset=UTF-8';

		@mail( $to, $subject, $body, $headers );
	}
}

if ( ! function_exists( 'thessley_maybe_unwantedip_report' ) ) {
	/**
	 * Shares a blocked IP with unwantedip.eagleeye-intelligence.com — a
	 * self-hosted, cross-host reputation tracker, not a third-party service.
	 * Fires from thessley_log_event() itself for the same reason the Telegram
	 * alert does: a real block calls wp_die() at mu-plugin time, before
	 * 'plugins_loaded' — nothing hooked later would ever see these events.
	 *
	 * Only reports actual blocks, never log-only detections — the shared
	 * tracker is for "this IP did something and was stopped", not every
	 * signature this install happens to be tuning.
	 */
	function thessley_maybe_unwantedip_report( $module, $event, $action, $detail, $severity, $ip ) {
		if ( 'blocked' !== $action ) {
			return;
		}
		if ( ! get_option( 'thessley_unwantedip_enabled', false ) ) {
			return;
		}

		$api_key = trim( (string) get_option( 'thessley_unwantedip_api_key', '' ) );
		if ( '' === $api_key ) {
			return;
		}

		// Never report LAN/reserved/trusted addresses — they're never a
		// genuine attacker by definition, and the service only accepts
		// public IPv4 anyway.
		if ( '' === $ip || false === strpos( $ip, '.' ) || thessley_ip_is_exempt( $ip ) ) {
			return;
		}

		// A sustained flood from one IP would otherwise file the same report
		// dozens of times a minute — one report per (IP, module, event) per
		// hour is plenty for a reputation tracker; the local Event Log
		// already has the full detail for this install's own records.
		// Keyed on module+event, not just the IP: an IP's first block used
		// to lock out every OTHER kind of detection from that IP for the
		// same hour, so a genuinely new alert type on an already-seen IP
		// was silently dropped instead of reported.
		$lock_key = 'thessley_uip_lock_' . md5( $ip . '|' . $module . '|' . $event );
		if ( false !== get_transient( $lock_key ) ) {
			return;
		}
		set_transient( $lock_key, 1, HOUR_IN_SECONDS );

		$severity_word = $severity >= 18 ? 'critical' : ( $severity >= 14 ? 'high' : ( $severity >= 10 ? 'medium' : 'low' ) );

		// Turns internal slugs like "geo-login"/"login_country_denied" into
		// "Geo Login"/"Login Country Denied" — readable without knowing this
		// plugin's naming, and generic enough to cover any module/event
		// without a hand-maintained mapping table for every one of them.
		$humanize = function ( $slug ) {
			return ucwords( str_replace( array( '-', '_' ), ' ', (string) $slug ) );
		};

		// Anything gating wp-login.php itself — geo-based or attempt-count
		// based — is an unwanted login attempt from the reader's point of
		// view regardless of *why* this install stopped it, and "brute
		// force attempt" is the category anyone skimming a shared IP
		// reputation tracker actually recognizes. The specific reason
		// (which country, how many failed attempts) still goes in the
		// description below, just not as the headline category.
		$login_modules = array( 'geo-login', 'login-guard' );
		if ( in_array( $module, $login_modules, true ) ) {
			$title = 'WordPress Login Brute Force Attempt';
		} elseif ( 'ip-blocklist' === $module && 0 === strpos( $detail, 'matched ' ) ) {
			// $detail is "matched <source label>" (e.g. "matched Spamhaus
			// DROP (hijacked/spammer netblocks)", or "matched local
			// blocklist") — the actual matched source is a far more useful
			// public-facing category than the generic module/event name,
			// which would otherwise always just read "Ip Blocklist —
			// Listed Ip" regardless of which of the 6+ feeds caught it.
			$title = substr( $detail, strlen( 'matched ' ) );
		} else {
			$title = sprintf( '%s — %s', $humanize( $module ), $humanize( $event ) );
		}

		// Deliberately no blogname/domain here, unlike the Telegram alert —
		// that's a private message to the site owner; this is data shared
		// with a public reputation tracker, and which of your sites caught
		// something is not information that belongs on a public record.
		wp_remote_post(
			'https://unwantedip.eagleeye-intelligence.com/api/v1/report',
			array(
				'timeout'  => 3,
				// Own user-agent: WordPress' default one embeds this site's
				// address, which reports deliberately never carry. No version
				// suffix — THESSLEY_VERSION isn't defined this early.
				'user-agent' => 'wp-thessley',
				// Fire-and-forget, same reasoning as the Telegram call: this
				// can run right before wp_die(), and a slow/unreachable
				// remote API must never delay a blocked request.
				'blocking' => false,
				'headers'  => array(
					'Content-Type' => 'application/json',
					'X-API-Key'    => $api_key,
				),
				'body'     => wp_json_encode(
					array(
						'ip'       => $ip,
						'title'    => $title,
						'severity' => $severity_word,
						// unwantedip's own web UI (the "My Reports"/"All Reports"
						// tables, checked directly in its report-listing template)
						// never renders the title field anywhere a human looks —
						// only description. "title" above is kept because the API
						// requires it and the read endpoint does return it, but
						// the category alone (not this install's specific reason
						// or its 1-20 severity score, which mean nothing without
						// Thessley Security Hardening's own scale) is what belongs on a shared record.
						'description' => $title,
					)
				),
			)
		);
	}
}

if ( ! function_exists( 'thessley_reserved_cidrs' ) ) {
	/**
	 * Private/reserved IPv4 space (RFC 1918 + IANA special-purpose registry).
	 * Shared by every module: REMOTE_ADDR can't be spoofed over TCP, so a
	 * "bogon" source address only ever means a LAN/dev/VPN client or a
	 * reverse proxy passing an internal hop IP — never an attacker. Blocking
	 * on it has no security value and guarantees self-lockout, so nothing in
	 * this plugin (external lists, local escalation) is allowed to block it.
	 */
	function thessley_reserved_cidrs() {
		return array(
			'0.0.0.0/8',
			'10.0.0.0/8',
			'100.64.0.0/10',
			'127.0.0.0/8',
			'169.254.0.0/16',
			'172.16.0.0/12',
			'192.0.0.0/24',
			'192.0.2.0/24',
			'192.88.99.0/24',
			'192.168.0.0/16',
			'198.18.0.0/15',
			'198.51.100.0/24',
			'203.0.113.0/24',
			'224.0.0.0/4',
			'240.0.0.0/4',
		);
	}
}

if ( ! function_exists( 'thessley_cidr_to_range' ) ) {
	function thessley_cidr_to_range( $cidr ) {
		list( $ip, $prefix ) = explode( '/', $cidr );
		$mask  = ( 0xFFFFFFFF << ( 32 - (int) $prefix ) ) & 0xFFFFFFFF;
		$start = ip2long( $ip ) & $mask;
		return array( $start, $start | ( ~$mask & 0xFFFFFFFF ) );
	}
}

if ( ! function_exists( 'thessley_reserved_ranges' ) ) {
	/** @return array<int, array{0:int,1:int}> */
	function thessley_reserved_ranges() {
		static $ranges = null;
		if ( null === $ranges ) {
			$ranges = array_map( 'thessley_cidr_to_range', thessley_reserved_cidrs() );
		}
		return $ranges;
	}
}

if ( ! function_exists( 'thessley_ip_is_reserved' ) ) {
	function thessley_ip_is_reserved( $ip ) {
		$long = is_int( $ip ) ? $ip : ip2long( $ip );
		if ( false === $long ) {
			return false;
		}
		foreach ( thessley_reserved_ranges() as $r ) {
			if ( $long >= $r[0] && $long <= $r[1] ) {
				return true;
			}
		}
		return false;
	}
}

if ( ! function_exists( 'thessley_trusted_networks_remote_file' ) ) {
	/**
	 * Local cache of a CIDR-per-line list fetched daily from
	 * thessley_trusted_networks_url — lets every install point at one
	 * centrally-maintained file (e.g. hosted on the main site) instead of
	 * each server needing its own local copy kept in sync by hand.
	 */
	function thessley_trusted_networks_remote_file() {
		return thessley_data_file( 'trusted-networks-remote.conf' );
	}
}

if ( ! function_exists( 'thessley_parse_cidr_file' ) ) {
	function thessley_parse_cidr_file( $path ) {
		$ranges = array();
		if ( ! is_readable( $path ) ) {
			return $ranges;
		}
		foreach ( file( $path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES ) ?: array() as $line ) {
			$line = trim( $line );
			if ( '' === $line || '#' === $line[0] || false === strpos( $line, '/' ) ) {
				continue;
			}
			$ranges[] = thessley_cidr_to_range( $line );
		}
		return $ranges;
	}
}

if ( ! function_exists( 'thessley_parse_cidr_file_by_heading' ) ) {
	/**
	 * Same source file thessley_parse_cidr_file() reads, grouped by the
	 * "# Heading" comment that starts each blank-line-delimited section —
	 * crawler-nets.conf's own structure (a section is a "# Heading" line,
	 * then CIDRs and optional dated sub-comments, until the next blank
	 * line). Only used to attribute a trusted match to a human-readable
	 * source for the Bot Log — never for the actual exemption decision,
	 * which stays on the flat range list from thessley_parse_cidr_file().
	 *
	 * @return array<string,array<int,array{0:int,1:int}>> heading => ranges
	 */
	function thessley_parse_cidr_file_by_heading( $path ) {
		$by_heading = array();
		if ( ! is_readable( $path ) ) {
			return $by_heading;
		}

		$heading     = null;
		$after_blank = true;
		// Deliberately no FILE_SKIP_EMPTY_LINES here, unlike
		// thessley_parse_cidr_file() — this function's whole job is
		// noticing blank lines (they mark section boundaries), so
		// stripping them before the loop even sees them would mean only
		// the very first heading in the file is ever detected.
		foreach ( file( $path, FILE_IGNORE_NEW_LINES ) ?: array() as $line ) {
			$line = trim( $line );
			if ( '' === $line ) {
				$after_blank = true;
				continue;
			}
			if ( '#' === ( $line[0] ?? '' ) ) {
				if ( $after_blank ) {
					$heading = ltrim( $line, "# \t" );
				}
				$after_blank = false;
				continue;
			}
			$after_blank = false;
			if ( null === $heading || false === strpos( $line, '/' ) ) {
				continue;
			}
			$by_heading[ $heading ][] = thessley_cidr_to_range( $line );
		}
		return $by_heading;
	}
}

if ( ! function_exists( 'thessley_trusted_ranges' ) ) {
	/**
	 * Trusted networks — e.g. known search-engine crawler ranges you never
	 * want blocked — from a daily-downloaded cache of an operator-supplied
	 * URL (thessley_trusted_networks_url). Optional; empty if unconfigured.
	 */
	function thessley_trusted_ranges() {
		static $ranges = null;
		if ( null !== $ranges ) {
			return $ranges;
		}

		$ranges = thessley_parse_cidr_file( thessley_trusted_networks_remote_file() );

		return $ranges;
	}
}

if ( ! function_exists( 'thessley_trusted_networks_by_source_file' ) ) {
	function thessley_trusted_networks_by_source_file() {
		return thessley_data_file( 'trusted-networks-by-source.json' );
	}
}

if ( ! function_exists( 'thessley_trusted_network_source' ) ) {
	/** @return string|null the crawler-nets.conf section heading covering $needle, or null if unattributable */
	function thessley_trusted_network_source( $needle ) {
		static $by_heading = null;
		if ( null === $by_heading ) {
			$file       = thessley_trusted_networks_by_source_file();
			$by_heading = array();
			if ( '' !== $file && is_readable( $file ) ) {
				$decoded    = json_decode( (string) file_get_contents( $file ), true );
				$by_heading = is_array( $decoded ) ? $decoded : array();
			}
		}
		foreach ( $by_heading as $heading => $ranges ) {
			foreach ( $ranges as $r ) {
				if ( $needle >= $r[0] && $needle <= $r[1] ) {
					return $heading;
				}
			}
		}
		return null;
	}
}

if ( ! function_exists( 'thessley_bot_log_table' ) ) {
	function thessley_bot_log_table() {
		global $wpdb;
		return $wpdb->prefix . 'thessley_bot_log';
	}
}

if ( ! function_exists( 'thessley_bot_log_sighting' ) ) {
	/**
	 * Called from thessley_ip_is_trusted() itself, right where it finds a
	 * match — not a separate check re-deciding anything. A verified match
	 * here can never be blocked by anything else in this codebase: every
	 * module checks exemption before ever reaching a block decision, so
	 * there's no "was this later blocked" to correlate — every row this
	 * writes is, definitionally, a pass. Whether a given IP was *also*
	 * blocked at some other time (e.g. before it was whitelisted, or a
	 * different non-trusted IP spoofing the same bot's user-agent) is
	 * answered by cross-checking the main Event Log at render time
	 * instead, not by tracking state here.
	 */
	function thessley_bot_log_sighting( $needle, $ip_string ) {
		static $logged_this_request = array();
		if ( isset( $logged_this_request[ $ip_string ] ) ) {
			return; // thessley_ip_is_trusted() can be called more than once
			        // per request (each module checks exemption itself) —
			        // one row per IP per request, not one per call.
		}
		$logged_this_request[ $ip_string ] = true;

		$source = thessley_trusted_network_source( $needle );
		if ( null === $source ) {
			return; // matched, but no section header covers it — nothing useful to attribute
		}

		// Not every trusted section is a crawler — friend IPs, protected
		// own infrastructure, an ISP's customer range, a backup server —
		// those are operator-trusted people/servers, not "bots", and
		// logging every hit from the admin's own IP as a "bot sighting"
		// would just be noise in a log meant to answer "which crawlers
		// visited". Exclude by prefix rather than maintain a bot allowlist,
		// so a newly-added crawler vendor is included automatically.
		$non_bot_prefixes = array( 'RFC1918', 'Protected servers', 'Friend IPs', 'VOO ', 'JetBackup', 'Martin' );
		foreach ( $non_bot_prefixes as $prefix ) {
			if ( 0 === stripos( $source, $prefix ) ) {
				return;
			}
		}

		global $wpdb;
		$table = thessley_bot_log_table();
		$wpdb->suppress_errors( true );
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- $wpdb->insert() already parameterizes every value; the raw REQUEST_URI is intentional here, same as the events-table insert above.
		$wpdb->insert(
			$table,
			array(
				'created_at' => current_time( 'mysql' ),
				'bot_name'   => substr( $source, 0, 128 ),
				'ip'         => substr( $ip_string, 0, 45 ),
				'uri'        => substr( esc_url_raw( wp_unslash( (string) ( $_SERVER['REQUEST_URI'] ?? '' ) ) ), 0, 255 ),
			),
			array( '%s', '%s', '%s', '%s' )
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$wpdb->suppress_errors( false );
	}
}

if ( ! function_exists( 'thessley_ip_is_trusted' ) ) {
	function thessley_ip_is_trusted( $ip ) {
		$long = is_int( $ip ) ? $ip : ip2long( $ip );
		if ( false === $long ) {
			return false;
		}
		foreach ( thessley_trusted_ranges() as $r ) {
			if ( $long >= $r[0] && $long <= $r[1] ) {
				if ( function_exists( 'thessley_bot_log_sighting' ) ) {
					thessley_bot_log_sighting( $long, is_int( $ip ) ? long2ip( $long ) : (string) $ip );
				}
				return true;
			}
		}
		return false;
	}
}

if ( ! function_exists( 'thessley_ip_is_exempt' ) ) {
	/**
	 * Combined "never enforce against this IP" check — reserved,
	 * operator-trusted (CIDR file/URL), or explicitly allowlisted. This is
	 * the one check nearly every blocking module already calls, so an IP
	 * added to the allowlist (Perimeter > Whitelist) is honored everywhere
	 * automatically, not just by whichever module happens to check for it.
	 *
	 * Accepts either a dotted-decimal string or an ip2long() integer — most
	 * callers pass whichever form they already have on hand.
	 */
	function thessley_ip_is_exempt( $ip ) {
		if ( thessley_ip_is_reserved( $ip ) || thessley_ip_is_trusted( $ip ) ) {
			return true;
		}

		$ip_string = is_int( $ip ) ? long2ip( $ip ) : (string) $ip;
		return in_array( $ip_string, (array) get_option( 'thessley_ip_allowlist', array() ), true );
	}
}

/*
 * Shared cross-module IP escalation: any check can call
 * thessley_local_blocklist_add() to put an IP on a short-lived local
 * blocklist that ip-blocklist also enforces, so one module's detection
 * protects against that IP everywhere, not just for the request that
 * triggered it. The list lives in the thessley_local_blocklist option
 * (autoloaded, so reading it in the early gate costs no extra query) and
 * is never written to disk: it used to be mirrored into a generated PHP
 * range file under mu-plugins, but that file only ever held exact single
 * IPs already keyed by address in the option, so an isset() on the option
 * is both simpler and faster than a range search over a file.
 */

if ( ! function_exists( 'thessley_local_blocklist_add' ) ) {
	function thessley_local_blocklist_add( $ip, $reason, $ttl_seconds = DAY_IN_SECONDS ) {
		$long = ip2long( $ip );
		// thessley_ip_is_exempt() now covers the allowlist too, not just
		// reserved/trusted — an explicitly never-block IP shouldn't even
		// appear in the Local Blocklist list in the first place: relying
		// only on the enforcement check skipping it there is fragile (a
		// future check.php could get the order wrong) and confusing in the
		// admin UI (an IP sitting in "blocked" that never actually gets
		// blocked).
		if ( false === $long || thessley_ip_is_exempt( $long ) ) {
			return false;
		}

		$list        = get_option( 'thessley_local_blocklist', array() );
		$list[ $ip ] = array(
			'reason'     => (string) $reason,
			'added_at'   => time(),
			'expires_at' => time() + (int) $ttl_seconds,
		);
		update_option( 'thessley_local_blocklist', $list, false );

		return true;
	}
}

if ( ! function_exists( 'thessley_local_blocklist_rebuild' ) ) {
	/** Drops expired entries from the local blocklist option. */
	function thessley_local_blocklist_rebuild() {
		$list = get_option( 'thessley_local_blocklist', array() );
		$now  = time();
		$kept = array();

		foreach ( $list as $ip => $entry ) {
			if ( ! empty( $entry['expires_at'] ) && $entry['expires_at'] < $now ) {
				continue;
			}
			$kept[ $ip ] = $entry;
		}

		if ( count( $kept ) !== count( $list ) ) {
			update_option( 'thessley_local_blocklist', $kept, false );
		}
	}
}

if ( ! function_exists( 'thessley_local_blocklist_has' ) ) {
	/** True when $ip (dotted string) is on the local blocklist and its entry hasn't expired. */
	function thessley_local_blocklist_has( $ip ) {
		$list = get_option( 'thessley_local_blocklist', array() );
		if ( ! isset( $list[ $ip ] ) ) {
			return false;
		}
		$expires = $list[ $ip ]['expires_at'] ?? 0;
		return empty( $expires ) || $expires >= time();
	}
}

if ( defined( 'THESSLEY_DISABLE' ) && THESSLEY_DISABLE ) {
	return;
}

// CLI/cron has no real "visitor" and REMOTE_ADDR is unreliable there
// (often unset or a loopback placeholder) — never gate it, only HTTP requests.
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	return;
}

$GLOBALS['thessley_checks'] = array();

// Wrapped in an IIFE rather than left as top-level statements: this file is
// require()'d directly as an mu-plugin (not inside any function), so bare
// top-level variables here would otherwise leak into the global PHP
// namespace for the rest of the request.
( function () {
	// The plugin's folder name and the list of enabled modules come from
	// options, but never as a path: the folder must be a plain directory
	// name and each module a plain slug, joined onto WP_PLUGIN_DIR, so a
	// tampered option can't make this require anything outside the plugin.
	$folder = get_option( 'thessley_plugin_folder', '' );
	$slugs  = get_option( 'thessley_active_checks', array() );
	if ( is_string( $folder ) && preg_match( '/^[A-Za-z0-9_-][A-Za-z0-9._-]*$/', $folder ) && is_array( $slugs ) ) {
		// Alphabetical by slug: the same order the old per-file glob() gave.
		sort( $slugs );
		// realpath() only resolves paths on the local filesystem (it returns
		// false for a URL or stream wrapper), and the resolved file must sit
		// inside this plugin's own folder, so this can only ever load a local
		// check.php that ships with the plugin, never a remote file.
		$plugin_root = realpath( WP_PLUGIN_DIR . '/' . $folder );
		foreach ( $slugs as $slug ) {
			if ( ! is_string( $slug ) || ! preg_match( '/^[a-z0-9-]+$/', $slug ) || false === $plugin_root ) {
				continue;
			}
			$check_file = realpath( $plugin_root . '/includes/modules/' . $slug . '/check.php' );
			if ( false !== $check_file && 0 === strpos( $check_file, $plugin_root . DIRECTORY_SEPARATOR ) && is_readable( $check_file ) ) {
				require $check_file;
			}
		}
	}

	usort(
		$GLOBALS['thessley_checks'],
		function ( $a, $b ) {
			// usort() isn't guaranteed stable before PHP 8 (this plugin's floor
			// is 7.4), so 'seq' (registration order) breaks priority ties
			// explicitly instead of trusting the engine to preserve it.
			return $a['priority'] <=> $b['priority'] ?: $a['seq'] <=> $b['seq'];
		}
	);

	foreach ( $GLOBALS['thessley_checks'] as $entry ) {
		$result = call_user_func( $entry['check'] );
		if ( is_array( $result ) ) {
			wp_die(
				esc_html( $result['reason'] ?? 'Forbidden' ),
				'403 Forbidden',
				array( 'response' => 403 )
			);
		}
	}
} )();
