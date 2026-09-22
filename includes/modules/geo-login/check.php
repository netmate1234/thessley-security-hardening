<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Copied verbatim into wp-content/mu-plugins/wp-thessley-checks/ by the
// geo-login module on activation. Runs inside wp-thessley-early.php.
//
// Reuses geo-blocker's compiled country index and lookup function
// (thessley_geo_lookup(), defined by geo-blocker's own check file) rather
// than compiling a second copy of the same ~358,000-range dataset. If
// geo-blocker has never been active, thessley_geo_lookup() simply doesn't
// exist yet and this check no-ops — nothing to restrict without it.

if ( ! function_exists( 'thessley_geo_login_is_login_request' ) ) {
	/**
	 * Matches the path itself, not basename(): the same /wp-login.php/foo
	 * and //wp-login.php bypasses that applied to xmlrpc.php apply here.
	 */
	function thessley_geo_login_is_login_request() {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- must inspect the raw request path to detect wp-login.php; sanitizing it here would risk altering the very string this security check is matching against.
		$uri  = (string) ( $_SERVER['REQUEST_URI'] ?? '' );
		$path = rawurldecode( strtok( $uri, '?' ) );
		$path = preg_replace( '#/+#', '/', $path );
		return (bool) preg_match( '#(?:^|/)wp-login\.php(?:/|$)#i', (string) $path );
	}
}

// Priority 5: must run before Geo Blocker's own (default 10) site-wide
// country check. Both check.php files finish loading — and defining
// their functions, including geo-blocker's thessley_geo_lookup() this
// relies on — before either one's callback actually runs, so this only
// changes execution order, not what's available. Without it, a blocked
// country hitting wp-login.php while Geo Blocker is set to block would
// get the generic sitewide refusal and wp_die() before this more
// specific check — and its local-blocklist escalation — ever ran.
thessley_register_check(
	function () {
		if ( ! function_exists( 'thessley_geo_lookup' ) || ! thessley_geo_login_is_login_request() ) {
			return null;
		}

		$indices = get_option( 'thessley_geo_login_country_indices', array() );
		if ( empty( $indices ) ) {
			return null; // no allowlist configured — nothing to restrict
		}

		$ip = thessley_client_ip();
		if ( '' === $ip || false === strpos( $ip, '.' ) || thessley_ip_is_exempt( $ip ) ) {
			return null; // LAN/reserved/trusted always allowed — never self-lock
		}

		$needle = ip2long( $ip );
		if ( false === $needle ) {
			return null;
		}

		$file = WPMU_PLUGIN_DIR . '/wp-thessley-checks/data/geo-country-index.bin';
		$idx  = thessley_geo_lookup( $file, $needle );
		if ( null === $idx || in_array( $idx, $indices, true ) ) {
			return null; // unknown IP (fail open) or an allowed country
		}

		$label   = function_exists( 'thessley_geo_country_label' ) ? thessley_geo_country_label( $idx ) : "index {$idx}";
		$enforce = get_option( 'thessley_geo_login_enforce_mode', 'log' );

		if ( 'block' !== $enforce ) {
			thessley_log_event( 'geo-login', 'login_country_denied', 'logged', "country {$label} (log-only)", 9 );
			return null;
		}

		thessley_log_event( 'geo-login', 'login_country_denied', 'blocked', "country {$label}", 13 );

		// A login attempt is a much stronger signal than an ordinary page
		// view, so escalate to the shared blocklist: this IP gets denied
		// site-wide, not just at the login form, on every future request.
		// Gated on enforce mode already being "block" (not just detecting a
		// hit) for the same reason query-guard does this — a still-tuning
		// allowlist shouldn't cause real blocks via a side channel while
		// the module itself is in log-only mode.
		thessley_local_blocklist_add( $ip, "geo-login: {$label}" );

		return array( 'reason' => 'Admin login is not available from your location.' );
	},
	5
);
