<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require_once __DIR__ . '/class-store.php';
require_once __DIR__ . '/class-crypto.php';

/**
 * Passwordless login via a companion Android app, BankID-style:
 *
 *  - Desktop: wp-login.php shows a QR code. Scanning it with the app
 *    identifies *and* authenticates the user in one step — like BankID,
 *    the site doesn't know who's logging in until a device approves it.
 *  - Same device: instead of a QR, a tappable link opens the app
 *    directly (Android App Link) carrying the same request.
 *
 * Protocol is FIDO2-inspired rather than real WebAuthn: a device-bound
 * EC keypair generated in Android Keystore (hardware-backed, requires a
 * fresh biometric unlock per signature — enforced app-side via
 * setUserAuthenticationRequired(), not something this server can verify
 * directly), challenge/response over a short-lived request row, and a
 * signed string that always includes this site's own home_url() so a
 * QR relayed from a phishing site is self-evidently for the wrong
 * origin (see Thessley_Passkey_Crypto's docblock).
 *
 * The Android app itself is a separate codebase — this module is the
 * server half of the protocol only.
 *
 * QR rendering uses davidshimjs/qrcodejs (MIT), bundled locally at
 * assets/vendor/qrcode.min.js rather than loaded from a CDN — this
 * plugin ships through the WordPress.org directory, which expects
 * bundled assets, not remote script dependencies.
 *
 * NOT YET DONE in this scaffold (follow-up work, not covered here):
 *  - Styling/placement on wp-login.php beyond a bare functional block.
 */
class Thessley_Module_Passkey_Login {

	const CRON_HOOK      = 'thessley_passkey_prune';
	const LOGIN_TTL      = 120; // seconds a login QR/link stays valid
	const ENROLL_TTL     = 120; // seconds an enrollment QR/link stays valid
	const RATE_LIMIT_MAX = 20;  // per IP per window, on the two unauthenticated POST endpoints
	const RATE_LIMIT_WINDOW = 600;

	public static function activate() {
		Thessley_Passkey_Store::install_tables();

		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', self::CRON_HOOK );
		}

		self::add_rewrite_rule();
		flush_rewrite_rules();
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
		flush_rewrite_rules();
	}

	public static function register() {
		Thessley_Passkey_Store::maybe_upgrade();

		add_action( self::CRON_HOOK, array( Thessley_Passkey_Store::class, 'prune_expired_requests' ) );
		add_action( 'admin_post_thessley_pk_save_settings', array( __CLASS__, 'handle_save_settings' ) );
		add_action( 'admin_post_thessley_pk_revoke', array( __CLASS__, 'handle_revoke' ) );
		add_action( 'admin_post_thessley_pk_save_user_mode', array( __CLASS__, 'handle_save_user_mode' ) );

		if ( self::enabled() ) {
			// Priority 30: after core's own username/password check (20)
			// has already run and returned a real WP_User — same ordering
			// Login Guard's lockout check uses, for the same reason: this
			// only needs to act once we know the password was otherwise
			// correct, not interfere with "wrong password" handling.
			add_filter( 'authenticate', array( __CLASS__, 'maybe_block_password_login' ), 30, 1 );
		}

		add_action( 'init', array( __CLASS__, 'add_rewrite_rule' ) );
		add_filter( 'query_vars', array( __CLASS__, 'add_query_vars' ) );
		add_action( 'template_redirect', array( __CLASS__, 'maybe_render_auth_page' ) );

		add_action( 'rest_api_init', array( __CLASS__, 'register_routes' ) );

		if ( self::enabled() ) {
			add_action( 'login_head', array( __CLASS__, 'login_head_styles' ) );
			add_action( 'login_enqueue_scripts', array( __CLASS__, 'login_page_assets' ) );
			add_action( 'login_footer', array( __CLASS__, 'login_form_markup' ) );
		}

		add_action( 'show_user_profile', array( __CLASS__, 'render_profile_section' ) );
		add_action( 'edit_user_profile', array( __CLASS__, 'render_profile_section' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'profile_page_assets' ) );

		return __CLASS__;
	}

	public static function enabled() {
		return (bool) get_option( 'thessley_passkey_enabled', false );
	}

	/**
	 * Site-wide floor. 'optional': a user may still choose password-only
	 * on their own profile. 'required': every user with an active device
	 * is forced to passkey-only, regardless of their own profile choice
	 * — the site setting can tighten what a user picked, never loosen it.
	 */
	public static function mode() {
		$mode = get_option( 'thessley_passkey_mode', 'optional' );
		return in_array( $mode, array( 'optional', '2fa', 'required' ), true ) ? $mode : 'optional';
	}

	private static function mode_rank( $mode ) {
		$ranks = array(
			'optional' => 0,
			'2fa'      => 1,
			'required' => 2,
		);
		return $ranks[ $mode ] ?? 0;
	}

	private static function user_has_active_device( $user_id ) {
		foreach ( Thessley_Passkey_Store::devices_for_user( $user_id ) as $d ) {
			if ( ! $d->revoked_at ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The user's own preference, independent of whether the site floor
	 * currently forces something stricter anyway. One of:
	 *   'optional' — password alone is enough
	 *   '2fa'      — password, then an app approval, both required
	 *   'required' — password login refused outright, app only
	 */
	public static function user_preferred_mode( $user_id ) {
		$mode = get_user_meta( $user_id, 'thessley_passkey_user_mode', true );
		return in_array( $mode, array( 'optional', '2fa', 'required' ), true ) ? $mode : 'optional';
	}

	/**
	 * What actually applies to this user right now. Strictness order is
	 * optional < 2fa < required; the site floor can only push a user's
	 * choice up this scale, never pull it back down — a user who opted
	 * into 2fa or required keeps that even if the site default is
	 * 'optional', but a site set to 'required' overrides everyone
	 * regardless of their personal pick.
	 */
	public static function effective_mode_for_user( $user_id ) {
		if ( ! self::user_has_active_device( $user_id ) ) {
			return 'optional'; // nothing to require yet, regardless of any setting
		}
		$site = self::mode();
		$user = self::user_preferred_mode( $user_id );
		return self::mode_rank( $site ) >= self::mode_rank( $user ) ? $site : $user;
	}

	// --- Rewrite route: the human-facing fallback page -------------------
	//
	// Not used by the app at all (see app_link()'s docblock below) — this
	// plugin runs on arbitrary,
	// unrelated customer domains, and Android App Links' autoVerify
	// requires every destination domain to be individually declared in
	// the app's manifest plus serve a matching assetlinks.json, which
	// doesn't scale across installs the way it does for a single-issuer
	// app like BankID. Both the QR content and the same-device tap target
	// are instead a custom URI scheme (app_link(), below) that works
	// identically regardless of which site it points at, with the app
	// doing its own in-app camera scan rather than relying on the OS to
	// hand a scanned https URL to the right app. This route exists only
	// so a human who opens the QR's https URL some other way (e.g. a
	// generic camera app that doesn't know about the custom scheme) lands
	// somewhere coherent instead of a 404.

	public static function add_rewrite_rule() {
		add_rewrite_tag( '%thessley_auth_type%', '(login|enroll|2fa)' );
		add_rewrite_tag( '%thessley_auth_id%', '([^&/]+)' );
		add_rewrite_rule(
			'^thessley-auth/(login|enroll|2fa)/([^/]+)/?$',
			'index.php?thessley_auth_type=$matches[1]&thessley_auth_id=$matches[2]',
			'top'
		);
	}

	public static function add_query_vars( $vars ) {
		$vars[] = 'thessley_auth_type';
		$vars[] = 'thessley_auth_id';
		return $vars;
	}

	/**
	 * Placeholder — fill in once the app has a real applicationId, so the
	 * fallback page's Play Store link resolves. A filter rather than a
	 * settings-page field: one-time developer-level value, not something
	 * a site admin sets per site.
	 */
	private static function app_package_id() {
		return apply_filters( 'thessley_passkey_app_package_id', 'REPLACE_WITH_APP_PACKAGE_ID' );
	}

	/**
	 * Custom-scheme URI — the actual QR payload and same-device tap
	 * target. Carries everything the app needs to sign (type, request_id,
	 * nonce, origin) without any server round-trip after scanning/tapping,
	 * and works identically on every site since custom schemes don't
	 * require per-domain registration the way https App Links do.
	 */
	private static function app_link( $type, $request_id, $nonce ) {
		return 'thessleypasskey://auth?' . http_build_query(
			array(
				'type'   => $type,
				'id'     => $request_id,
				'nonce'  => $nonce,
				'origin' => home_url(),
			)
		);
	}

	/**
	 * URL for the human-facing thessley-auth page (maybe_render_auth_page())
	 * — built as a plain query string rather than the pretty
	 * thessley-auth/{type}/{id}/ path the rewrite rule also accepts. A
	 * site without a custom permalink structure never runs that rewrite
	 * rule at all (same lesson already learned the hard way for the
	 * Android app's own REST calls — see ApiClient.kt), so the pretty
	 * form 404s there. The query-string form hits index.php directly and
	 * works regardless of a site's permalink settings; add_query_vars()
	 * registers these as real query vars either way, so
	 * maybe_render_auth_page() needs no changes to accept both forms.
	 * This matters most for the 2fa redirect: unlike login/enroll's `url`
	 * field (a fallback shown only if the app fails to intercept the
	 * app_link), the 2fa confirmation page has no other way to be
	 * reached at all.
	 */
	private static function auth_url( $type, $request_id ) {
		return home_url( '/?thessley_auth_type=' . $type . '&thessley_auth_id=' . rawurlencode( $request_id ) );
	}

	/**
	 * Fallback page for the QR/link's https URL, for a human who opens it
	 * some other way than the app's own scanner/tap handling (see the
	 * docblock above this section).
	 */
	public static function maybe_render_auth_page() {
		$type = get_query_var( 'thessley_auth_type' );
		$id   = get_query_var( 'thessley_auth_id' );

		if ( ! $type || ! $id ) {
			return;
		}

		$request = Thessley_Passkey_Store::get_request( $id );

		nocache_headers();
		header( 'Content-Type: text/html; charset=utf-8' );

		if ( ! $request || $request->type !== $type || strtotime( $request->expires_at . ' UTC' ) < time() ) {
			status_header( 410 );
			echo '<!doctype html><meta charset="utf-8"><title>Expired</title><p>This login/enrollment request has expired. Go back and try again.</p>';
			exit;
		}

		if ( '2fa' === $type ) {
			self::render_2fa_page( $request );
			exit;
		}

		printf(
			'<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>%1$s</title>' .
			'<p>Open this on the device with the %2$s app installed to continue.</p>' .
			'<p><a href="%3$s">Get the app</a></p>',
			esc_html( get_bloginfo( 'name' ) ),
			esc_html( get_bloginfo( 'name' ) ),
			esc_url( 'https://play.google.com/store/apps/details?id=' . self::app_package_id() )
		);
		exit;
	}

	/**
	 * Unlike a plain login/enroll request — which shows its QR on the page
	 * that started it (wp-login.php, profile.php) and only falls back to
	 * this route if the app failed to intercept the link — a 2fa request
	 * has nowhere else to be shown: the password form redirects here
	 * directly, so this page has to be the real confirmation UI, not just
	 * a fallback message.
	 */
	private static function render_2fa_page( $request ) {
		$app_link  = self::app_link( '2fa', $request->request_id, $request->nonce );
		$rest_base = esc_url_raw( rest_url( 'thessley/v1/passkey/login' ) );
		$qr_src    = esc_url( THESSLEY_PLUGIN_URL . 'assets/vendor/qrcode.min.js' );
		?>
		<!doctype html>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width,initial-scale=1">
		<title><?php echo esc_html( get_bloginfo( 'name' ) ); ?> — confirm login</title>
		<div style="max-width:360px;margin:40px auto;padding:16px;font-family:sans-serif;text-align:center">
			<h1 style="font-size:1.1em"><?php echo esc_html( get_bloginfo( 'name' ) ); ?></h1>
			<p>Your password was correct. Confirm with the app to finish logging in.</p>
			<div id="thessley-2fa-qr" style="display:inline-block;line-height:0"></div>
			<p><a href="<?php echo esc_attr( $app_link ); ?>">Open on this device</a></p>
			<p id="thessley-2fa-status" style="color:#666"></p>
		</div>
		<script src="<?php echo $qr_src; ?>"></script>
		<script>
		(function () {
			new QRCode(document.getElementById('thessley-2fa-qr'), { text: <?php echo wp_json_encode( $app_link ); ?>, width: 200, height: 200 });

			var statusEl = document.getElementById('thessley-2fa-status');
			var poll = setInterval(function () {
				fetch(<?php echo wp_json_encode( esc_url_raw( $rest_base . '/' . $request->request_id . '/status' ) ); ?>)
					.then(function (r) { return r.json(); })
					.then(function (s) {
						if (s.status === 'approved') { clearInterval(poll); window.location.href = s.redirect_to; }
						if (s.status === 'denied' || s.status === 'expired') { clearInterval(poll); statusEl.textContent = 'Request ' + s.status + ' — log in again to retry.'; }
					});
			}, 1500);
		})();
		</script>
		<?php
	}

	// --- REST API --------------------------------------------------------

	public static function register_routes() {
		register_rest_route(
			'thessley/v1',
			'/passkey/login/start',
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'rest_login_start' ),
				'permission_callback' => '__return_true',
			)
		);

		register_rest_route(
			'thessley/v1',
			'/passkey/login/(?P<id>[\w-]+)/status',
			array(
				'methods'             => 'GET',
				'callback'            => array( __CLASS__, 'rest_login_status' ),
				'permission_callback' => '__return_true',
			)
		);

		register_rest_route(
			'thessley/v1',
			'/passkey/login/(?P<id>[\w-]+)/respond',
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'rest_login_respond' ),
				'permission_callback' => '__return_true',
			)
		);

		register_rest_route(
			'thessley/v1',
			'/passkey/enroll/start',
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'rest_enroll_start' ),
				'permission_callback' => function () {
					return is_user_logged_in();
				},
			)
		);

		register_rest_route(
			'thessley/v1',
			'/passkey/enroll/(?P<id>[\w-]+)/status',
			array(
				'methods'             => 'GET',
				'callback'            => array( __CLASS__, 'rest_enroll_status' ),
				'permission_callback' => function () {
					return is_user_logged_in();
				},
			)
		);

		register_rest_route(
			'thessley/v1',
			'/passkey/enroll/(?P<id>[\w-]+)/respond',
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'rest_enroll_respond' ),
				'permission_callback' => '__return_true',
			)
		);
	}

	private static function rate_limited( $bucket ) {
		$ip  = thessley_client_ip();
		$key = 'thessley_pk_rl_' . $bucket . '_' . md5( $ip );
		$n   = (int) get_transient( $key );

		if ( $n >= self::RATE_LIMIT_MAX ) {
			return true;
		}

		set_transient( $key, $n + 1, self::RATE_LIMIT_WINDOW );
		return false;
	}

	public static function rest_login_start( WP_REST_Request $req ) {
		if ( ! self::enabled() ) {
			return new WP_Error( 'thessley_passkey_disabled', 'Passkey login is not enabled on this site.', array( 'status' => 403 ) );
		}
		if ( self::rate_limited( 'login_start' ) ) {
			return new WP_Error( 'thessley_rate_limited', 'Too many requests.', array( 'status' => 429 ) );
		}

		$result             = Thessley_Passkey_Store::create_request( 'login', null, self::LOGIN_TTL );
		$result['url']      = self::auth_url( 'login', $result['request_id'] );
		$result['app_link'] = self::app_link( 'login', $result['request_id'], $result['nonce'] );

		return rest_ensure_response( $result );
	}

	public static function rest_login_status( WP_REST_Request $req ) {
		$id      = $req->get_param( 'id' );
		$request = Thessley_Passkey_Store::get_request( $id );

		if ( ! $request || ! in_array( $request->type, array( 'login', '2fa' ), true ) ) {
			return rest_ensure_response( array( 'status' => 'expired' ) );
		}
		if ( strtotime( $request->expires_at . ' UTC' ) < time() && 'pending' === $request->status ) {
			return rest_ensure_response( array( 'status' => 'expired' ) );
		}

		if ( 'approved' === $request->status ) {
			// First (and only) time this flips to "approved" for the poller:
			// establish the real WP session, then consume the row so a
			// captured/replayed copy of this response can't do it again.
			wp_set_auth_cookie( (int) $request->approver_user_id, false );
			do_action( 'wp_login', get_userdata( (int) $request->approver_user_id )->user_login, get_userdata( (int) $request->approver_user_id ) );
			Thessley_Passkey_Store::consume_request( $id );

			thessley_log_event( 'passkey-login', 'login_approved', 'noted', 'user #' . (int) $request->approver_user_id );

			return rest_ensure_response(
				array(
					'status'      => 'approved',
					'redirect_to' => admin_url(),
				)
			);
		}

		if ( 'consumed' === $request->status ) {
			// Someone polled again after the cookie was already issued once.
			return rest_ensure_response( array( 'status' => 'expired' ) );
		}

		return rest_ensure_response( array( 'status' => $request->status ) ); // pending | denied
	}

	public static function rest_login_respond( WP_REST_Request $req ) {
		$id        = $req->get_param( 'id' );
		$cred_id   = (string) $req->get_param( 'credential_id' );
		$action    = (string) $req->get_param( 'action' );
		$timestamp = (int) $req->get_param( 'timestamp' );
		$signature = (string) $req->get_param( 'signature' );

		if ( ! in_array( $action, array( 'approve', 'deny' ), true ) ) {
			return new WP_Error( 'thessley_bad_request', 'Invalid action.', array( 'status' => 400 ) );
		}

		$request = Thessley_Passkey_Store::get_request( $id );
		if ( ! $request || ! in_array( $request->type, array( 'login', '2fa' ), true ) || 'pending' !== $request->status
			|| strtotime( $request->expires_at . ' UTC' ) < time() ) {
			return new WP_Error( 'thessley_expired', 'This request is no longer valid.', array( 'status' => 409 ) );
		}

		if ( ! Thessley_Passkey_Crypto::timestamp_fresh( $timestamp ) ) {
			return new WP_Error( 'thessley_stale', 'Timestamp out of range.', array( 'status' => 401 ) );
		}

		$passkey = Thessley_Passkey_Store::get_passkey_by_credential( $cred_id );
		if ( ! $passkey ) {
			return new WP_Error( 'thessley_unknown_device', 'Unknown or revoked device.', array( 'status' => 401 ) );
		}

		// A 2fa request already knows who's logging in (the password step
		// identified them) — unlike a plain login request, where whichever
		// device approves IS the identification. Only that same user's own
		// device may resolve it.
		if ( '2fa' === $request->type && (int) $request->requester_user_id !== (int) $passkey->user_id ) {
			thessley_log_event( 'passkey-login', 'signature_invalid', 'blocked', 'credential ' . $cred_id . ' tried to confirm another user\'s 2fa request' );
			return new WP_Error( 'thessley_wrong_account', 'This device belongs to a different account.', array( 'status' => 403 ) );
		}

		// The real enforcement boundary for the 2fa-bypass this module
		// used to have: hiding the anonymous-login toggle in the UI only
		// stops someone *clicking* it — anyone who knows this endpoint
		// exists could still call it directly. A plain 'login'-type
		// approval (anonymous: whichever device responds identifies the
		// user) is exactly as strong as a single factor, so it can never
		// be allowed to finish a login for an account whose effective
		// mode is '2fa' — that mode's entire point is requiring both.
		// 'required' is unaffected: app-alone login is what that mode
		// *is*, not something to guard against.
		if ( 'login' === $request->type && 'approve' === $action
			&& '2fa' === self::effective_mode_for_user( (int) $passkey->user_id ) ) {
			thessley_log_event( 'passkey-login', 'anonymous_login_blocked', 'blocked', 'credential ' . $cred_id . ' — account requires password first' );
			return new WP_Error(
				'thessley_2fa_required',
				'This account requires your password first — log in with it, then confirm with the app.',
				array( 'status' => 403 )
			);
		}

		$message = Thessley_Passkey_Crypto::canonical_string( $request->type, $id, home_url(), $request->nonce, $timestamp, $action );

		if ( ! Thessley_Passkey_Crypto::verify( $passkey->public_key, $message, $signature ) ) {
			thessley_log_event( 'passkey-login', 'signature_invalid', 'blocked', 'credential ' . $cred_id );
			return new WP_Error( 'thessley_bad_signature', 'Signature verification failed.', array( 'status' => 401 ) );
		}

		Thessley_Passkey_Store::bump_counter_and_touch( self::passkey_row_id( $passkey ), $passkey->counter + 1 );

		if ( 'deny' === $action ) {
			Thessley_Passkey_Store::resolve_request( $id, 'denied', $passkey->user_id, self::passkey_row_id( $passkey ) );
			thessley_log_event( 'passkey-login', 'login_denied', 'noted', 'user #' . $passkey->user_id . ' denied a login attempt not initiated by them' );
			return rest_ensure_response( array( 'result' => 'ok' ) );
		}

		$resolved = Thessley_Passkey_Store::resolve_request( $id, 'approved', $passkey->user_id, self::passkey_row_id( $passkey ) );
		if ( ! $resolved ) {
			return new WP_Error( 'thessley_already_resolved', 'This request was already resolved.', array( 'status' => 409 ) );
		}

		return rest_ensure_response( array( 'result' => 'ok' ) );
	}

	public static function rest_enroll_start( WP_REST_Request $req ) {
		if ( ! self::enabled() ) {
			return new WP_Error( 'thessley_passkey_disabled', 'Passkey login is not enabled on this site.', array( 'status' => 403 ) );
		}

		$result             = Thessley_Passkey_Store::create_request( 'enroll', get_current_user_id(), self::ENROLL_TTL );
		$result['url']      = self::auth_url( 'enroll', $result['request_id'] );
		$result['app_link'] = self::app_link( 'enroll', $result['request_id'], $result['nonce'] );

		return rest_ensure_response( $result );
	}

	public static function rest_enroll_status( WP_REST_Request $req ) {
		$id      = $req->get_param( 'id' );
		$request = Thessley_Passkey_Store::get_request( $id );

		if ( ! $request || 'enroll' !== $request->type || (int) $request->requester_user_id !== get_current_user_id() ) {
			return new WP_Error( 'thessley_not_found', 'Not found.', array( 'status' => 404 ) );
		}
		if ( strtotime( $request->expires_at . ' UTC' ) < time() && 'pending' === $request->status ) {
			return rest_ensure_response( array( 'status' => 'expired' ) );
		}

		$response = array( 'status' => $request->status );

		if ( 'approved' === $request->status && $request->credential_id ) {
			$passkey = Thessley_Passkey_Store::get_passkey_by_credential( self::credential_string_for_row( $request->credential_id ) );
			$response['label'] = $passkey ? $passkey->label : '';
		}

		return rest_ensure_response( $response );
	}

	public static function rest_enroll_respond( WP_REST_Request $req ) {
		if ( self::rate_limited( 'enroll_respond' ) ) {
			return new WP_Error( 'thessley_rate_limited', 'Too many requests.', array( 'status' => 429 ) );
		}

		$id         = $req->get_param( 'id' );
		$public_key = (string) $req->get_param( 'public_key' );
		$algorithm  = (string) $req->get_param( 'algorithm' );
		$label      = (string) $req->get_param( 'label' );
		$timestamp  = (int) $req->get_param( 'timestamp' );
		$proof      = (string) $req->get_param( 'proof_signature' );

		$request = Thessley_Passkey_Store::get_request( $id );
		if ( ! $request || 'enroll' !== $request->type || 'pending' !== $request->status
			|| strtotime( $request->expires_at . ' UTC' ) < time() ) {
			return new WP_Error( 'thessley_expired', 'This request is no longer valid.', array( 'status' => 409 ) );
		}
		if ( ! Thessley_Passkey_Crypto::timestamp_fresh( $timestamp ) ) {
			return new WP_Error( 'thessley_stale', 'Timestamp out of range.', array( 'status' => 401 ) );
		}
		if ( ! $public_key ) {
			return new WP_Error( 'thessley_bad_request', 'Missing public key.', array( 'status' => 400 ) );
		}

		// Proof of possession: the app signs with the *new* private key it
		// just generated, over the same canonical-string shape used
		// everywhere else (type=enroll, action=register) — proves the
		// submitted public key has a matching private key the app
		// actually holds, the same thing WebAuthn's registration-time
		// clientDataJSON signature proves.
		$message = Thessley_Passkey_Crypto::canonical_string( 'enroll', $id, home_url(), $request->nonce, $timestamp, 'register' );

		if ( ! Thessley_Passkey_Crypto::verify( $public_key, $message, $proof ) ) {
			thessley_log_event( 'passkey-login', 'signature_invalid', 'blocked', 'enroll proof-of-possession failed' );
			return new WP_Error( 'thessley_bad_signature', 'Proof of possession failed.', array( 'status' => 401 ) );
		}

		$credential_id = Thessley_Passkey_Store::add_passkey( (int) $request->requester_user_id, $public_key, $algorithm, $label );
		$row_id        = Thessley_Passkey_Store::get_passkey_row_id( $credential_id );

		$resolved = Thessley_Passkey_Store::resolve_request( $id, 'approved', (int) $request->requester_user_id, $row_id );
		if ( ! $resolved ) {
			return new WP_Error( 'thessley_already_resolved', 'This request was already resolved.', array( 'status' => 409 ) );
		}

		thessley_log_event( 'passkey-login', 'enroll_approved', 'noted', 'user #' . (int) $request->requester_user_id . ' added device "' . sanitize_text_field( $label ) . '"' );

		// The app needs this for every future login/respond call — it has
		// no other way to learn the server-assigned credential_id, since
		// it necessarily generated its local keypair before this request
		// (the server can't hand out an id for a key it hasn't verified
		// possession of yet).
		return rest_ensure_response(
			array(
				'result'        => 'ok',
				'credential_id' => $credential_id,
			)
		);
	}

	/** $request->credential_id stores the passkeys.id row id, not the credential_id string — this resolves one to the other for display. */
	private static function credential_string_for_row( $row_id ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name, not user input.
		return $wpdb->get_var( $wpdb->prepare( 'SELECT credential_id FROM ' . Thessley_Passkey_Store::passkeys_table() . ' WHERE id = %d', $row_id ) );
	}

	private static function passkey_row_id( $passkey ) {
		return (int) $passkey->id;
	}

	// --- wp-login.php integration ----------------------------------------

	/** render_profile_section()'s inline <script> (below) relies on the global QRCode this defines — profile.php/user-edit.php only, not every admin page. */
	public static function profile_page_assets( $hook ) {
		if ( ! self::enabled() || ! in_array( $hook, array( 'profile.php', 'user-edit.php' ), true ) ) {
			return;
		}
		wp_enqueue_script( 'thessley-qrcodejs', THESSLEY_PLUGIN_URL . 'assets/vendor/qrcode.min.js', array(), THESSLEY_VERSION, true );
	}

	/**
	 * One static screen per site mode, decided before anyone has typed
	 * anything — no username-first step, no toggle to click:
	 *  - optional: password form AND the QR shown together, QR already
	 *              polling. Either one logs you in; whichever a visitor
	 *              reaches for first works. This also happens to cover a
	 *              user whose *personal* mode is stricter than this site
	 *              default (effective_mode_for_user() can return '2fa' or
	 *              'required' even on an 'optional' site) — the QR is
	 *              already right there either way, nothing extra needed.
	 *  - 2fa:      password form only. The QR is deliberately not offered
	 *              here at all — see rest_login_respond()'s docblock on
	 *              why an anonymous app-only approval must never be
	 *              enough to finish a login for a 2fa account. That
	 *              enforcement lives server-side, not in this screen, but
	 *              there's no reason to invite the attempt either.
	 *  - required: QR only, already polling, password form hidden by CSS
	 *              — nothing else on the page. An account with no device
	 *              yet still technically needs a password to get in, with
	 *              no UI route to it here; that's a deliberate choice by
	 *              whoever sets this to 'required', not an oversight.
	 */
	public static function login_head_styles() {
		if ( 'required' === self::mode() ) {
			echo '<style>#loginform{display:none}</style>';
		}
	}

	public static function login_page_assets() {
		if ( '2fa' === self::mode() ) {
			return; // password form only — see login_head_styles()'s docblock
		}

		wp_enqueue_script( 'thessley-qrcodejs', THESSLEY_PLUGIN_URL . 'assets/vendor/qrcode.min.js', array(), THESSLEY_VERSION, true );

		wp_register_script( 'thessley-passkey-login', false, array( 'thessley-qrcodejs' ), THESSLEY_VERSION, true );
		wp_enqueue_script( 'thessley-passkey-login' );

		$rest_base = esc_url_raw( rest_url( 'thessley/v1/passkey/login' ) );

		wp_add_inline_script(
			'thessley-passkey-login',
			"(function(){\n" .
			"  var box = document.getElementById('thessley-passkey-box');\n" .
			"  if (!box) return;\n" .
			"  fetch('{$rest_base}/start', {method:'POST'}).then(function(r){return r.json();}).then(function(data){\n" .
			"    new QRCode(document.getElementById('thessley-passkey-qr'), {text: data.app_link, width: 180, height: 180});\n" .
			"    var linkEl = document.getElementById('thessley-passkey-link');\n" .
			"    if (linkEl) { linkEl.href = data.app_link; }\n" .
			"    var poll = setInterval(function(){\n" .
			"      fetch('{$rest_base}/' + data.request_id + '/status').then(function(r){return r.json();}).then(function(s){\n" .
			"        if (s.status === 'approved') { clearInterval(poll); window.location.href = s.redirect_to; }\n" .
			"        if (s.status === 'denied' || s.status === 'expired') { clearInterval(poll); box.textContent = 'Request ' + s.status + ' — refresh to try again.'; }\n" .
			"      });\n" .
			"    }, 1500);\n" .
			"  });\n" .
			'})();'
		);
	}

	/** Hooked to 'login_footer', not 'login_form' — 'login_form' fires inside the password <form>, which both looks wrong and risks the same nested-element problems invalid markup causes elsewhere in this module. */
	public static function login_form_markup() {
		if ( '2fa' === self::mode() ) {
			return;
		}
		?>
		<div id="thessley-passkey-box" style="margin:12px 0;padding:12px;border:1px solid #dcdcde;border-radius:4px;text-align:center">
			<p class="description">Scan this code with the <?php echo esc_html( get_bloginfo( 'name' ) ); ?> app, or open it on this device.</p>
			<div id="thessley-passkey-qr" style="display:inline-block;line-height:0"></div>
			<p><a id="thessley-passkey-link" href="#">Open on this device</a></p>
		</div>
		<?php
	}

	// --- Settings page (Perimeter cluster) --------------------------------

	public static function handle_save_settings() {
		check_admin_referer( 'thessley_pk_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		$posted = (string) ( $_POST['mode'] ?? '' );
		$mode   = in_array( $posted, array( '2fa', 'required' ), true ) ? $posted : 'optional';

		update_option( 'thessley_passkey_enabled', isset( $_POST['enabled'] ) );
		update_option( 'thessley_passkey_mode', $mode );

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function render_page() {
		$enabled = self::enabled();
		$mode    = self::mode();

		Thessley_UI::open( 'passkey-login' );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only result flag set only by this module's own admin-post redirect, which already check_admin_referer()'d before redirecting.
		if ( isset( $_GET['saved'] ) ) {
			Thessley_UI::notice( 'success', 'Settings saved.' );
		}

		Thessley_UI::notice(
			'info',
			'The server-side protocol, REST endpoints, device storage, signature verification, and QR rendering are all in place. The companion Android app is a separate project — see this module\'s docblock.',
			true
		);

		Thessley_UI::section( 'Settings', 'admin-generic' );
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'thessley_pk_save_settings' ); ?>
			<input type="hidden" name="action" value="thessley_pk_save_settings">

			<?php
			Thessley_UI::row(
				'Enabled',
				function () use ( $enabled ) {
					?>
					<label><input type="checkbox" name="enabled" <?php checked( $enabled ); ?>> Allow passwordless login via the app</label>
					<?php
				}
			);

			Thessley_UI::row(
				'Login method',
				function () use ( $mode ) {
					?>
					<label><input type="radio" name="mode" value="optional" <?php checked( 'optional', $mode ); ?>> Password — the login page shows the normal password form only</label><br>
					<label><input type="radio" name="mode" value="2fa" <?php checked( '2fa', $mode ); ?>> Password, then app — password first, the app confirms it afterward</label><br>
					<label><input type="radio" name="mode" value="required" <?php checked( 'required', $mode ); ?>> App only — the login page shows a QR code only, no password form</label>
					<?php
				},
				'A user with no device enrolled always falls back to plain password, regardless of this setting — there is nothing to confirm with yet. A user can also set a stricter method than this for just their own account on their profile page, but never a looser one.'
			);

			submit_button( 'Save settings' );
			?>
		</form>
		<?php
		Thessley_UI::section_end();
		Thessley_UI::close();
	}

	// --- Profile page: per-user device list -------------------------------

	public static function render_profile_section( $user ) {
		if ( ! self::enabled() ) {
			return;
		}

		$devices    = Thessley_Passkey_Store::devices_for_user( $user->ID );
		$has_device = self::user_has_active_device( $user->ID );
		$can_edit   = get_current_user_id() === (int) $user->ID || current_user_can( 'manage_options' );
		?>
		<h2>Passkey devices</h2>
		<table class="form-table">
			<?php // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only result flag set only by this module's own admin-post redirect, which already check_admin_referer()'d before redirecting. ?>
			<?php if ( isset( $_GET['thessley_pk_saved'] ) ) : ?>
				<tr><td colspan="2"><div class="notice notice-success inline"><p>Login method updated.</p></div></td></tr>
			<?php endif; ?>
			<tr>
				<th>Login method</th>
				<td>
					<?php
					$preferred = self::user_preferred_mode( $user->ID );
					$labels    = array(
						'optional' => 'Password or the app',
						'2fa'      => 'Password, then app confirmation',
						'required' => 'App only — password login disabled',
					);
					?>
					<?php if ( ! $has_device ) : ?>
						<p class="description">Add a device below to choose how this account logs in.</p>
					<?php elseif ( $can_edit ) : ?>
						<div id="thessley-pk-mode-box">
							<?php foreach ( $labels as $value => $label ) : ?>
								<label><input type="radio" name="thessley_user_mode" value="<?php echo esc_attr( $value ); ?>" <?php checked( $value, $preferred ); ?>> <?php echo esc_html( $label ); ?></label><br>
							<?php endforeach; ?>
							<?php submit_button( 'Save', 'secondary', 'thessley-pk-mode-save', false, array( 'type' => 'button', 'style' => 'margin-top:8px' ) ); ?>
							<p id="thessley-pk-mode-status" class="description"></p>
						</div>
						<script>
						(function () {
							// A plain <form> here would nest inside WordPress core's
							// own #your-profile form (profile.php/user-edit.php wrap
							// show_user_profile/edit_user_profile entirely inside it) —
							// HTML doesn't allow nested forms, so the browser collapses
							// them into one, and both forms' same-named _wpnonce fields
							// collide: whichever value survives gets checked against
							// the WRONG action, failing core's own profile-save nonce
							// check with "Link expired". Submitting via fetch() instead
							// avoids creating a second <form> at all.
							var box = document.getElementById('thessley-pk-mode-box');
							var btn = document.getElementById('thessley-pk-mode-save');
							var status = document.getElementById('thessley-pk-mode-status');

							btn.addEventListener('click', function () {
								var mode = box.querySelector('input[name="thessley_user_mode"]:checked').value;
								btn.disabled = true;
								status.textContent = 'Saving…';

								var body = new URLSearchParams({
									action: 'thessley_pk_save_user_mode',
									user_id: <?php echo (int) $user->ID; ?>,
									user_mode: mode,
									_wpnonce: <?php echo wp_json_encode( wp_create_nonce( 'thessley_pk_save_user_mode_' . $user->ID ) ); ?>,
								});

								fetch(<?php echo wp_json_encode( esc_url_raw( admin_url( 'admin-post.php' ) ) ); ?>, {
									method: 'POST',
									headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
									body: body,
								}).then(function () {
									status.textContent = 'Saved.';
									btn.disabled = false;
								}).catch(function () {
									status.textContent = 'Something went wrong — try again.';
									btn.disabled = false;
								});
							});
						})();
						</script>
					<?php else : ?>
						<p class="description"><?php echo esc_html( $labels[ $preferred ] ); ?></p>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<th>Enrolled devices</th>
				<td>
					<?php if ( empty( $devices ) ) : ?>
						<p class="description">No devices enrolled yet.</p>
					<?php else : ?>
						<table class="widefat" style="max-width:600px">
							<thead><tr><th>Label</th><th>Added</th><th>Last used</th><th>Status</th><th></th></tr></thead>
							<tbody>
							<?php foreach ( $devices as $d ) : ?>
								<tr>
									<td><?php echo esc_html( $d->label ?: 'Unnamed device' ); ?></td>
									<td><?php echo esc_html( mysql2date( 'M j, Y', $d->created_at ) ); ?></td>
									<td><?php echo $d->last_used_at ? esc_html( mysql2date( 'M j, Y H:i', $d->last_used_at ) ) : '—'; ?></td>
									<td><?php echo $d->revoked_at ? 'Revoked' : 'Active'; ?></td>
									<td>
										<?php if ( ! $d->revoked_at && ( get_current_user_id() === (int) $user->ID || current_user_can( 'manage_options' ) ) ) : ?>
											<?php // No <form> here — see the Login method script's comment on why nested forms inside profile.php/user-edit.php break WordPress core's own nonce check. ?>
											<button type="button" class="button button-small thessley-pk-revoke-btn"
												data-id="<?php echo esc_attr( $d->id ); ?>"
												data-user-id="<?php echo esc_attr( $user->ID ); ?>"
												data-nonce="<?php echo esc_attr( wp_create_nonce( 'thessley_pk_revoke_' . $d->id ) ); ?>">Revoke</button>
										<?php endif; ?>
									</td>
								</tr>
							<?php endforeach; ?>
							</tbody>
						</table>
						<script>
						(function () {
							document.querySelectorAll('.thessley-pk-revoke-btn').forEach(function (btn) {
								btn.addEventListener('click', function () {
									btn.disabled = true;
									var body = new URLSearchParams({
										action: 'thessley_pk_revoke',
										id: btn.dataset.id,
										user_id: btn.dataset.userId,
										_wpnonce: btn.dataset.nonce,
									});
									fetch(<?php echo wp_json_encode( esc_url_raw( admin_url( 'admin-post.php' ) ) ); ?>, {
										method: 'POST',
										headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
										body: body,
									}).then(function () { window.location.reload(); })
									  .catch(function () { btn.disabled = false; });
								});
							});
						})();
						</script>
					<?php endif; ?>

					<?php if ( get_current_user_id() === (int) $user->ID ) : ?>
						<div id="thessley-pk-enroll-box" style="margin-top:14px">
							<button type="button" class="button" id="thessley-pk-enroll-start">Add a device</button>
							<div id="thessley-pk-enroll-qr" style="display:none;margin-top:10px;line-height:0"></div>
							<p id="thessley-pk-enroll-status" class="description" style="margin-top:8px"></p>
						</div>
						<p class="description" style="margin-top:4px">
							Scan the code with the device you're enrolling, or open the link on that same device.
						</p>
						<script>
						(function(){
							var btn = document.getElementById('thessley-pk-enroll-start');
							var status = document.getElementById('thessley-pk-enroll-status');
							var qrBox = document.getElementById('thessley-pk-enroll-qr');
							var restBase = <?php echo wp_json_encode( esc_url_raw( rest_url( 'thessley/v1/passkey/enroll' ) ) ); ?>;
							var nonce = <?php echo wp_json_encode( wp_create_nonce( 'wp_rest' ) ); ?>;

							btn.addEventListener('click', function () {
								btn.disabled = true;
								status.textContent = 'Starting…';

								fetch(restBase + '/start', {
									method: 'POST',
									headers: { 'X-WP-Nonce': nonce },
								}).then(function (r) { return r.json(); }).then(function (data) {
									qrBox.style.display = 'block';
									qrBox.innerHTML = '';
									new QRCode(qrBox, { text: data.app_link, width: 160, height: 160 });
									status.innerHTML = 'Or open on the device you want to enroll: <a href="' + data.app_link + '">' + data.app_link + '</a>';

									var poll = setInterval(function () {
										fetch(restBase + '/' + data.request_id + '/status', {
											headers: { 'X-WP-Nonce': nonce },
										}).then(function (r) { return r.json(); }).then(function (s) {
											if (s.status === 'approved') {
												clearInterval(poll);
												status.textContent = 'Added "' + (s.label || 'device') + '". Reload this page to see it in the list.';
												btn.disabled = false;
											} else if (s.status === 'expired') {
												clearInterval(poll);
												status.textContent = 'Request expired — try again.';
												btn.disabled = false;
											}
										});
									}, 1500);
								});
							});
						})();
						</script>
					<?php endif; ?>
				</td>
			</tr>
		</table>
		<?php
	}

	public static function handle_revoke() {
		$id = (int) ( $_POST['id'] ?? 0 );
		check_admin_referer( 'thessley_pk_revoke_' . $id );

		$target_user_id = (int) ( $_POST['user_id'] ?? 0 );

		if ( get_current_user_id() !== $target_user_id && ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		Thessley_Passkey_Store::revoke( $id, $target_user_id );
		thessley_log_event( 'passkey-login', 'device_revoked', 'noted', 'device #' . $id . ' for user #' . $target_user_id );

		wp_safe_redirect( wp_get_referer() );
		exit;
	}

	public static function handle_save_user_mode() {
		$target_user_id = (int) ( $_POST['user_id'] ?? 0 );
		check_admin_referer( 'thessley_pk_save_user_mode_' . $target_user_id );

		if ( get_current_user_id() !== $target_user_id && ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		// A user with no active device can't meaningfully choose
		// Neither 2fa nor required mean anything without a device to
		// confirm with — there'd be nothing to log in with. Silently fall
		// back to 'optional' rather than trusting a posted value for a
		// state the UI never actually offers them.
		$posted = (string) ( $_POST['user_mode'] ?? '' );
		$mode   = ( self::user_has_active_device( $target_user_id ) && in_array( $posted, array( '2fa', 'required' ), true ) )
			? $posted
			: 'optional';

		update_user_meta( $target_user_id, 'thessley_passkey_user_mode', $mode );
		thessley_log_event( 'passkey-login', 'user_mode_changed', 'noted', 'user #' . $target_user_id . ' set to "' . $mode . '"' );

		wp_safe_redirect( add_query_arg( 'thessley_pk_saved', '1', wp_get_referer() ) );
		exit;
	}

	/**
	 * Runs after core's own 'authenticate' callback has already validated
	 * the password (priority 20) and returned a real WP_User — this only
	 * steps in once we know the password itself was correct, so a wrong
	 * password still gets WordPress's normal "incorrect password" error
	 * rather than this one.
	 *
	 * @param WP_User|WP_Error|null $user
	 * @return WP_User|WP_Error|null
	 */
	public static function maybe_block_password_login( $user ) {
		if ( ! ( $user instanceof WP_User ) ) {
			return $user; // already an error (wrong password/unknown user), or no credentials submitted — nothing to do
		}

		$mode = self::effective_mode_for_user( $user->ID );

		if ( 'optional' === $mode ) {
			return $user;
		}

		if ( 'required' === $mode ) {
			thessley_log_event( 'passkey-login', 'password_login_blocked', 'blocked', 'user #' . $user->ID . ' — passkey-only' );

			return new WP_Error(
				'thessley_passkey_required',
				sprintf(
					/* translators: %s: site name */
					__( '<strong>Password login is disabled for this account.</strong> Use the %s app to log in.', 'thessley-security-hardening' ),
					esc_html( get_bloginfo( 'name' ) )
				)
			);
		}

		// '2fa': the password was correct, but login isn't finished yet —
		// this bypasses wp_signon()'s normal completion entirely (no
		// cookie set here) and sends the browser to an app-confirmation
		// page instead. That page is bound to this exact user_id, so only
		// their own enrolled device(s) can approve it — unlike a plain
		// login request, which doesn't know who's logging in until a
		// device claims it (see this module's docblock on the BankID-
		// style identification model; a 2fa request is deliberately the
		// opposite of that, since the password step already identified
		// the user).
		//
		// The 'authenticate' filter also fires for XML-RPC and any other
		// password-based login path, not just wp-login.php's own form —
		// those callers expect a structured success/failure result, not
		// an HTTP redirect, so only actually redirect when this really is
		// the login form; everything else gets a plain rejection instead,
		// same shape as 'required' mode's.
		if ( 'wp-login.php' !== $GLOBALS['pagenow'] ) {
			thessley_log_event( 'passkey-login', 'password_login_blocked', 'blocked', 'user #' . $user->ID . ' — 2fa required, non-browser login context' );

			return new WP_Error(
				'thessley_passkey_2fa_required',
				sprintf(
					/* translators: %s: site name */
					__( '<strong>This account requires app confirmation.</strong> Log in through the website and use the %s app to finish.', 'thessley-security-hardening' ),
					esc_html( get_bloginfo( 'name' ) )
				)
			);
		}

		$result = Thessley_Passkey_Store::create_request( '2fa', $user->ID, self::LOGIN_TTL );

		thessley_log_event( 'passkey-login', 'password_step_ok', 'noted', 'user #' . $user->ID . ' — awaiting app confirmation' );

		wp_safe_redirect( self::auth_url( '2fa', $result['request_id'] ) );
		exit;
	}
}
