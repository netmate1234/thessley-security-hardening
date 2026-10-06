<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require_once __DIR__ . '/class-store.php';
require_once __DIR__ . '/class-crypto.php';
require_once __DIR__ . '/class-attestation.php';

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
 * QR codes are rendered as inline SVG (vector, scannable at any size or
 * screen density) by kazuhikoarase/qrcode-generator (MIT), bundled locally
 * at assets/vendor/qrcode-generator.js with a small wrapper,
 * assets/thessley-qr.js, rather than loaded from a CDN — this
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

	/** No separate on/off switch — the three-way "Login method" setting is the only control; 'optional' is the no-op state. */
	public static function enabled() {
		return true;
	}

	/**
	 * Single site-wide setting, the only control — there is deliberately
	 * no per-account override anymore. A per-account choice on top of
	 * this was two controls that could silently drift out of sync with
	 * each other, which is what the login page *displays* vs. what it
	 * *enforces* was built against: the direct cause of nearly every
	 * "the login page shows the wrong thing" report while building this.
	 * One setting applying identically to everyone means the page can
	 * always correctly show the right layout for it, with no identify
	 * step needed, because there's nothing left for the page to get out
	 * of sync with.
	 */
	public static function mode() {
		$mode = get_option( 'thessley_passkey_mode', 'optional' );
		return in_array( $mode, array( 'optional', '2fa', 'required' ), true ) ? $mode : 'optional';
	}

	private static function user_has_active_device( $user_id ) {
		foreach ( Thessley_Passkey_Store::devices_for_user( $user_id ) as $d ) {
			if ( ! $d->revoked_at ) {
				return true;
			}
		}
		return false;
	}

	/** What applies to this user right now: the site mode, unless they have no device yet — nothing to require without one, regardless of the setting. */
	public static function effective_mode_for_user( $user_id ) {
		return self::user_has_active_device( $user_id ) ? self::mode() : 'optional';
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
	/**
	 * @param string $ip The request's own IP (from create_request()'s
	 *                   return value, or $request->ip for an already-
	 *                   stored row) — shown on the app's approval screen
	 *                   so a user asked to blindly approve a *relayed*
	 *                   request (someone else's login, passed off as
	 *                   "scan this to verify you're human") has an actual
	 *                   signal to notice something's wrong, instead of
	 *                   just a static warning with no context at all.
	 */
	/**
	 * @param string $username Only meaningful for 'type' === '2fa', where
	 *                         the password step already identified the
	 *                         account — lets the app auto-pick the right
	 *                         locally-enrolled device for that account
	 *                         instead of guessing, now that a phone can
	 *                         hold more than one enrolled account for the
	 *                         same origin. 'login' requests get nothing
	 *                         here on purpose: that flow is anonymous by
	 *                         design (whichever device approves IS the
	 *                         identification), so there's deliberately no
	 *                         server-known account to pre-select.
	 */
	private static function app_link( $type, $request_id, $nonce, $ip = '', $username = '' ) {
		$params = array(
			'type'   => $type,
			'id'     => $request_id,
			'nonce'  => $nonce,
			'origin' => home_url(),
		);

		if ( '' !== $ip ) {
			$params['ip'] = $ip;
			$country      = self::geo_label_for_ip( $ip );
			if ( '' !== $country ) {
				$params['country'] = $country;
			}
		}

		if ( '' !== $username ) {
			$params['username'] = $username;
		}

		return 'thessleypasskey://auth?' . http_build_query( $params );
	}

	/**
	 * Best-effort country label for the approval-screen context above —
	 * reuses Geo Blocker's own lookup functions, which only exist when
	 * that module is enabled (and its dataset downloaded), so this must
	 * degrade to '' rather than error when either is missing.
	 */
	private static function geo_label_for_ip( $ip ) {
		if ( ! function_exists( 'thessley_geo_lookup' ) || ! function_exists( 'thessley_geo_country_label' ) || ! function_exists( 'thessley_data_file' ) ) {
			return '';
		}

		$needle = ip2long( $ip );
		if ( false === $needle ) {
			return '';
		}

		$idx = thessley_geo_lookup( thessley_data_file( 'geo-country-index.bin' ), $needle );
		return null === $idx ? '' : (string) thessley_geo_country_label( $idx );
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
			'<p>Open this on the device with the Thessley Passkey app installed to continue.</p>' .
			'<p><a href="%2$s">Get the app</a></p>',
			esc_html( get_bloginfo( 'name' ) ),
			esc_url( 'https://play.google.com/store/apps/details?id=' . self::app_package_id() )
		);
		exit;
	}

	/**
	 * Registers (does not print) the QR scripts — the library, then the
	 * ThessleyQR.render() wrapper that depends on it. Every place that draws
	 * a QR depends on the 'thessley-qr' handle.
	 */
	private static function register_qr_scripts() {
		if ( ! wp_script_is( 'thessley-qrcode-generator', 'registered' ) ) {
			wp_register_script( 'thessley-qrcode-generator', THESSLEY_PLUGIN_URL . 'assets/vendor/qrcode-generator.js', array(), THESSLEY_VERSION, true );
			wp_register_script( 'thessley-qr', THESSLEY_PLUGIN_URL . 'assets/thessley-qr.js', array( 'thessley-qrcode-generator' ), THESSLEY_VERSION, true );
		}
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
		$requester  = get_userdata( (int) $request->requester_user_id );
		$app_link   = self::app_link( '2fa', $request->request_id, $request->nonce, $request->ip, $requester ? $requester->user_login : '' );
		$rest_base = esc_url_raw( rest_url( 'thessley/v1/passkey/login' ) );
		?>
		<!doctype html>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width,initial-scale=1">
		<title><?php echo esc_html( get_bloginfo( 'name' ) ); ?> — confirm login</title>
		<div style="max-width:360px;margin:40px auto;padding:16px;font-family:sans-serif;text-align:center">
			<h1 style="font-size:1.1em"><?php echo esc_html( get_bloginfo( 'name' ) ); ?></h1>
			<p>Your password was correct. Confirm with the app to finish logging in.</p>
			<div id="thessley-2fa-qr" style="display:inline-block;line-height:0;background:#fff;padding:12px;border-radius:4px"></div>
			<p><a href="<?php echo esc_attr( $app_link ); ?>">Open on this device</a></p>
			<p id="thessley-2fa-status" style="color:#666"></p>
		</div>
		<?php
		// This standalone page never runs wp_head()/wp_footer(), so the
		// registered scripts are printed explicitly, still through the
		// script API (dependency order, version, escaped URL) rather than
		// a hand-written <script src>.
		self::register_qr_scripts();
		wp_print_scripts( 'thessley-qr' );
		?>
		<script>
		(function () {
			ThessleyQR.render(document.getElementById('thessley-2fa-qr'), <?php echo wp_json_encode( $app_link ); ?>, 300);

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
			'/passkey/devices',
			array(
				'methods'             => 'GET',
				'callback'            => array( __CLASS__, 'rest_devices_html' ),
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
		$result['app_link'] = self::app_link( 'login', $result['request_id'], $result['nonce'], $result['ip'] );

		self::bind_browser_to_request( $result['request_id'] );

		return rest_ensure_response( $result );
	}

	/**
	 * Login-CSRF guard: without this, any browser that knows a
	 * request_id (or forces one to load via e.g. a bare `<img>` tag —
	 * no click needed) could GET /login/{id}/status itself and receive
	 * the resulting auth cookie once the real device approves it. Not
	 * account takeover — the attacker already needed their own device
	 * to approve their own request — but it plants *that* session into
	 * an unrelated victim's browser, the same class of problem a normal
	 * form nonce prevents for a POST. Binds the one browser that called
	 * *_start() as the only one allowed to actually receive the cookie
	 * for that specific request, the same way wp_login.php's own nonce
	 * binds a login POST to the page that rendered its form.
	 *
	 * A transient (not a DB column) because these tokens are exactly as
	 * short-lived as the request itself — no migration needed for
	 * something that's gone in under two minutes either way.
	 */
	private static function bind_browser_to_request( $request_id ) {
		$token = bin2hex( random_bytes( 16 ) );
		set_transient( 'thessley_pk_bt_' . $request_id, $token, self::LOGIN_TTL + 30 );
		setcookie(
			'thessley_pk_bt',
			$token,
			array(
				'expires'  => time() + self::LOGIN_TTL + 30,
				'path'     => '/',
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Strict',
			)
		);
	}

	/** @return bool Whether the calling browser is the one bind_browser_to_request() bound this request_id to. */
	private static function browser_matches_request( $request_id ) {
		$expected = get_transient( 'thessley_pk_bt_' . $request_id );
		$actual   = isset( $_COOKIE['thessley_pk_bt'] ) ? (string) $_COOKIE['thessley_pk_bt'] : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- compared with hash_equals() below, never echoed or used otherwise.

		return is_string( $expected ) && '' !== $expected && '' !== $actual && hash_equals( $expected, $actual );
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
			// Only the browser bind_browser_to_request() bound this
			// request_id to gets the cookie — anyone else polling this
			// same request_id (e.g. a forced background image load from
			// an attacker who approved their own request with their own
			// device) just sees "pending" forever, same as before it was
			// approved. Deliberately doesn't consume the row here: the
			// real browser still needs to be able to complete this on
			// its own next poll.
			if ( ! self::browser_matches_request( $id ) ) {
				thessley_log_event( 'passkey-login', 'login_csrf_blocked', 'blocked', 'request ' . $id . ' — polled by a browser that never called *_start()' );

				return rest_ensure_response( array( 'status' => 'pending' ) );
			}

			// First (and only) time this flips to "approved" for the poller:
			// establish the real WP session, then consume the row so a
			// captured/replayed copy of this response can't do it again.
			delete_transient( 'thessley_pk_bt_' . $id );
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
		$result['app_link'] = self::app_link( 'enroll', $result['request_id'], $result['nonce'], $result['ip'] );

		return rest_ensure_response( $result );
	}

	/** Backs the profile page's live refresh after an enroll/revoke, so the device list updates without a full page reload. */
	public static function rest_devices_html( WP_REST_Request $req ) {
		return rest_ensure_response( array( 'html' => self::render_devices_list_html( wp_get_current_user() ) ) );
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

		$id                = $req->get_param( 'id' );
		$public_key        = (string) $req->get_param( 'public_key' );
		$algorithm         = (string) $req->get_param( 'algorithm' );
		$label             = (string) $req->get_param( 'label' );
		$timestamp         = (int) $req->get_param( 'timestamp' );
		$proof             = (string) $req->get_param( 'proof_signature' );
		$attestation_chain = (array) $req->get_param( 'attestation_chain' );

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
		self::notify_device_enrolled( (int) $request->requester_user_id, $label );
		self::record_attestation( $row_id, $attestation_chain, $request->nonce, $public_key );

		// The app needs this for every future login/respond call — it has
		// no other way to learn the server-assigned credential_id, since
		// it necessarily generated its local keypair before this request
		// (the server can't hand out an id for a key it hasn't verified
		// possession of yet).
		//
		// username is new: the app previously had no idea *which account*
		// a stored device belonged to, which is exactly what made more
		// than one enrolled account on the same site+phone unworkable —
		// nothing to tell them apart by. Stored alongside credential_id
		// so the app can label its device list and, for a 2fa challenge
		// (which already knows who's logging in), pick the matching
		// local device automatically instead of guessing.
		$enrolled_user = get_userdata( (int) $request->requester_user_id );

		return rest_ensure_response(
			array(
				'result'        => 'ok',
				'credential_id' => $credential_id,
				'username'      => $enrolled_user ? $enrolled_user->user_login : '',
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

	/**
	 * The one tripwire against a hijacked WP session being used to enroll
	 * a persistent backdoor device (that session only needs to survive
	 * long enough to add one; the device then keeps working even after a
	 * password change). An attacker with an active session can't stop
	 * this email going to the real account owner's address, which is a
	 * meaningfully different capability than the session itself grants.
	 */
	private static function notify_device_enrolled( $user_id, $label ) {
		$user = get_userdata( $user_id );
		if ( ! $user || ! $user->user_email ) {
			return;
		}

		wp_mail(
			$user->user_email,
			sprintf( '[%s] New passkey device added to your account', get_bloginfo( 'name' ) ),
			sprintf(
				"A new device (\"%s\") was just added to your account (%s) on %s, from IP %s.\n\n" .
				"If this was you, no action is needed.\n\n" .
				"If this wasn't you, log in and remove it immediately from your profile page's \"Passkey devices\" section, then change your password.",
				sanitize_text_field( $label ),
				$user->user_login,
				home_url(),
				thessley_client_ip()
			)
		);
	}

	/**
	 * Verifies the device's Keystore attestation chain and records the
	 * result — but, per Thessley_Passkey_Attestation's own docblock, never
	 * rejects enrollment on it. This is purely visibility for now: the
	 * profile page shows whatever level comes back, and a confirmed
	 * software-only (non-hardware-backed) result is worth knowing about
	 * even before this becomes a hard gate.
	 */
	private static function record_attestation( $row_id, $attestation_chain, $nonce, $public_key ) {
		$result = Thessley_Passkey_Attestation::verify( $attestation_chain, $nonce, $public_key );

		if ( ! $result['ok'] ) {
			Thessley_Passkey_Store::set_attestation_level( $row_id, null );
			thessley_log_event( 'passkey-login', 'attestation_unverified', 'noted', 'device #' . $row_id . ': ' . $result['reason'] );
			return;
		}

		Thessley_Passkey_Store::set_attestation_level( $row_id, $result['security_level_name'] );
		thessley_log_event( 'passkey-login', 'attestation_verified', 'noted', 'device #' . $row_id . ': ' . $result['security_level_name'] );
	}

	// --- wp-login.php integration ----------------------------------------

	/** render_profile_section()'s inline <script> (below) relies on the global ThessleyQR this defines — profile.php/user-edit.php only, not every admin page. */
	public static function profile_page_assets( $hook ) {
		if ( ! self::enabled() || ! in_array( $hook, array( 'profile.php', 'user-edit.php' ), true ) ) {
			return;
		}
		self::register_qr_scripts();
		wp_enqueue_script( 'thessley-qr' );
		// Pulled in here too (normally only loaded on the plugin's own
		// wp-thessley-* pages) so the device list below can use the same
		// Thessley_UI::badge() house style as the rest of the plugin
		// instead of plain table text.
		wp_enqueue_style( 'thessley-admin', THESSLEY_PLUGIN_URL . 'assets/admin.css', array(), THESSLEY_VERSION );
	}

	/**
	 * One static screen per site mode, decided before anyone has typed
	 * anything — no username-first step, no toggle to click. There is no
	 * per-account override to diverge from this: every account with a
	 * device enrolled sees whichever of the three is live, identically.
	 *  - optional: password form AND the QR shown together, QR already
	 *              polling. Either one logs you in; whichever a visitor
	 *              reaches for first works.
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

		self::register_qr_scripts();

		wp_register_script( 'thessley-passkey-login', false, array( 'thessley-qr' ), THESSLEY_VERSION, true );
		wp_enqueue_script( 'thessley-passkey-login' );

		$rest_base = esc_url_raw( rest_url( 'thessley/v1/passkey/login' ) );

		wp_add_inline_script(
			'thessley-passkey-login',
			"(function(){\n" .
			"  var box = document.getElementById('thessley-passkey-box');\n" .
			"  if (!box) return;\n" .
			"  fetch('{$rest_base}/start', {method:'POST'}).then(function(r){return r.json();}).then(function(data){\n" .
			"    ThessleyQR.render(document.getElementById('thessley-passkey-qr'), data.app_link, 270);\n" .
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
			<p class="description">Scan this code with the Thessley Passkey app, or open it on this device.</p>
			<div id="thessley-passkey-qr" style="display:inline-block;line-height:0;background:#fff;padding:12px;border-radius:4px"></div>
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

		update_option( 'thessley_passkey_mode', $mode );

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function render_page() {
		$mode = self::mode();

		Thessley_UI::open( 'passkey-login' );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only result flag set only by this module's own admin-post redirect, which already check_admin_referer()'d before redirecting.
		if ( isset( $_GET['saved'] ) ) {
			Thessley_UI::notice( 'success', 'Settings saved.' );
		}

		Thessley_UI::section( 'Settings', 'admin-generic' );
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'thessley_pk_save_settings' ); ?>
			<input type="hidden" name="action" value="thessley_pk_save_settings">

			<?php
			Thessley_UI::row(
				'Login method',
				function () use ( $mode ) {
					?>
					<label><input type="radio" name="mode" value="optional" <?php checked( 'optional', $mode ); ?>> Password or the app — password form and QR shown together</label><br>
					<label><input type="radio" name="mode" value="2fa" <?php checked( '2fa', $mode ); ?>> Password, then app — password first, the app confirms it afterward</label><br>
					<label><input type="radio" name="mode" value="required" <?php checked( 'required', $mode ); ?>> App only — QR only, no password form</label>
					<?php
				},
				'Applies to every account with a device enrolled. An account with no device yet always falls back to plain password — there is nothing to confirm with yet.'
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
		?>
		<h2>Passkey devices</h2>
		<div class="thessley" style="margin-bottom:20px">
			<div id="thessley-pk-devices-wrap"><?php echo self::render_devices_list_html( $user ); ?></div>

			<?php if ( get_current_user_id() === (int) $user->ID ) : ?>
				<div id="thessley-pk-enroll-box" style="margin-top:16px;max-width:300px;padding:20px;border:1px solid #dcdcde;border-radius:6px;background:#fff;text-align:center">
					<?php
				$enroll_hint_by_mode = array(
					'optional' => "Add a new device to sign in without a password.",
					'2fa'      => 'Add a new device to confirm logins with, after your password.',
					'required' => 'Add a new device — the app is the only way to sign in.',
				);
				?>
				<p id="thessley-pk-enroll-hint" class="description" style="margin:0 0 14px"><?php echo esc_html( $enroll_hint_by_mode[ self::mode() ] ?? $enroll_hint_by_mode['optional'] ); ?></p>
					<button type="button" class="button button-primary" id="thessley-pk-enroll-start">Add a device</button>
					<div id="thessley-pk-enroll-qr" style="display:none;margin:16px auto 0;line-height:0;background:#fff;padding:12px;border-radius:4px"></div>
					<p id="thessley-pk-enroll-status" class="description" style="margin-top:12px;word-break:break-all"></p>
				</div>
			<?php endif; ?>

			<script>
					(function () {
						var wrap = document.getElementById('thessley-pk-devices-wrap');
						var devicesEndpoint = <?php echo wp_json_encode( esc_url_raw( rest_url( 'thessley/v1/passkey/devices' ) ) ); ?>;
						var restNonce = <?php echo wp_json_encode( wp_create_nonce( 'wp_rest' ) ); ?>;

						// Shared by both revoke (below) and enroll-approved (further
						// below) — re-fetches just the device table's markup and
						// swaps it in, so neither action needs a full page reload.
						function refreshDevices() {
							return fetch(devicesEndpoint, { headers: { 'X-WP-Nonce': restNonce } })
								.then(function (r) { return r.json(); })
								.then(function (data) { if ( data && data.html != null ) { wrap.innerHTML = data.html; } });
						}

						// Delegated on #thessley-pk-devices-wrap itself (which
						// survives refreshDevices()'s innerHTML swap) rather than
						// bound per-button, since the buttons it's listening for
						// get replaced wholesale on every refresh.
						wrap.addEventListener('click', function (e) {
							var btn = e.target.closest('.thessley-pk-revoke-btn');
							if ( ! btn ) {
								return;
							}
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
							}).then(refreshDevices).catch(function () { btn.disabled = false; });
						});

						<?php if ( get_current_user_id() === (int) $user->ID ) : ?>
						(function () {
							var btn = document.getElementById('thessley-pk-enroll-start');
							var hint = document.getElementById('thessley-pk-enroll-hint');
							var status = document.getElementById('thessley-pk-enroll-status');
							var qrBox = document.getElementById('thessley-pk-enroll-qr');
							var restBase = <?php echo wp_json_encode( esc_url_raw( rest_url( 'thessley/v1/passkey/enroll' ) ) ); ?>;

							btn.addEventListener('click', function () {
								btn.disabled = true;
								hint.textContent = 'Starting…';

								fetch(restBase + '/start', {
									method: 'POST',
									headers: { 'X-WP-Nonce': restNonce },
								}).then(function (r) { return r.json(); }).then(function (data) {
									if (!data || !data.app_link) {
										hint.textContent = 'Could not start enrollment: ' + (data && data.message ? data.message : 'no response from the server.');
										btn.disabled = false;
										return;
									}

									btn.style.display = 'none';
									hint.textContent = "Scan this with the device you're enrolling, or tap the link below on that same device.";
									qrBox.style.display = 'inline-block';
									qrBox.innerHTML = '';
									ThessleyQR.render(qrBox, data.app_link, 236);
									status.innerHTML = '<a href="' + data.app_link + '">Open on this device</a>';

									var poll = setInterval(function () {
										fetch(restBase + '/' + data.request_id + '/status', {
											headers: { 'X-WP-Nonce': restNonce },
										}).then(function (r) { return r.json(); }).then(function (s) {
											if (s.status === 'approved') {
												clearInterval(poll);
												qrBox.style.display = 'none';
												status.textContent = '';
												hint.textContent = 'Added "' + (s.label || 'device') + '".';
												refreshDevices();
											} else if (s.status === 'expired') {
												clearInterval(poll);
												qrBox.style.display = 'none';
												hint.textContent = 'Request expired — try again.';
												status.textContent = '';
												btn.style.display = 'inline-block';
												btn.disabled = false;
											}
										});
									}, 1500);
								}).catch(function (err) {
									hint.textContent = 'Network error starting enrollment: ' + err.message;
									btn.disabled = false;
								});
							});
						})();
						<?php endif; ?>
				})();
				</script>
		</div>
		<?php
	}

	/** Renders just the device table (or the empty-state message) — shared by the initial profile-page render and the /passkey/devices refresh endpoint so both stay pixel-identical. */
	private static function render_devices_list_html( $user ) {
		$devices = Thessley_Passkey_Store::devices_for_user( $user->ID );

		ob_start();
		if ( empty( $devices ) ) :
			?>
			<p class="description">No devices enrolled yet.</p>
			<?php
		else :
			?>
			<div class="thessley">
			<table class="widefat striped thessley-pk-devices" style="max-width:680px">
				<thead><tr><th>Label</th><th>Added</th><th>Last used</th><th>Status</th><th>Security</th><th></th></tr></thead>
				<tbody>
				<?php
				// [tone, dashicon, label] — tone feeds Thessley_UI::badge()'s
				// existing good/warn/bad/quiet palette, same as every other
				// module's status badges.
				$attestation_meta = array(
					'strongbox' => array( 'good', 'shield', 'StrongBox hardware' ),
					'tee'       => array( 'good', 'lock', 'TEE hardware' ),
					'software'  => array( 'warn', 'shield-alt', 'Software only' ),
				);
				?>
				<?php foreach ( $devices as $d ) : ?>
					<?php list( $att_tone, $att_icon, $att_label ) = $attestation_meta[ $d->attestation_level ?? '' ] ?? array( 'quiet', 'editor-help', 'Unverified' ); ?>
					<tr>
						<td><?php echo esc_html( $d->label ?: 'Unnamed device' ); ?></td>
						<td><?php echo esc_html( mysql2date( 'M j, Y', $d->created_at ) ); ?></td>
						<td><?php echo $d->last_used_at ? esc_html( mysql2date( 'M j, Y H:i', $d->last_used_at ) ) : '—'; ?></td>
						<td><?php Thessley_UI::badge( $d->revoked_at ? 'Revoked' : 'Active', $d->revoked_at ? 'bad' : 'good', $d->revoked_at ? 'dismiss' : 'yes-alt' ); ?></td>
						<td><?php Thessley_UI::badge( $att_label, $att_tone, $att_icon ); ?></td>
						<td>
							<?php if ( ! $d->revoked_at && ( get_current_user_id() === (int) $user->ID || current_user_can( 'manage_options' ) ) ) : ?>
								<?php // No <form> here — nested forms inside profile.php/user-edit.php break WordPress core's own nonce check; the click handler further up uses fetch() instead. ?>
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
			</div>
			<?php
		endif;
		return ob_get_clean();
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

		self::bind_browser_to_request( $result['request_id'] );

		thessley_log_event( 'passkey-login', 'password_step_ok', 'noted', 'user #' . $user->ID . ' — awaiting app confirmation' );

		wp_safe_redirect( self::auth_url( '2fa', $result['request_id'] ) );
		exit;
	}
}
