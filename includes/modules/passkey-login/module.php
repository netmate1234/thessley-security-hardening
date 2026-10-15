<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require_once __DIR__ . '/class-store.php';
require_once __DIR__ . '/class-crypto.php';
require_once __DIR__ . '/class-attestation.php';
require_once __DIR__ . '/class-tpm.php';

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

	/**
	 * Whether wp-login.php collects the username in a first step, before
	 * showing the QR. A second site-wide choice on top of mode(), applying
	 * to the two modes where the app can log you in on its own:
	 *  - optional: step 1 asks for the username, step 2 shows the password
	 *              form (username filled in) and the QR together.
	 *  - required: step 1 asks for the username, step 2 shows the QR only.
	 * Ignored in '2fa', where the password step already identifies the
	 * account. Off by default: the QR is then shown straight away and the
	 * device that approves it is what identifies you (BankID-style).
	 *
	 * Enforced server-side, not just by the screen: while this is on,
	 * /login/start refuses to create a request without a username, and a
	 * request created for a username can only be approved by that
	 * account's own devices (see rest_login_respond()) — the same rule a
	 * 2fa request already follows, so the page can never show one thing
	 * while the server accepts another.
	 */
	public static function identify() {
		return '2fa' !== self::mode() && (bool) get_option( 'thessley_passkey_identify', false );
	}

	/**
	 * Whether the login screen asks for a username before anything else.
	 * Same as identify() for 'optional', but always true for 'required' —
	 * not an admin preference there, because it's the only way a deviceless
	 * account can ever be told apart from one that still has a device (see
	 * rest_login_start()'s has_device branch and login_form_markup()).
	 */
	private static function identify_first() {
		return self::identify() || 'required' === self::mode();
	}

	/** Only the main login form: not lost-password, register, reset-password or the interim-login iframe, where a username box or QR makes no sense. */
	private static function is_main_login_screen() {
		$action = isset( $GLOBALS['action'] ) ? $GLOBALS['action'] : 'login';
		return 'login' === $action && empty( $GLOBALS['interim_login'] );
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
			echo '<!doctype html><meta charset="utf-8"><title>Expired</title><p>This Thessley Passkey login/enrollment request has expired. Go back and try again.</p>';
			exit;
		}

		if ( '2fa' === $type ) {
			self::render_2fa_page( $request );
			exit;
		}

		printf(
			'<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>%1$s</title>' .
			'<p>Open this on the device with the Thessley Passkey app installed to continue.</p>' .
			'<p><a href="%2$s">Get the Thessley Passkey app</a></p>',
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
			// Versioned by file time so a change to just these files (e.g. the QR
			// sizing) is not hidden behind a cached copy under the same ?ver=.
			$gen_path = THESSLEY_PLUGIN_DIR . 'assets/vendor/qrcode-generator.js';
			$qr_path  = THESSLEY_PLUGIN_DIR . 'assets/thessley-qr.js';
			$gen_ver  = file_exists( $gen_path ) ? (string) filemtime( $gen_path ) : THESSLEY_VERSION;
			$qr_ver   = file_exists( $qr_path ) ? (string) filemtime( $qr_path ) : THESSLEY_VERSION;
			wp_register_script( 'thessley-qrcode-generator', THESSLEY_PLUGIN_URL . 'assets/vendor/qrcode-generator.js', array(), $gen_ver, true );
			wp_register_script( 'thessley-qr', THESSLEY_PLUGIN_URL . 'assets/thessley-qr.js', array( 'thessley-qrcode-generator' ), $qr_ver, true );
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
		<div style="box-sizing:border-box;max-width:360px;margin:40px auto;padding:16px;font-family:sans-serif;text-align:center">
			<h1 style="font-size:1.1em"><?php echo esc_html( get_bloginfo( 'name' ) ); ?></h1>
			<p>Your password was correct. Confirm with the Thessley Passkey app to finish logging in.</p>
			<div id="thessley-2fa-qr" style="display:inline-block;line-height:0;background:#fff;padding:12px;border-radius:4px"></div>
			<p><a href="<?php echo esc_attr( $app_link ); ?>" style="display:block;box-sizing:border-box;width:100%;padding:12px 16px;border-radius:4px;background:#2271b1;color:#fff;font-weight:600;text-decoration:none">Open on this device</a></p>
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

		// Optional step for a device whose key lives in a TPM: prove the chip is genuine before enrolling.
		// Open like enroll/respond (the pending enrolment request is the capability), rate limited.
		register_rest_route(
			'thessley/v1',
			'/passkey/enroll/(?P<id>[\w-]+)/tpm-challenge',
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'rest_enroll_tpm_challenge' ),
				'permission_callback' => '__return_true',
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

		// Anonymous by default: no requester, so whichever enrolled device
		// approves IS the identification. With the username prompt on, the
		// request is created *for* the typed account instead.
		$requester = null;
		$typed     = '';

		$has_device = false;

		if ( self::identify_first() ) {
			$raw   = $req->get_param( 'username' );
			$typed = is_string( $raw ) ? substr( trim( sanitize_text_field( wp_unslash( $raw ) ) ), 0, 100 ) : '';

			if ( '' === $typed ) {
				return new WP_Error( 'thessley_bad_request', 'Enter your username.', array( 'status' => 400 ) );
			}

			$user = get_user_by( 'login', $typed );
			if ( ! $user && is_email( $typed ) ) {
				$user = get_user_by( 'email', $typed );
			}

			// An unknown name gets a real, working-looking request bound to
			// account 0, which no device can ever match — so the response,
			// the QR and the polling all look exactly like a genuine
			// account's, whether or not it exists or has a device. Nothing
			// here lets anyone find out which usernames are real. The typed
			// text (not the account's canonical login) goes into the link
			// for the same reason: echoing the canonical name would turn an
			// email address into its username.
			$requester = $user ? (int) $user->ID : 0;

			// Bucketed with "unknown username" (both false) on purpose — this
			// must never let a prober tell "real account, no device" apart
			// from "no such account". Only a real account WITH a device
			// produces the other, distinguishable outcome, which is already
			// implied by the whole identify flow routing approvals to it.
			$has_device = $requester ? self::user_has_active_device( $requester ) : false;
		}

		$result               = Thessley_Passkey_Store::create_request( 'login', $requester, self::LOGIN_TTL );
		$result['url']        = self::auth_url( 'login', $result['request_id'] );
		$result['app_link']   = self::app_link( 'login', $result['request_id'], $result['nonce'], $result['ip'], $typed );
		$result['has_device'] = $has_device;

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
		// The token is lowercase hex (bin2hex()), which sanitize_text_field()
		// leaves untouched, so a genuine cookie still matches byte for byte.
		$actual = isset( $_COOKIE['thessley_pk_bt'] ) ? sanitize_text_field( wp_unslash( $_COOKIE['thessley_pk_bt'] ) ) : '';

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
			$approver = get_userdata( (int) $request->approver_user_id );
			if ( $approver ) {
				// WordPress core's own login hook, fired so other plugins see this as a normal login.
				do_action( 'wp_login', $approver->user_login, $approver ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core hook, not one this plugin defines.
			}
			Thessley_Passkey_Store::consume_request( $id );

			thessley_log_event( 'passkey-login', 'login_approved', 'noted', 'user #' . (int) $request->approver_user_id );

			// Where wp-login.php would send this user after a password login. Running the same
			// 'login_redirect' filter means plugins that route particular accounts elsewhere (a
			// client dashboard page, say) apply to app logins too, instead of everyone landing on
			// wp-admin.
			$redirect_to = admin_url();
			if ( $approver ) {
				$redirect_to = wp_validate_redirect( apply_filters( 'login_redirect', $redirect_to, '', $approver ), admin_url() ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core hook, not one this plugin defines.
			}

			return rest_ensure_response(
				array(
					'status'      => 'approved',
					'redirect_to' => $redirect_to,
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

		// A request that already knows who is logging in — a 2fa request (the
		// password step identified them) or a login started with the
		// username prompt on — may only be resolved by that same account's
		// own devices. An anonymous login request (no requester) is the one
		// kind where whichever device approves IS the identification. A
		// requester of 0 is the placeholder for a username that doesn't
		// exist: no device belongs to account 0, so it can never resolve.
		if ( null !== $request->requester_user_id && (int) $request->requester_user_id !== (int) $passkey->user_id ) {
			thessley_log_event( 'passkey-login', 'signature_invalid', 'blocked', 'credential ' . $cred_id . ' tried to resolve another account\'s ' . $request->type . ' request' );
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
				'This account requires your password first — log in with it, then confirm with the Thessley Passkey app.',
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
		return rest_ensure_response( array( 'html' => wp_kses( self::render_devices_list_html( wp_get_current_user() ), self::devices_list_allowed_html() ) ) );
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
			$passkey = Thessley_Passkey_Store::get_passkey_by_credential( Thessley_Passkey_Store::get_credential_string_for_row( $request->credential_id ) );
			$response['label'] = $passkey ? $passkey->label : '';
		}

		return rest_ensure_response( $response );
	}

	/** The TPM manufacturer roots we trust: every tpm-roots/*.pem shipped with this module. */
	private static function tpm_root_files() {
		$files = glob( __DIR__ . '/tpm-roots/*.pem' );
		return $files ? $files : array();
	}

	public static function rest_enroll_tpm_challenge( WP_REST_Request $req ) {
		if ( self::rate_limited( 'enroll_tpm' ) ) {
			return new WP_Error( 'thessley_rate_limited', 'Too many requests.', array( 'status' => 429 ) );
		}

		$id      = $req->get_param( 'id' );
		$request = Thessley_Passkey_Store::get_request( $id );
		if ( ! $request || 'enroll' !== $request->type || 'pending' !== $request->status
			|| strtotime( $request->expires_at . ' UTC' ) < time() ) {
			return new WP_Error( 'thessley_expired', 'This request is no longer valid.', array( 'status' => 409 ) );
		}

		$certs = $req->get_param( 'ek_certs' );
		$ak    = $req->get_param( 'ak_public' );
		if ( ! is_array( $certs ) || ! is_string( $ak ) || strlen( $ak ) > 1024 ) {
			return new WP_Error( 'thessley_bad_request', 'Missing TPM details.', array( 'status' => 400 ) );
		}

		$ders = array();
		foreach ( $certs as $c ) {
			$der = is_string( $c ) ? base64_decode( $c, true ) : false; // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- decoding binary certificate data.
			if ( false === $der ) {
				return self::tpm_refused( 'bad certificate' );
			}
			$ders[] = $der;
		}
		$ak_public = base64_decode( $ak, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- decoding binary key data.
		if ( false === $ak_public || '' === $ak_public ) {
			return self::tpm_refused( 'bad attestation key' );
		}

		$ek = Thessley_Passkey_Tpm::verify_ek_chain( $ders, self::tpm_root_files() );
		if ( null === $ek ) {
			return self::tpm_refused( 'the TPM certificate chain is not one we trust' );
		}

		try {
			$info = Thessley_Passkey_Tpm::parse_public( $ak_public );
			$need = Thessley_Passkey_Tpm::ATTR_FIXEDTPM | Thessley_Passkey_Tpm::ATTR_FIXEDPARENT | Thessley_Passkey_Tpm::ATTR_RESTRICTED | Thessley_Passkey_Tpm::ATTR_SIGN;
			if ( ( $info['attributes'] & $need ) !== $need ) {
				return self::tpm_refused( 'attestation key is not a restricted signing key' );
			}
			$secret = random_bytes( 32 );
			$cred   = Thessley_Passkey_Tpm::make_credential( $ek['x'], $ek['y'], Thessley_Passkey_Tpm::name( $ak_public ), $secret );
		} catch ( Exception $e ) {
			return self::tpm_refused( 'could not build the challenge' );
		}

		set_transient(
			'thessley_pk_tpm_' . $id,
			array(
				'ak'     => hash( 'sha256', $ak_public ),
				'secret' => hash( 'sha256', $secret ),
				'maker'  => $ek['manufacturer'],
				'model'  => $ek['model'],
			),
			300
		);

		return rest_ensure_response(
			array(
				'credential_blob' => base64_encode( $cred['credential_blob'] ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- binary TPM structure on the wire.
				'secret'          => base64_encode( $cred['secret'] ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- binary TPM structure on the wire.
			)
		);
	}

	private static function tpm_refused( $reason ) {
		thessley_log_event( 'passkey-login', 'tpm_challenge_refused', 'blocked', $reason );
		return new WP_Error( 'thessley_tpm_unverified', 'The TPM could not be verified: ' . $reason . '.', array( 'status' => 400 ) );
	}

	/**
	 * Step 2: check the device's proof that its signing key lives in the TPM challenged earlier.
	 *
	 * @return array ok (bool), reason, maker, model.
	 */
	private static function verify_tpm( $request_id, $nonce, $public_key_b64, array $t ) {
		$state = get_transient( 'thessley_pk_tpm_' . $request_id );
		delete_transient( 'thessley_pk_tpm_' . $request_id ); // one challenge, one attempt.
		if ( ! is_array( $state ) ) {
			return array(
				'ok'     => false,
				'reason' => 'no challenge was issued',
			);
		}
		$field = static function ( $key ) use ( $t ) {
			return isset( $t[ $key ] ) && is_string( $t[ $key ] ) ? base64_decode( $t[ $key ], true ) : false; // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- decoding binary TPM structures.
		};
		$ak        = $field( 'ak_public' );
		$activated = $field( 'activated_secret' );
		$attest    = $field( 'certify_info' );
		$sig       = $field( 'certify_signature' );
		$key_pub   = $field( 'key_public' );
		$spki      = base64_decode( $public_key_b64, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- decoding the public key.
		if ( in_array( false, array( $ak, $activated, $attest, $sig, $key_pub, $spki ), true ) ) {
			return array(
				'ok'     => false,
				'reason' => 'incomplete proof',
			);
		}
		if ( ! hash_equals( $state['ak'], hash( 'sha256', $ak ) ) ) {
			return array(
				'ok'     => false,
				'reason' => 'a different attestation key than the one challenged',
			);
		}
		if ( ! hash_equals( $state['secret'], hash( 'sha256', $activated ) ) ) {
			return array(
				'ok'     => false,
				'reason' => 'activation secret does not match (the key and the TPM certificate are not in the same chip)',
			);
		}
		$reason = Thessley_Passkey_Tpm::verify_certification( $ak, $attest, $sig, $key_pub, $nonce, $spki );
		if ( null !== $reason ) {
			return array(
				'ok'     => false,
				'reason' => $reason,
			);
		}
		return array(
			'ok'    => true,
			'maker' => $state['maker'],
			'model' => $state['model'],
		);
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
		$level = '';
		$tpm   = $req->get_param( 'tpm' );
		if ( is_array( $tpm ) ) {
			$result = self::verify_tpm( $id, $request->nonce, $public_key, $tpm );
			if ( $result['ok'] ) {
				Thessley_Passkey_Store::set_attestation_level( $row_id, 'tpm' );
				thessley_log_event( 'passkey-login', 'attestation_verified', 'noted', 'device #' . $row_id . ': tpm (' . trim( $result['maker'] . ' ' . $result['model'] ) . ')' );
				$level = 'tpm';
			} else {
				Thessley_Passkey_Store::set_attestation_level( $row_id, null );
				thessley_log_event( 'passkey-login', 'attestation_unverified', 'noted', 'device #' . $row_id . ': tpm: ' . $result['reason'] );
			}
		} else {
			self::record_attestation( $row_id, $attestation_chain, $request->nonce, $public_key );
		}

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
				'attestation'   => $level,
			)
		);
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
				"If this wasn't you, log in and remove it immediately from your profile page's \"Thessley Passkey devices\" section, then change your password.",
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
		// Versioned by file time, like the plugin's own pages: with the plugin
		// version alone a phone (or CDN) keeps serving a stale stylesheet after
		// an update that only changed the CSS, e.g. the device cards.
		$css_path = THESSLEY_PLUGIN_DIR . 'assets/admin.css';
		$css_ver  = file_exists( $css_path ) ? (string) filemtime( $css_path ) : THESSLEY_VERSION;
		wp_enqueue_style( 'thessley-admin', THESSLEY_PLUGIN_URL . 'assets/admin.css', array(), $css_ver );
	}

	/**
	 * One static screen per site mode, decided before anyone has typed
	 * anything, except where noted. There is no per-account override to
	 * diverge from this: every account with a device enrolled sees whichever
	 * of the three is live, identically.
	 *  - optional: password form AND the QR shown together, QR already
	 *              polling. Either one logs you in; whichever a visitor
	 *              reaches for first works.
	 *  - 2fa:      password form only. The QR is deliberately not offered
	 *              here at all — see rest_login_respond()'s docblock on
	 *              why an anonymous app-only approval must never be
	 *              enough to finish a login for a 2fa account. That
	 *              enforcement lives server-side, not in this screen, but
	 *              there's no reason to invite the attempt either.
	 *  - required: username first, always (identify_first() forces this —
	 *              not an admin toggle here). The typed account's device
	 *              status decides what step 2 shows: QR only if it has one,
	 *              or the password form if it doesn't (rest_login_start()'s
	 *              has_device) — the only way a lost/revoked-only-device
	 *              account can reach the password field that
	 *              effective_mode_for_user() already lets it use
	 *              server-side. An account that still has a device gets
	 *              WordPress's normal "Password login is disabled" error if
	 *              it tries anyway.
	 */
	public static function login_head_styles() {
		if ( ! self::is_main_login_screen() ) {
			return;
		}

		if ( self::identify_first() ) {
			// Username first: the password form waits for step 1 (and, in
			// 'required', step 2 as well whenever the account turns out to
			// have a device). Hidden by a class that only a script adds, so
			// a browser without JavaScript simply keeps the normal password
			// form instead of being locked out of it; the login script
			// takes the class off once it's known the account needs it.
			//
			// Not display:none, on purpose. WordPress's own user-profile.js
			// (the show/hide-password button) runs on page load and
			// *disables* any password input that is hidden at that moment,
			// "to prevent autofill and submission" — and never re-enables
			// it, so revealing a display:none form later leaves the
			// password field dead. Collapsing the form to nothing while its
			// inputs keep their own layout boxes looks the same, is not
			// "hidden" to that check, and visibility:hidden also keeps the
			// fields out of tab order and away from screen readers and
			// autofill until step 2.
			echo '<style>html.thessley-pk-step1 #loginform{visibility:hidden!important;height:0!important;min-height:0!important;overflow:hidden!important;margin:0!important;padding:0!important;border:0!important;box-shadow:none!important}</style><script>document.documentElement.classList.add("thessley-pk-step1");</script>';
		}
	}

	public static function login_page_assets() {
		if ( '2fa' === self::mode() || ! self::is_main_login_screen() ) {
			return; // password form only — see login_head_styles()'s docblock
		}

		self::register_qr_scripts();

		wp_register_script( 'thessley-passkey-login', false, array( 'thessley-qr' ), THESSLEY_VERSION, true );
		wp_enqueue_script( 'thessley-passkey-login' );

		$config = array(
			'rest'     => esc_url_raw( rest_url( 'thessley/v1/passkey/login' ) ),
			'identify' => self::identify_first(),
			'optional' => 'optional' === self::mode(),
			'required' => 'required' === self::mode(),
		);

		wp_add_inline_script(
			'thessley-passkey-login',
			str_replace( '__THESSLEY_PK_CONFIG__', wp_json_encode( $config, JSON_HEX_TAG | JSON_HEX_AMP ), self::login_script() )
		);
	}

	/**
	 * The login screen's behaviour. Without the username prompt it starts a
	 * request on load and shows the QR (original behaviour — never the case
	 * for 'required', which always prompts). With it, there are two steps:
	 *   1. a username box — nothing else (for "Password or the app" the
	 *      password form is held back too);
	 *   2. what's shown depends on mode and that account's device status:
	 *        - "Password or the app": the QR plus the password form, with
	 *          the username filled in.
	 *        - "App only": the QR if the account has a device, or the
	 *          password form (filled in, same as above) if it doesn't —
	 *          has_device from /start decides, never a client-side guess.
	 * A wrong password reloads wp-login.php with the username WordPress
	 * kept in the form, which carries straight on to step 2.
	 */
	private static function login_script() {
		return <<<'JS'
(function () {
	var cfg = __THESSLEY_PK_CONFIG__;
	var box = document.getElementById('thessley-passkey-box');
	if (!box) { return; }

	var root     = document.documentElement;
	var qrEl     = document.getElementById('thessley-passkey-qr');
	var linkEl   = document.getElementById('thessley-passkey-link');
	var wrap     = document.getElementById('thessley-passkey-qrwrap');
	var idForm   = document.getElementById('thessley-passkey-id');
	var userIn   = document.getElementById('thessley-passkey-username');
	var changeEl = document.getElementById('thessley-passkey-change');
	var msg      = document.getElementById('thessley-passkey-msg');
	var poll = null, lastName = '', gen = 0;

	// WordPress only keeps the typed name in the password form after a wrong
	// password for an account that exists (it blanks it for an unknown one),
	// so the name is also remembered for this browser tab, and used only to
	// carry on after a failed login. Cleared as soon as it is no longer needed.
	var KEY = 'thessleyPkUser';
	function remember(n) { try { sessionStorage.setItem(KEY, n); } catch (e) {} }
	function recall() { try { return sessionStorage.getItem(KEY) || ''; } catch (e) { return ''; } }
	function forget() { try { sessionStorage.removeItem(KEY); } catch (e) {} }

	function stop() { if (poll) { clearInterval(poll); poll = null; } }
	function say(text) { msg.textContent = text || ''; }

	// Step 1: ask for the username.
	function stepOne() {
		gen++; stop(); say(''); forget();
		qrEl.innerHTML = '';
		wrap.style.display = 'none';
		idForm.style.display = '';
		if (cfg.optional || cfg.required) { root.classList.add('thessley-pk-step1'); }
		userIn.focus();
	}

	// Reveals the real password form, username pre-filled. Used for
	// "Password or the app" (always) and for 'required' when the typed
	// account turns out to have no device (see stepTwo()).
	function revealPassword(name) {
		root.classList.remove('thessley-pk-step1');
		var login = document.getElementById('user_login');
		var pass  = document.getElementById('user_pass');
		if (login) { login.value = name; }
		if (pass) { pass.disabled = false; pass.focus(); }
		// WordPress's own script re-sets (and focuses) the username field
		// about 200 ms after the page loads, which on a reload can land
		// after this and blank it again. Put the name back if so — never
		// over anything the user has typed since — and keep the cursor
		// in the password field.
		setTimeout(function () {
			if (login && !login.value) { login.value = name; }
			if (pass) { pass.disabled = false; }  // belt and braces: WordPress's own scripts may disable a field that was hidden when they ran
			if (pass && login && document.activeElement === login) { pass.focus(); }
		}, 450);
	}

	// Step 2: the QR — plus, for "Password or the app", the password form
	// too. For 'required' with no device on file, skip the QR entirely
	// (nothing could ever approve it) and go straight to the password form.
	function stepTwo(name, hasDevice) {
		remember(name);
		idForm.style.display = 'none';

		if (cfg.required && !hasDevice) {
			wrap.style.display = 'none';
			qrEl.innerHTML = '';
			box.style.display = 'none';
			revealPassword(name);
			return;
		}

		wrap.style.display = '';
		if (cfg.optional) { revealPassword(name); }
	}

	function ended(status) {
		stop();
		qrEl.innerHTML = '';
		say('Request ' + status + '. ');
		var again = document.createElement('a');
		again.href = '#';
		again.textContent = 'Get a new code';
		again.addEventListener('click', function (e) { e.preventDefault(); begin(lastName); });
		msg.appendChild(again);
	}

	function begin(name) {
		var my = ++gen;
		stop(); say('');
		lastName = name || '';

		var opts = { method: 'POST' };
		if (cfg.identify) {
			opts.headers = { 'Content-Type': 'application/json' };
			opts.body = JSON.stringify({ username: name });
		}

		fetch(cfg.rest + '/start', opts).then(function (r) { return r.json(); }).then(function (data) {
			if (my !== gen) { return; }
			if (!data || !data.app_link) {
				var why = data && data.message ? data.message : 'Could not start the Thessley Passkey app login. Try again.';
				if (cfg.identify) { stepOne(); }
				say(why);
				return;
			}

			if (cfg.required && false === data.has_device) {
				// No device on file for this account (or it doesn't exist) —
				// nothing could ever approve a QR, so skip it and drop
				// straight to the password form.
				if (cfg.identify) { stepTwo(name, false); }
				return;
			}

			qrEl.innerHTML = '';
			ThessleyQR.render(qrEl, data.app_link, 270);
			linkEl.href = data.app_link;
			if (cfg.identify) { stepTwo(name, true); }

			poll = setInterval(function () {
				fetch(cfg.rest + '/' + data.request_id + '/status').then(function (r) { return r.json(); }).then(function (s) {
					if (my !== gen) { return; }
					if (s.status === 'approved') { stop(); forget(); window.location.href = s.redirect_to; }
					else if (s.status === 'denied' || s.status === 'expired') { ended(s.status); }
				});
			}, 1500);
		}).catch(function () {
			if (my === gen) { say('Network error. Try again.'); }
		});
	}

	if (cfg.identify) {
		idForm.addEventListener('submit', function (e) {
			e.preventDefault();
			var name = userIn.value.trim();
			if (name) { begin(name); }
		});
		changeEl.addEventListener('click', function (e) { e.preventDefault(); stepOne(); });

		// After a wrong password WordPress reloads this page with an error;
		// carry straight on to step 2 for the same username.
		var typed   = document.getElementById('user_login');
		var carried = (typed && typed.value.trim()) || (document.getElementById('login_error') ? recall() : '');
		if (carried) {
			userIn.value = carried;
			begin(carried);
		} else {
			forget();
		}
	} else {
		begin('');
	}
})();
JS;
	}

	/** Hooked to 'login_footer', not 'login_form' — 'login_form' fires inside the password <form>, which both looks wrong and risks the same nested-element problems invalid markup causes elsewhere in this module. */
	public static function login_form_markup() {
		if ( '2fa' === self::mode() || ! self::is_main_login_screen() ) {
			return;
		}

		$identify = self::identify_first();
		?>
		<div id="thessley-passkey-box" style="max-width:320px;margin:12px auto;padding:12px;box-sizing:border-box;border:1px solid #dcdcde;border-radius:4px;text-align:center">
			<?php if ( $identify ) : ?>
				<?php // Without JavaScript the username box would do nothing; hide the whole box and leave the normal password form (never hidden without a script) as the way in. ?>
				<noscript><style>#thessley-passkey-box{display:none}</style></noscript>
				<form id="thessley-passkey-id" novalidate style="margin:0">
					<p class="description" style="margin-bottom:8px">
						<?php
						if ( 'optional' === self::mode() ) {
							echo 'Enter your username to sign in with a password or the Thessley Passkey app.';
						} elseif ( 'required' === self::mode() ) {
							echo 'Enter your username to continue.';
						} else {
							echo 'Enter your username to sign in with the Thessley Passkey app.';
						}
						?>
					</p>
					<label for="thessley-passkey-username" class="screen-reader-text">Username or email address</label>
					<input type="text" id="thessley-passkey-username" name="username" class="input" autocomplete="username" autocapitalize="none" spellcheck="false" maxlength="100" placeholder="Username or email address" style="width:100%;box-sizing:border-box;margin:0 0 8px;padding:6px 10px;min-height:40px;font-size:16px;line-height:1.5">
					<button type="submit" class="button button-primary" style="width:100%">Continue</button>
				</form>
			<?php endif; ?>
			<div id="thessley-passkey-qrwrap"<?php echo $identify ? ' style="display:none"' : ''; ?>>
				<p class="description">Scan this code with the Thessley Passkey app, or open it on this device.</p>
				<div id="thessley-passkey-qr" style="display:inline-block;line-height:0;background:#fff;padding:12px;border-radius:4px"></div>
				<p style="margin:12px 0 0"><a id="thessley-passkey-link" class="button" href="#" style="display:block;box-sizing:border-box;width:100%;text-align:center">Open on this device</a></p>
				<?php if ( $identify ) : ?>
					<p><a id="thessley-passkey-change" href="#">Use a different username</a></p>
				<?php endif; ?>
			</div>
			<p id="thessley-passkey-msg" role="status" style="margin:8px 0 0"></p>
		</div>
		<?php
	}

	// --- Settings page (Perimeter cluster) --------------------------------

	public static function handle_save_settings() {
		check_admin_referer( 'thessley_pk_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		$posted = isset( $_POST['mode'] ) ? sanitize_key( wp_unslash( $_POST['mode'] ) ) : '';
		$mode   = in_array( $posted, array( '2fa', 'required' ), true ) ? $posted : 'optional';

		update_option( 'thessley_passkey_mode', $mode );

		// Absent when the radios were disabled (the page greys them out in
		// 'Password, then app' mode, where they don't apply) — leave the
		// saved choice alone rather than silently resetting it.
		if ( isset( $_POST['identify'] ) ) {
			update_option( 'thessley_passkey_identify', '1' === sanitize_text_field( wp_unslash( $_POST['identify'] ) ) ? 1 : 0 );
		}

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function render_page() {
		$mode     = self::mode();
		$identify = (bool) get_option( 'thessley_passkey_identify', false ); // the saved choice, even while the current mode ignores it

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
					<label><input type="radio" name="mode" value="optional" <?php checked( 'optional', $mode ); ?>> Password or the Thessley Passkey app — password form and QR shown together</label><br>
					<label><input type="radio" name="mode" value="2fa" <?php checked( '2fa', $mode ); ?>> Password, then the Thessley Passkey app — password first, the app then confirms it</label><br>
					<label><input type="radio" name="mode" value="required" <?php checked( 'required', $mode ); ?>> Thessley Passkey app only — QR only, no password form</label>
					<?php
				},
				'Applies to every account with a device enrolled. An account with no device yet always falls back to plain password — there is nothing to confirm with yet.'
			);

			Thessley_UI::row(
				'Username prompt',
				function () use ( $identify ) {
					?>
					<label><input type="radio" name="identify" value="0" <?php checked( ! $identify ); ?>> Not asked — the QR is shown straight away, and the Thessley Passkey app works out who you are</label><br>
					<label><input type="radio" name="identify" value="1" <?php checked( $identify ); ?>> Ask for the username first — then show the QR for that account</label>
					<?php
				},
				'For “Password or the Thessley Passkey app” and “Thessley Passkey app only”. With the prompt, step 1 is just a username box; step 2 shows the QR (and, for “Password or the Thessley Passkey app”, the password form with the username filled in). Only that account’s own devices can then approve the QR, and an unknown username looks exactly like a real one — nothing reveals which accounts exist or have a device. Not used by “Password, then the Thessley Passkey app”: the password step already tells the site who you are.'
			);

			submit_button( 'Save settings' );
			?>
		</form>
		<script>
		( function () {
			var modes = document.querySelectorAll( 'input[name="mode"]' );
			var asks  = document.querySelectorAll( 'input[name="identify"]' );
			function sync() {
				var picked = document.querySelector( 'input[name="mode"]:checked' );
				var off    = picked && '2fa' === picked.value;
				asks.forEach( function ( a ) { a.disabled = off; } );
			}
			modes.forEach( function ( m ) { m.addEventListener( 'change', sync ); } );
			sync();
		}() );
		</script>
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
		<h2>Thessley Passkey devices</h2>
		<div class="thessley" style="margin-bottom:20px">
			<div id="thessley-pk-devices-wrap"><?php echo wp_kses( self::render_devices_list_html( $user ), self::devices_list_allowed_html() ); ?></div>

			<?php if ( get_current_user_id() === (int) $user->ID ) : ?>
				<div id="thessley-pk-enroll-box" style="margin-top:16px;max-width:300px;padding:20px;border:1px solid #dcdcde;border-radius:6px;background:#fff;text-align:center">
					<?php
				$enroll_hint_by_mode = array(
					'optional' => "Add a new device to sign in with the Thessley Passkey app, without a password.",
					'2fa'      => 'Add a new device to confirm logins with the Thessley Passkey app, after your password.',
					'required' => 'Add a new device — the Thessley Passkey app is the only way to sign in.',
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
							// Step 1: "are you sure?". Step 2 (below): the person re-enters their password.
							if ( ! window.confirm( 'Are you sure you want to revoke "' + ( btn.dataset.label || 'this device' ) + '"? It will no longer be able to approve logins.' ) ) {
								return;
							}
							askPassword( btn.dataset.label || 'this device', function ( password, fail, done ) {
								var body = new URLSearchParams({
									action: 'thessley_pk_revoke',
									id: btn.dataset.id,
									user_id: btn.dataset.userId,
									_wpnonce: btn.dataset.nonce,
									password: password,
								});
								fetch(<?php echo wp_json_encode( esc_url_raw( admin_url( 'admin-post.php' ) ) ); ?>, {
									method: 'POST',
									credentials: 'same-origin',
									headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
									body: body,
								}).then(function (r) {
									return r.json().catch(function () { return {}; }).then(function (data) {
										if ( r.ok && data.success ) {
											done();
											return refreshDevices();
										}
										fail( ( data && data.data && data.data.message ) || 'Could not revoke the device.' );
									});
								}).catch(function () { fail( 'Could not reach the site.' ); });
							});
						});

						// The password prompt (step 2). Built with text nodes only, never innerHTML.
						function askPassword(label, submit) {
							function mk(tag, cls, text) {
								var n = document.createElement(tag);
								if ( cls ) { n.className = cls; }
								if ( text ) { n.textContent = text; }
								return n;
							}
							var dlg = mk('dialog', 'thessley-pk-dialog');
							var form = mk('form');
							form.setAttribute('method', 'dialog');
							form.appendChild(mk('h3', null, 'Confirm it is you'));
							form.appendChild(mk('p', null, 'Enter your password to revoke "' + label + '".'));
							var input = mk('input');
							input.type = 'password';
							input.required = true;
							input.autocomplete = 'current-password';
							input.setAttribute('aria-label', 'Password');
							form.appendChild(input);
							var err = mk('p', 'thessley-pk-dialog-error');
							err.setAttribute('role', 'alert');
							form.appendChild(err);
							var row = mk('div', 'thessley-pk-dialog-buttons');
							var cancel = mk('button', 'button', 'Cancel');
							cancel.type = 'button';
							cancel.addEventListener('click', function () { dlg.close(); });
							var ok = mk('button', 'button button-primary', 'Revoke device');
							ok.type = 'submit';
							row.appendChild(cancel);
							row.appendChild(ok);
							form.appendChild(row);
							form.addEventListener('submit', function (ev) {
								ev.preventDefault();
								ok.disabled = true;
								err.textContent = '';
								submit( input.value, function (message) { err.textContent = message; ok.disabled = false; input.select(); }, function () { dlg.close(); } );
							});
							dlg.addEventListener('close', function () { dlg.remove(); });
							dlg.appendChild(form);
							document.body.appendChild(dlg);
							if ( dlg.showModal ) { dlg.showModal(); } else { dlg.setAttribute('open', ''); }
							input.focus();
						}

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
									hint.textContent = "Scan this with the Thessley Passkey app on the device you're enrolling, or tap the link below on that same device.";
									qrBox.style.display = 'inline-block';
									qrBox.innerHTML = '';
									ThessleyQR.render(qrBox, data.app_link, 236);
									var open = document.createElement('a');
									open.className = 'button button-primary';
									open.href = data.app_link;
									open.textContent = 'Open on this device';
									status.textContent = '';
									status.appendChild(open);

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

	/**
	 * Exactly the markup render_devices_list_html() produces — a table, the
	 * status badges, and the Revoke button with its data-* attributes —
	 * and nothing else. Core's wp_kses_post() list has no <button>, so this
	 * is an explicit allow-list: anything outside it is stripped before the
	 * markup reaches the page or the refresh endpoint.
	 */
	private static function devices_list_allowed_html() {
		return array(
			'div'    => array( 'class' => true ),
			'p'      => array( 'class' => true ),
			'table'  => array( 'class' => true, 'style' => true ),
			'thead'  => array(),
			'tbody'  => array(),
			'tr'     => array( 'class' => true ),
			'th'     => array(),
			'td'     => array( 'class' => true, 'data-label' => true ),
			'span'   => array( 'class' => true ),
			'button' => array(
				'type'          => true,
				'class'         => true,
				'disabled'      => true,
				'data-id'       => true,
				'data-user-id'  => true,
				'data-nonce'    => true,
				'data-label'    => true,
			),
		);
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
			<table class="widefat striped thessley-pk-devices" style="max-width:760px">
				<thead><tr><th>Label</th><th>Added</th><th>Last used</th><th>Status</th><th>Security</th><th>Score</th><th></th></tr></thead>
				<tbody>
				<?php
				// [tone, dashicon, label] — tone feeds Thessley_UI::badge()'s
				// existing good/warn/bad/quiet palette, same as every other
				// module's status badges.
				$attestation_meta = array(
					'strongbox' => array( 'good', 'shield', 'StrongBox hardware' ),
					'tpm'       => array( 'good', 'desktop', 'TPM 2.0 hardware' ),
					'tee'       => array( 'good', 'lock', 'TEE hardware' ),
					'software'  => array( 'warn', 'shield-alt', 'Software only' ),
				);
				// Security score (0-100) from where the key was verified to live at
				// enrolment — the same values as the Drupal module. It does not know
				// how the app protects the key (PIN, security key).
				$attestation_score = array(
					'strongbox' => 100,
					'tpm'       => 95,
					'tee'       => 85,
					'software'  => 40,
				);
				?>
				<?php foreach ( $devices as $d ) : ?>
						<?php list( $att_tone, $att_icon, $att_label ) = $attestation_meta[ $d->attestation_level ?? '' ] ?? array( 'quiet', 'editor-help', 'Unverified' ); ?>
						<?php // data-label feeds the mobile card layout (assets/admin.css): below 783px each row becomes a card and the cell's label is shown as its caption. ?>
						<tr class="<?php echo $d->revoked_at ? 'thessley-pk-revoked' : ''; ?>">
							<td class="thessley-pk-name" data-label="Label"><?php echo esc_html( $d->label ?: 'Unnamed device' ); ?></td>
							<td data-label="Added"><?php echo esc_html( mysql2date( 'M j, Y', $d->created_at ) ); ?></td>
							<td data-label="Last used"><?php echo $d->last_used_at ? esc_html( mysql2date( 'M j, Y H:i', $d->last_used_at ) ) : '—'; ?></td>
							<td data-label="Status"><?php Thessley_UI::badge( $d->revoked_at ? 'Revoked' : 'Active', $d->revoked_at ? 'bad' : 'good', $d->revoked_at ? 'dismiss' : 'yes-alt' ); ?></td>
							<td data-label="Security"><?php Thessley_UI::badge( $att_label, $att_tone, $att_icon ); ?></td>
							<td data-label="Score"><?php echo $d->revoked_at ? '—' : esc_html( ( $attestation_score[ $d->attestation_level ?? '' ] ?? 20 ) . ' / 100' ); ?></td>
							<td class="thessley-pk-actions">
								<?php if ( ! $d->revoked_at && ( get_current_user_id() === (int) $user->ID || current_user_can( 'manage_options' ) ) ) : ?>
									<?php // No <form> here — nested forms inside profile.php/user-edit.php break WordPress core's own nonce check; the click handler further up uses fetch() instead. ?>
									<button type="button" class="button button-small thessley-pk-revoke-btn"
										data-id="<?php echo esc_attr( $d->id ); ?>"
										data-user-id="<?php echo esc_attr( $user->ID ); ?>"
										data-label="<?php echo esc_attr( $d->label ); ?>"
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


	/** Wrong passwords allowed per window (seconds) before revoking is paused for that user. */
	const REAUTH_MAX    = 5;
	const REAUTH_WINDOW = 900;

	/**
	 * Revoke one device. Two steps: the page asks "are you sure?", and this handler then requires the acting
	 * user's own password (an administrator revoking someone else's device uses their own). Revoking is what
	 * you do when a phone is lost, so the app cannot be the proof, and an open session must not be enough to
	 * wipe the devices. Answers JSON: {success:true} or {success:false, data:{message}}.
	 */
	public static function handle_revoke() {
		$id = isset( $_POST['id'] ) ? absint( wp_unslash( $_POST['id'] ) ) : 0;
		check_admin_referer( 'thessley_pk_revoke_' . $id );

		$target_user_id = isset( $_POST['user_id'] ) ? absint( wp_unslash( $_POST['user_id'] ) ) : 0;

		if ( get_current_user_id() !== $target_user_id && ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'Forbidden.' ), 403 );
		}

		$me       = wp_get_current_user();
		$rl_key   = 'thessley_pk_reauth_' . $me->ID;
		$failures = (int) get_transient( $rl_key );
		if ( $failures >= self::REAUTH_MAX ) {
			wp_send_json_error( array( 'message' => 'Too many wrong passwords. Try again in a few minutes.' ), 429 );
		}

		$password = isset( $_POST['password'] ) ? (string) wp_unslash( $_POST['password'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified by check_admin_referer() above; a password must not be sanitised.
		if ( '' === $password || ! wp_check_password( $password, $me->user_pass, $me->ID ) ) {
			set_transient( $rl_key, $failures + 1, self::REAUTH_WINDOW );
			thessley_log_event( 'passkey-login', 'device_revoke_wrong_password', 'noted', 'user #' . $me->ID );
			wp_send_json_error( array( 'message' => 'Wrong password.' ), 403 );
		}
		delete_transient( $rl_key );

		Thessley_Passkey_Store::revoke( $id, $target_user_id );
		thessley_log_event( 'passkey-login', 'device_revoked', 'noted', 'device #' . $id . ' for user #' . $target_user_id );

		wp_send_json_success();
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
				__( '<strong>Password login is disabled for this account.</strong> Use the Thessley Passkey app to log in.', 'thessley-security-hardening' )
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
				__( '<strong>This account requires confirmation with the Thessley Passkey app.</strong> Log in through the website and use the Thessley Passkey app to finish.', 'thessley-security-hardening' )
			);
		}

		$result = Thessley_Passkey_Store::create_request( '2fa', $user->ID, self::LOGIN_TTL );

		self::bind_browser_to_request( $result['request_id'] );

		thessley_log_event( 'passkey-login', 'password_step_ok', 'noted', 'user #' . $user->ID . ' — awaiting Thessley Passkey app confirmation' );

		wp_safe_redirect( self::auth_url( '2fa', $result['request_id'] ) );
		exit;
	}
}
