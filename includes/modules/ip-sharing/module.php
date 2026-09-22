<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Shares blocked IPs with unwantedip.eagleeye-intelligence.com — a
 * self-hosted, cross-host reputation tracker (not a third-party service).
 * The actual send call (thessley_maybe_unwantedip_report()) lives in the
 * mu-loader, not here, for the same reason Alerts works that
 * way: a real block calls wp_die() at mu-plugin time, before regular
 * plugins have loaded, so nothing hooked here would ever see those
 * events. This module is just the admin UI and settings around that.
 *
 * Only ever reports actual blocks (never log-only detections) for an IP
 * that isn't LAN/reserved/trusted, and at most once per IP per hour.
 */
class Thessley_Module_IP_Sharing {

	const API = 'https://unwantedip.eagleeye-intelligence.com/api/v1';

	public static function activate() {
		// Pre-arms the toggle so reporting goes live the moment a key exists
		// — but doesn't do anything by itself: thessley_maybe_unwantedip_report()
		// (mu-loader) requires both this AND a saved API key, and getting a
		// key means calling out to unwantedip's signup endpoint, which is a
		// real account creation and needs a human to actually click it.
		add_option( 'thessley_unwantedip_enabled', true );
	}
	public static function deactivate() {}

	public static function register() {
		add_action( 'admin_post_thessley_uip_save_settings', array( __CLASS__, 'handle_save_settings' ) );
		add_action( 'admin_post_thessley_uip_test', array( __CLASS__, 'handle_test' ) );
		add_action( 'admin_post_thessley_uip_signup', array( __CLASS__, 'handle_signup' ) );

		return __CLASS__;
	}

	/**
	 * Signup has no form — the account identity *is* the requesting public
	 * IP, resolved server-side by unwantedip from the actual connection.
	 * That means this button, not a person or an agent running curl
	 * somewhere, has to be what makes the request: this server's own
	 * outbound connection is the only thing that legitimately proves "this
	 * WordPress install lives at this IP". The returned key is shown
	 * exactly once and saved immediately — there's no recovery endpoint.
	 */
	public static function handle_signup() {
		check_admin_referer( 'thessley_uip_signup' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		$response = wp_remote_post( self::API . '/signup', array( 'timeout' => 15 ) );

		if ( is_wp_error( $response ) ) {
			wp_safe_redirect( add_query_arg( 'signup', rawurlencode( 'fail:' . $response->get_error_message() ), wp_get_referer() ) );
			exit;
		}

		$code = wp_remote_retrieve_response_code( $response );
		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( 201 === $code && ! empty( $body['api_key'] ) ) {
			update_option( 'thessley_unwantedip_api_key', $body['api_key'] );
			update_option( 'thessley_unwantedip_enabled', true );
			wp_safe_redirect( add_query_arg( 'signup', 'ok', wp_get_referer() ) );
			exit;
		}

		if ( 409 === $code ) {
			wp_safe_redirect( add_query_arg( 'signup', 'exists', wp_get_referer() ) );
			exit;
		}

		$error = $body['error'] ?? "HTTP {$code}";
		wp_safe_redirect( add_query_arg( 'signup', rawurlencode( 'fail:' . $error ), wp_get_referer() ) );
		exit;
	}

	public static function handle_save_settings() {
		check_admin_referer( 'thessley_uip_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		update_option( 'thessley_unwantedip_enabled', isset( $_POST['enabled'] ) );

		$key = isset( $_POST['api_key'] ) ? sanitize_text_field( wp_unslash( $_POST['api_key'] ) ) : '';
		update_option( 'thessley_unwantedip_api_key', $key );

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	/** Reports a harmless, obviously-synthetic test IP so a real address never appears in your own test history. */
	public static function handle_test() {
		check_admin_referer( 'thessley_uip_test' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		$key = trim( (string) get_option( 'thessley_unwantedip_api_key', '' ) );
		if ( '' === $key ) {
			wp_safe_redirect( add_query_arg( 'test', 'missing', wp_get_referer() ) );
			exit;
		}

		$response = wp_remote_post(
			self::API . '/report',
			array(
				'timeout' => 10,
				'headers' => array(
					'Content-Type' => 'application/json',
					'X-API-Key'    => $key,
				),
				'body'    => wp_json_encode(
					array(
						// TEST-NET-1 (RFC 5737) — reserved for documentation, never a
						// real attacker, and easy to spot/ignore in report history.
						// No site name/domain here, matching the real report path —
						// this is public data, not a private alert.
						'ip'          => '203.0.113.1',
						'title'       => 'Thessley Security Hardening test report',
						'severity'    => 'low',
						'description' => 'Test report — if this appears, reporting is wired up correctly.',
					)
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			wp_safe_redirect( add_query_arg( 'test', rawurlencode( 'fail:' . $response->get_error_message() ), wp_get_referer() ) );
			exit;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( $code >= 200 && $code < 300 ) {
			wp_safe_redirect( add_query_arg( 'test', 'ok', wp_get_referer() ) );
			exit;
		}

		$body  = json_decode( wp_remote_retrieve_body( $response ), true );
		$error = $body['error'] ?? "HTTP {$code}";
		wp_safe_redirect( add_query_arg( 'test', rawurlencode( 'fail:' . $error ), wp_get_referer() ) );
		exit;
	}

	public static function render_page() {
		$enabled = get_option( 'thessley_unwantedip_enabled', false );
		$key     = (string) get_option( 'thessley_unwantedip_api_key', '' );

		Thessley_UI::open( 'ip-sharing' );

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only result flags set only by this module's own admin-post redirects, which already check_admin_referer() before redirecting.
		$saved  = isset( $_GET['saved'] );
		$signup = isset( $_GET['signup'] ) ? sanitize_text_field( wp_unslash( $_GET['signup'] ) ) : '';
		$test   = isset( $_GET['test'] ) ? sanitize_text_field( wp_unslash( $_GET['test'] ) ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		if ( $saved ) {
			Thessley_UI::notice( 'success', 'Settings saved.' );
		}
		if ( '' !== $signup ) {
			if ( 'ok' === $signup ) {
				Thessley_UI::notice( 'success', 'Signed up and saved the API key — sharing is now enabled.' );
			} elseif ( 'exists' === $signup ) {
				Thessley_UI::notice(
					'warning',
					'An account for this server\'s public IP already exists. Keys are shown once at signup and can\'t be retrieved again — if yours was lost, the site owner has to reissue one manually.'
				);
			} else {
				Thessley_UI::notice( 'error', 'Sign-up failed: ' . esc_html( str_replace( 'fail:', '', $signup ) ) );
			}
		}
		if ( '' !== $test ) {
			if ( 'ok' === $test ) {
				Thessley_UI::notice( 'success', 'Test report accepted.' );
			} elseif ( 'missing' === $test ) {
				Thessley_UI::notice( 'warning', 'Set an API key first.' );
			} else {
				Thessley_UI::notice( 'error', 'Report rejected: ' . esc_html( str_replace( 'fail:', '', $test ) ) );
			}
		}

		Thessley_UI::tiles(
			array(
				array(
					'icon'  => $enabled ? 'yes-alt' : 'warning',
					'tone'  => $enabled ? 'good' : 'warn',
					'value' => $enabled ? 'Enabled' : 'Disabled',
					'label' => 'IP sharing',
				),
				array(
					'icon'  => $key ? 'yes-alt' : 'warning',
					'tone'  => $key ? 'good' : 'warn',
					'value' => $key ? 'Set' : 'Not set',
					'label' => 'API key',
				),
			)
		);

		if ( ! $key ) {
			?>
			<div class="thessley-actions" style="margin-bottom:14px">
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<?php wp_nonce_field( 'thessley_uip_signup' ); ?>
					<input type="hidden" name="action" value="thessley_uip_signup">
					<?php submit_button( 'Sign up for an API key', 'primary', 'submit', false ); ?>
				</form>
				<p class="thessley-help" style="margin-top:6px">
					Sends one request, from this server, to <code>/api/v1/signup</code>. Your account identity is this server's own public IP — there's nothing to fill in first.
				</p>
			</div>
			<?php
		}

		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'thessley_uip_save_settings' ); ?>
			<input type="hidden" name="action" value="thessley_uip_save_settings">

			<?php Thessley_UI::section( 'unwantedip.eagleeye-intelligence.com', 'shield-alt' ); ?>
				<?php
				Thessley_UI::row(
					'Enabled',
					function () use ( $enabled ) {
						?>
						<label><input type="checkbox" name="enabled" <?php checked( $enabled ); ?>> Share every genuine block with the shared IP reputation tracker</label>
						<?php
					},
					'Only actual blocks are reported — never log-only detections — and at most once per IP per hour, so a sustained flood from one address files one report, not hundreds. LAN, reserved, and trusted-network IPs are never reported.'
				);

				Thessley_UI::row(
					'API key',
					function () use ( $key ) {
						?>
						<input type="text" name="api_key" value="<?php echo esc_attr( $key ); ?>" style="width:100%;max-width:420px" autocomplete="off">
						<?php
					},
					'Filled in automatically by "Sign up" below — there\'s no signup form on the site itself, since your account identity is this server\'s own public IP. Paste one in by hand only if you already have a key from elsewhere (e.g. reissued by the site owner).'
				);
				?>
			<?php Thessley_UI::section_end(); ?>

			<?php submit_button( 'Save settings' ); ?>
		</form>

		<div class="thessley-actions" style="margin-top:14px">
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'thessley_uip_test' ); ?>
				<input type="hidden" name="action" value="thessley_uip_test">
				<?php submit_button( 'Send test report', 'secondary', 'submit', false ); ?>
			</form>
		</div>
		<?php
		Thessley_UI::close();
	}
}
