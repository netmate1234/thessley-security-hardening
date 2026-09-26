<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Site-wide per-IP request throttling, independent of Login Guard (login
 * forms specifically) and Query Guard (attack signatures specifically).
 * Covers admin-ajax, REST, wp-cron.php, uploads — anything that reaches
 * PHP at all, since it's a plain request-count check with no WordPress
 * context needed, unlike Login Guard which has to hook actual auth events.
 */
class Thessley_Module_Rate_Limiter {

	public static function activate() {
		self::deploy_check_file();
	}

	public static function deactivate() {
		Thessley_Module_Loader::unregister_check( 'rate-limiter' );
	}

	public static function register() {
		self::deploy_check_file();
		add_action( 'admin_post_thessley_rl_save_settings', array( __CLASS__, 'handle_save_settings' ) );
		// Runs once WordPress has decided the request is a 404, which the early
		// gate cannot know yet. Priority 0 so it counts before any redirect
		// plugin gets a chance to answer the request.
		add_action( 'template_redirect', array( __CLASS__, 'watch_404_probing' ), 0 );
		return __CLASS__;
	}

	const DEFAULT_404_DISTINCT = 10;
	const PROBE_WINDOW         = 60;

	/**
	 * Catches blind sweeps by behaviour rather than by signature: an IP that
	 * asks for many different paths that do not exist within a minute is
	 * probing, whatever the paths are (new scanner toolkits are guessing
	 * fresh file names every week, and most of a sweep's first requests hit
	 * names no signature has caught up with yet).
	 *
	 * What is deliberately not counted, because ordinary visitors and
	 * crawlers cause these: missing images/CSS/JS/fonts (a page with a few
	 * broken assets), requests that carry a Referer from this same site
	 * (someone following a broken link), and logged-in users.
	 */
	public static function watch_404_probing() {
		if ( ! is_404() || ! get_option( 'thessley_ratelimit_enabled', true ) ) {
			return;
		}

		$limit = (int) get_option( 'thessley_ratelimit_404_distinct', self::DEFAULT_404_DISTINCT );
		if ( $limit < 1 || is_user_logged_in() ) {
			return;
		}

		$ip = thessley_client_ip();
		if ( '' === $ip || thessley_ip_is_exempt( $ip ) ) {
			return;
		}

		$path = (string) wp_parse_url( thessley_request_uri(), PHP_URL_PATH );
		if ( preg_match( '/\.(?:jpe?g|png|gif|webp|avif|svg|ico|css|js|map|woff2?|ttf|eot|otf|mp[34]|webm)$/i', $path ) ) {
			return;
		}

		$referer_host = isset( $_SERVER['HTTP_REFERER'] ) ? wp_parse_url( esc_url_raw( wp_unslash( $_SERVER['HTTP_REFERER'] ) ), PHP_URL_HOST ) : '';
		if ( $referer_host && wp_parse_url( home_url(), PHP_URL_HOST ) === $referer_host ) {
			return;
		}

		$key   = 'thessley_p404_' . md5( $ip );
		$state = get_transient( $key );
		$state = is_array( $state ) ? $state : array( 'paths' => array(), 'flagged' => false );
		$now   = time();

		foreach ( $state['paths'] as $hash => $ts ) {
			if ( $ts <= $now - self::PROBE_WINDOW ) {
				unset( $state['paths'][ $hash ] );
			}
		}
		$state['paths'][ md5( $path ) ] = $now;

		$distinct = count( $state['paths'] );
		$tripped  = $distinct >= $limit;

		// Log and escalate once per burst, not once per request: a sweep can be
		// hundreds of requests and the event log should record it once.
		$first = $tripped && empty( $state['flagged'] );
		if ( $first ) {
			$state['flagged'] = true;
		}
		set_transient( $key, $state, 2 * self::PROBE_WINDOW );

		if ( ! $tripped ) {
			return;
		}

		$block = 'block' === get_option( 'thessley_ratelimit_mode', 'log' );

		if ( $first ) {
			thessley_log_event(
				'rate-limiter',
				'probe_flood',
				$block ? 'blocked' : 'logged',
				sprintf( '%d distinct missing paths within %d s (latest: %s)', $distinct, self::PROBE_WINDOW, substr( $path, 0, 120 ) ),
				10
			);

			if ( $block && get_option( 'thessley_ratelimit_escalate', true ) ) {
				$minutes = max( 1, (int) get_option( 'thessley_ratelimit_escalate_minutes', 30 ) );
				thessley_local_blocklist_add( $ip, 'rate-limiter: 404 probing', $minutes * MINUTE_IN_SECONDS );
			}
		}

		if ( $block ) {
			wp_die( esc_html__( 'Access denied.', 'thessley-security-hardening' ), '', array( 'response' => 403 ) );
		}
	}

	private static function deploy_check_file() {
		// Enables this module's early-gate check. The mu-loader requires the
		// check.php in this folder directly, so there is nothing to copy.
		Thessley_Module_Loader::register_check( 'rate-limiter' );
	}


	public static function handle_save_settings() {
		check_admin_referer( 'thessley_rl_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		update_option( 'thessley_ratelimit_enabled', isset( $_POST['enabled'] ) );
		update_option( 'thessley_ratelimit_mode', ( isset( $_POST['mode'] ) && 'block' === $_POST['mode'] ) ? 'block' : 'log' );
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- (int) cast is itself the sanitizer; wp_unslash() would be a no-op on a value about to be cast to int.
		update_option( 'thessley_ratelimit_per_minute', max( 10, (int) ( $_POST['per_minute'] ?? 300 ) ) );
		update_option( 'thessley_ratelimit_escalate', isset( $_POST['escalate'] ) );
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- same as per_minute above; 0 turns the 404 rule off.
		update_option( 'thessley_ratelimit_404_distinct', max( 0, (int) ( $_POST['probe_404'] ?? self::DEFAULT_404_DISTINCT ) ) );
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- same as per_minute above.
		update_option( 'thessley_ratelimit_escalate_after', max( 1, (int) ( $_POST['escalate_after'] ?? 3 ) ) );
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- same as per_minute above.
		update_option( 'thessley_ratelimit_escalate_minutes', max( 1, (int) ( $_POST['escalate_minutes'] ?? 30 ) ) );

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function render_page() {
		$enabled  = get_option( 'thessley_ratelimit_enabled', true );
		$mode     = get_option( 'thessley_ratelimit_mode', 'log' );
		$per_min  = (int) get_option( 'thessley_ratelimit_per_minute', 300 );
		$escalate = get_option( 'thessley_ratelimit_escalate', true );
		$probe404 = (int) get_option( 'thessley_ratelimit_404_distinct', self::DEFAULT_404_DISTINCT );
		$after    = (int) get_option( 'thessley_ratelimit_escalate_after', 3 );
		$minutes  = (int) get_option( 'thessley_ratelimit_escalate_minutes', 30 );

		Thessley_UI::open( 'rate-limiter' );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only result flag set only by this module's own admin-post redirect, which already check_admin_referer()'d before redirecting.
		if ( isset( $_GET['saved'] ) ) {
			Thessley_UI::notice( 'success', 'Settings saved.' );
		}

		Thessley_UI::tiles(
			array(
				array(
					'icon'  => $enabled ? ( 'block' === $mode ? 'shield-alt' : 'visibility' ) : 'warning',
					'tone'  => $enabled ? ( 'block' === $mode ? 'good' : 'warn' ) : 'warn',
					'value' => ! $enabled ? 'Disabled' : ( 'block' === $mode ? 'Blocking' : 'Log only' ),
					'label' => 'enforcement mode',
				),
				array( 'icon' => 'clock', 'tone' => 'quiet', 'value' => number_format_i18n( $per_min ), 'label' => 'requests/min per IP' ),
			)
		);

		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'thessley_rl_save_settings' ); ?>
			<input type="hidden" name="action" value="thessley_rl_save_settings">

			<?php Thessley_UI::section( 'Settings', 'clock' ); ?>
				<?php
				Thessley_UI::row(
					'Enabled',
					function () use ( $enabled ) {
						?>
						<label><input type="checkbox" name="enabled" <?php checked( $enabled ); ?>> Throttle requests per IP</label>
						<?php
					}
				);

				Thessley_UI::row(
					'Limit',
					function () use ( $per_min ) {
						?>
						<input type="number" name="per_minute" value="<?php echo esc_attr( $per_min ); ?>" min="10" style="width:7em"> requests per minute, per IP
						<?php
					},
					'Only counts requests that reach PHP — a page\'s CSS/JS/image sub-resources are served directly by the web server and never counted. 300/min (5/sec) comfortably covers normal browsing, editing, and REST/heartbeat polling while catching genuine floods.'
				);

				Thessley_UI::row(
					'404 probing',
					function () use ( $probe404 ) {
						?>
						<input type="number" name="probe_404" value="<?php echo esc_attr( $probe404 ); ?>" min="0" style="width:5em"> different missing pages within <?php echo esc_html( self::PROBE_WINDOW ); ?> seconds, per IP
						<?php
					},
					'Catches blind sweeps by behaviour, whatever paths they guess. Missing images/CSS/JS, visits following a broken link on this site, and logged-in users are not counted. Uses the mode and escalation settings below. Set to 0 to turn it off.'
				);

				Thessley_UI::row(
					'Mode',
					function () use ( $mode ) {
						?>
						<label><input type="radio" name="mode" value="log" <?php checked( $mode, 'log' ); ?>> Log only</label>
						<label><input type="radio" name="mode" value="block" <?php checked( $mode, 'block' ); ?>> Block (403)</label>
						<?php
					}
				);

				Thessley_UI::row(
					'Escalation',
					function () use ( $escalate, $after, $minutes ) {
						?>
						<label><input type="checkbox" name="escalate" <?php checked( $escalate ); ?>> After
							<input type="number" name="escalate_after" value="<?php echo esc_attr( $after ); ?>" min="1" style="width:4em">
							consecutive over-limit minutes, add the IP to the local blocklist for
							<input type="number" name="escalate_minutes" value="<?php echo esc_attr( $minutes ); ?>" min="1" style="width:5em"> minutes
						</label>
						<?php
					},
					'Distinguishes a brief legitimate burst (one busy minute) from a sustained flood, before handing it to the IP Blocklist module for a longer, cheaper block at the early gate.'
				);
				?>
			<?php Thessley_UI::section_end(); ?>

			<?php submit_button( 'Save settings' ); ?>
		</form>
		<?php
		Thessley_UI::close();
	}
}
