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
		return __CLASS__;
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
