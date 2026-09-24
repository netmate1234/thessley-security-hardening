<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Owns everything that feeds thessley_ip_is_exempt()'s trusted/allowlist
 * checks — the base layer being a CIDR-per-line file fetched from a URL
 * (e.g. known crawler ranges), plus a short list of individually-listed
 * IPv4 addresses on top of it. Both used to live as separate fields on
 * the IP Blocklist page, but they were only ever actually checked there
 * and, separately, at local-blocklist escalation time — Geo Blocker, Geo
 * Login, Rate Limiter, Login Guard, and Query Guard's signature scan all
 * ignored them. Fixed at the source instead of patching each one by
 * hand: thessley_ip_is_exempt() (mu-loader) now checks both itself, and
 * that's the one exemption check nearly every blocking module already
 * calls — so an entry here is honored everywhere automatically,
 * including any future module that follows the same pattern.
 *
 * No check.php: this module doesn't gate anything itself, it just owns
 * the settings UI and the daily refresh for data the early gate reads
 * directly (thessley_trusted_ranges(), thessley_ip_allowlist option).
 */
class Thessley_Module_Whitelist {

	const CRON_HOOK      = 'thessley_trusted_networks_refresh';
	const DEFAULT_URL    = 'https://wp-opsec.eagleeye-intelligence.com/wp-content/uploads/wp-opsec/crawler-nets.conf';

	public static function activate() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time(), 'daily', self::CRON_HOOK );
		}
		// No URL is stored and nothing is fetched here: refresh() (below)
		// already no-ops on an empty thessley_trusted_networks_url, and
		// the settings page pre-fills the field with self::DEFAULT_URL as
		// a suggestion — activating the plugin must never by itself start
		// pulling from a third-party URL before the admin has saved this
		// page (even just accepting that suggestion) at least once.
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	public static function register() {
		add_action( self::CRON_HOOK, array( __CLASS__, 'refresh' ) );
		add_action( 'admin_post_thessley_wl_save_settings', array( __CLASS__, 'handle_save_settings' ) );
		add_action( 'admin_post_thessley_wl_refresh_now', array( __CLASS__, 'handle_refresh_now' ) );
		return __CLASS__;
	}

	/**
	 * Downloads the optional remote trusted-networks list and caches it
	 * locally, so every install can point at one centrally-maintained file
	 * (e.g. hosted on the main site) instead of each server needing its own
	 * local copy kept in sync by hand. A failed fetch keeps the last-good
	 * cache rather than clearing trust on a transient network hiccup.
	 */
	public static function refresh() {
		$url  = trim( (string) get_option( 'thessley_trusted_networks_url', '' ) );
		$dest = thessley_trusted_networks_remote_file();

		if ( '' === $url ) {
			if ( '' !== $dest && file_exists( $dest ) ) {
				Thessley_Module_Loader::fs_delete( $dest );
			}
			delete_option( 'thessley_trusted_networks_remote_stats' );
			return;
		}

		// Explicit user-agent so this site's address isn't sent to whatever host
		// the admin pointed the list at (WordPress' default one includes it).
		$response = wp_remote_get( $url, array( 'timeout' => 20, 'user-agent' => 'wp-thessley/' . THESSLEY_VERSION ) );
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			update_option(
				'thessley_trusted_networks_remote_stats',
				array(
					'error'      => is_wp_error( $response ) ? $response->get_error_message() : 'HTTP ' . wp_remote_retrieve_response_code( $response ),
					'checked_at' => time(),
				),
				false
			);
			return;
		}

		$body = wp_remote_retrieve_body( $response );

		// Creates the uploads data folder if needed; '' means it isn't usable.
		$dest = Thessley_Module_Loader::data_file( 'trusted-networks-remote.conf' );
		$tmp  = '' === $dest ? '' : $dest . '.tmp-' . wp_generate_password( 8, false );
		if ( '' === $tmp || ! Thessley_Module_Loader::fs_put_contents( $tmp, $body ) ) {
			update_option(
				'thessley_trusted_networks_remote_stats',
				array(
					'error'      => 'could not write the downloaded file (filesystem unavailable), previous cache kept',
					'checked_at' => time(),
				),
				false
			);
			return;
		}
		$count = count( thessley_parse_cidr_file( $tmp ) );

		if ( $count < 1 ) {
			// Empty or unparseable response — don't let a bad fetch silently
			// wipe out a previously-working trusted list.
			Thessley_Module_Loader::fs_delete( $tmp );
			update_option(
				'thessley_trusted_networks_remote_stats',
				array(
					'error'      => 'downloaded file had no valid CIDR lines, previous cache kept',
					'checked_at' => time(),
				),
				false
			);
			return;
		}

		Thessley_Module_Loader::fs_move( $tmp, $dest, true );
		self::write_by_source( $dest );

		update_option(
			'thessley_trusted_networks_remote_stats',
			array(
				'count'      => $count,
				'updated_at' => time(),
				'url'        => $url,
			),
			false
		);
	}

	/**
	 * A second, section-labeled breakdown of the same file, kept only so
	 * the Bot Log can say *which* crawler an exempted visit actually
	 * matched (e.g. "Googlebot / Google infrastructure") instead of just
	 * "trusted". Not used for the exemption decision itself.
	 */
	private static function write_by_source( $source_file ) {
		$by_heading = thessley_parse_cidr_file_by_heading( $source_file );

		Thessley_Module_Loader::write_data_file( 'trusted-networks-by-source.json', wp_json_encode( $by_heading ) );
	}

	public static function handle_refresh_now() {
		check_admin_referer( 'thessley_wl_refresh_now' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}
		self::refresh();
		wp_safe_redirect( add_query_arg( 'refreshed', '1', wp_get_referer() ) );
		exit;
	}

	public static function handle_save_settings() {
		check_admin_referer( 'thessley_wl_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- validated below via filter_var( ..., FILTER_VALIDATE_URL ) before it's ever stored.
		$trusted_url_raw = isset( $_POST['trusted_networks_url'] ) ? trim( wp_unslash( $_POST['trusted_networks_url'] ) ) : '';
		$trusted_url     = ( '' !== $trusted_url_raw && false !== filter_var( $trusted_url_raw, FILTER_VALIDATE_URL ) ) ? $trusted_url_raw : '';
		$url_changed     = $trusted_url !== get_option( 'thessley_trusted_networks_url', '' );
		update_option( 'thessley_trusted_networks_url', $trusted_url );

		if ( $url_changed ) {
			// Fetch immediately on save rather than waiting for tomorrow's
			// cron, same reasoning as activate()'s immediate refresh().
			self::refresh();
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- each line is validated below via filter_var( ..., FILTER_VALIDATE_IP ); anything that isn't a real IPv4 address is discarded before update_option().
		$raw  = isset( $_POST['allowlist'] ) ? wp_unslash( $_POST['allowlist'] ) : '';
		$list = array_filter( array_map( 'trim', preg_split( '/[\r\n,]+/', $raw ) ) );
		$list = array_values(
			array_filter(
				$list,
				function ( $ip ) {
					return false !== filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );
				}
			)
		);
		update_option( 'thessley_ip_allowlist', $list );

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function render_page() {
		// self::DEFAULT_URL as the fallback here (not '') pre-fills the
		// field with a real suggestion on a fresh install — accepting it
		// and clicking Save is what actually triggers the first fetch, in
		// handle_save_settings() below.
		$trusted_url          = get_option( 'thessley_trusted_networks_url', self::DEFAULT_URL );
		$trusted_remote_stats = get_option( 'thessley_trusted_networks_remote_stats', array() );
		$allowlist            = get_option( 'thessley_ip_allowlist', array() );

		Thessley_UI::open( 'whitelist' );

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only result flags set only by this module's own admin-post redirects, which already check_admin_referer() before redirecting.
		if ( isset( $_GET['saved'] ) ) {
			Thessley_UI::notice( 'success', 'Settings saved.' );
		}
		if ( isset( $_GET['refreshed'] ) ) {
			Thessley_UI::notice( 'success', 'Trusted networks list refreshed.' );
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		Thessley_UI::tiles(
			array(
				array(
					'icon'  => 'admin-site',
					'tone'  => 'quiet',
					'value' => ! empty( $trusted_remote_stats['count'] ) ? number_format_i18n( $trusted_remote_stats['count'] ) : '—',
					'label' => 'networks trusted',
				),
				array( 'icon' => 'yes-alt', 'tone' => 'quiet', 'value' => number_format_i18n( count( $allowlist ) ), 'label' => 'IPs whitelisted' ),
			)
		);

		?>
		<div class="thessley-actions" style="margin-bottom:18px">
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'thessley_wl_refresh_now' ); ?>
				<input type="hidden" name="action" value="thessley_wl_refresh_now">
				<?php submit_button( 'Refresh trusted networks now', 'secondary', 'submit', false ); ?>
			</form>
		</div>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'thessley_wl_save_settings' ); ?>
			<input type="hidden" name="action" value="thessley_wl_save_settings">

			<?php Thessley_UI::section( 'Trusted networks', 'admin-site' ); ?>
				<?php
				Thessley_UI::row(
					'URL',
					function () use ( $trusted_url, $trusted_remote_stats ) {
						?>
						<input type="url" name="trusted_networks_url" value="<?php echo esc_attr( $trusted_url ); ?>" style="width:100%;max-width:420px" placeholder="https://dashboard.eagleeye-intelligence.com/wp-content/uploads/wp-opsec/crawler-nets.conf">
						<?php
						if ( '' !== $trusted_url ) {
							echo ' ';
							if ( ! empty( $trusted_remote_stats['error'] ) ) {
								Thessley_UI::badge( 'fetch failed: ' . $trusted_remote_stats['error'], 'bad', 'warning' );
							} elseif ( ! empty( $trusted_remote_stats['count'] ) ) {
								Thessley_UI::badge(
									sprintf( '%d networks — updated %s', $trusted_remote_stats['count'], human_time_diff( $trusted_remote_stats['updated_at'] ) . ' ago' ),
									'good',
									'yes-alt'
								);
							}
						}
						?>
						<?php
					},
					'The base of the whitelist — a CIDR-per-line file (e.g. known crawler ranges) that\'s always exempt, from every blocking module. Downloaded once a day (also re-fetched immediately when this URL changes) and cached locally, so every install can point at one centrally-maintained file instead of each server keeping its own copy in sync by hand.'
				);
				?>
			<?php Thessley_UI::section_end(); ?>

			<?php Thessley_UI::section( 'Individual IPs', 'yes-alt' ); ?>
				<?php
				Thessley_UI::row(
					'Never-block IPs',
					function () use ( $allowlist ) {
						?>
						<textarea name="allowlist" rows="6" style="width:100%;max-width:420px" placeholder="203.0.113.7"><?php echo esc_textarea( implode( "\n", $allowlist ) ); ?></textarea>
						<?php
					},
					'One IPv4 per line, on top of the trusted networks above. Use this for your own address, a monitoring service, or anything else that should never be blocked no matter what triggers — the same way your LAN and reserved IP space always are.'
				);
				?>
			<?php Thessley_UI::section_end(); ?>

			<?php submit_button( 'Save settings' ); ?>
		</form>
		<?php
		Thessley_UI::close();
	}
}
