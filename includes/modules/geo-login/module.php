<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Restricts wp-login.php to an allow-list of countries — narrower than
 * Geo Blocker (which can gate the whole site): this only ever looks at
 * the login request itself, never ordinary browsing. Deliberately
 * allow-list-only ("accept admin login from chosen countries"), unlike
 * Geo Blocker's block-list/allow-list choice — a login form has one
 * legitimate audience (you), so there's no meaningful block-list case.
 *
 * Reuses Geo Blocker's compiled country index and lookup rather than
 * fetching/compiling a second copy of the same dataset — this module has
 * no cron, no refresh, no data file of its own. If Geo Blocker has never
 * been active, the check simply has nothing to look up against yet.
 */
class Thessley_Module_Geo_Login {

	public static function activate() {
		self::deploy_check_file();
	}

	public static function deactivate() {
		Thessley_Module_Loader::unregister_check( 'geo-login' );
	}

	public static function register() {
		self::deploy_check_file();
		add_action( 'admin_post_thessley_gl_save_settings', array( __CLASS__, 'handle_save_settings' ) );
		return __CLASS__;
	}

	private static function deploy_check_file() {
		// Enables this module's early-gate check. The mu-loader requires the
		// check.php in this folder directly, so there is nothing to copy.
		Thessley_Module_Loader::register_check( 'geo-login' );
	}

	public static function handle_save_settings() {
		check_admin_referer( 'thessley_gl_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		update_option( 'thessley_geo_login_enforce_mode', ( isset( $_POST['enforce'] ) && 'block' === $_POST['enforce'] ) ? 'block' : 'log' );

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- already unslashed, and array_intersect() against the real country-code list below discards anything not in it; nothing unvalidated ever reaches update_option().
		$posted = isset( $_POST['countries'] ) ? (array) wp_unslash( $_POST['countries'] ) : array();
		$codes  = class_exists( 'Thessley_Geo_Country_Codes' )
			? array_values( array_intersect( $posted, array_keys( Thessley_Geo_Country_Codes::all() ) ) )
			: array();
		update_option( 'thessley_geo_login_countries', $codes );

		$indices = array();
		if ( class_exists( 'Thessley_Geo_Country_Codes' ) ) {
			foreach ( $codes as $code ) {
				$i = Thessley_Geo_Country_Codes::index_of( $code );
				if ( null !== $i ) {
					$indices[] = $i;
				}
			}
		}
		update_option( 'thessley_geo_login_country_indices', $indices, false );

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function render_page() {
		$enforce  = get_option( 'thessley_geo_login_enforce_mode', 'log' );
		$selected = (array) get_option( 'thessley_geo_login_countries', array() );
		$ready    = class_exists( 'Thessley_Geo_Country_Codes' );

		Thessley_UI::open( 'geo-login' );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only result flag set only by this module's own admin-post redirect, which already check_admin_referer()'d before redirecting.
		if ( isset( $_GET['saved'] ) ) {
			Thessley_UI::notice( 'success', 'Settings saved.' );
		}

		if ( ! $ready ) {
			Thessley_UI::notice( 'warning', 'Geo Blocker must be active at least once — this module reuses its country dataset rather than keeping a separate copy.' );
			Thessley_UI::close();
			return;
		}

		Thessley_UI::tiles(
			array(
				array(
					'icon'  => empty( $selected ) ? 'warning' : ( 'block' === $enforce ? 'shield-alt' : 'visibility' ),
					'tone'  => empty( $selected ) ? 'warn' : ( 'block' === $enforce ? 'good' : 'warn' ),
					'value' => empty( $selected ) ? 'Not configured' : ( 'block' === $enforce ? 'Blocking' : 'Log only' ),
					'label' => 'enforcement mode',
				),
				array( 'icon' => 'admin-site-alt3', 'tone' => 'quiet', 'value' => number_format_i18n( count( $selected ) ), 'label' => 'countries allowed' ),
			)
		);

		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'thessley_gl_save_settings' ); ?>
			<input type="hidden" name="action" value="thessley_gl_save_settings">

			<?php Thessley_UI::section( 'Enforcement', 'lock' ); ?>
				<?php
				Thessley_UI::row(
					'Mode',
					function () use ( $enforce ) {
						?>
						<label><input type="radio" name="enforce" value="log" <?php checked( $enforce, 'log' ); ?>> Log only</label>
						<label><input type="radio" name="enforce" value="block" <?php checked( $enforce, 'block' ); ?>> Block (403)</label>
						<?php
					},
					'Start in log-only mode and check the Event Log for a few days before switching to block — IP-to-country data is approximate (VPNs, mobile carriers, satellite links routinely resolve to the wrong country), and this gates the login form itself. Your LAN, reserved IP space, and anything in the trusted-networks file are always exempt, regardless of country — the same rule every other blocking module follows, so this can never lock out your own network.'
				);
				?>
			<?php Thessley_UI::section_end(); ?>

			<?php Thessley_UI::section( 'Allowed countries', 'admin-site' ); ?>
				<?php if ( empty( $selected ) ) : ?>
					<p class="thessley-help" style="margin-top:0">No countries selected — nothing is restricted yet. Pick at least one below and save before switching Enforcement to Block.</p>
				<?php endif; ?>
				<div class="thessley-scroll" style="max-height:320px">
					<?php foreach ( Thessley_Geo_Country_Codes::all() as $code => $name ) : ?>
						<?php if ( 'ZZ' === $code ) { continue; } /* reserved space, not a real country to pick */ ?>
						<label style="display:inline-block;width:47%">
							<input type="checkbox" name="countries[]" value="<?php echo esc_attr( $code ); ?>" <?php checked( in_array( $code, $selected, true ) ); ?>>
							<?php echo esc_html( $name ); ?> <span class="thessley-muted">(<?php echo esc_html( $code ); ?>)</span>
						</label>
					<?php endforeach; ?>
				</div>
				<p class="thessley-help">IP geolocation data: <a href="https://db-ip.com" target="_blank" rel="noopener">DB-IP.com</a> Country Lite, used under CC BY 4.0 — same dataset as Geo Blocker, refreshed by that module's weekly cron.</p>
			<?php Thessley_UI::section_end(); ?>

			<?php submit_button( 'Save settings' ); ?>
		</form>
		<?php
		Thessley_UI::close();
	}
}
