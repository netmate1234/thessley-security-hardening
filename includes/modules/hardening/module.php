<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Post-compromise containment.
 *
 * These settings don't stop the initial break-in — they remove the tools an
 * attacker reaches for immediately afterwards: editing PHP from the
 * dashboard, dropping a webshell into uploads, and hiding a malicious plugin
 * from the plugin list (which is what the 2026 supply-chain backdoors did).
 */
class Thessley_Module_Hardening {

	const CRON_HOOK = 'thessley_hardening_scan';

	public static function activate() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + ( 20 * MINUTE_IN_SECONDS ), 'twicedaily', self::CRON_HOOK );
		}
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
		self::remove_uploads_guard();
	}

	public static function register() {
		add_action( 'admin_post_thessley_hd_save_settings', array( __CLASS__, 'handle_save_settings' ) );
		add_action( 'admin_post_thessley_hd_scan_now', array( __CLASS__, 'handle_scan_now' ) );
		add_action( self::CRON_HOOK, array( __CLASS__, 'scan_hidden_plugins' ) );

		if ( get_option( 'thessley_hardening_disable_file_edit', true ) && ! defined( 'DISALLOW_FILE_EDIT' ) ) {
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- this is WordPress core's own recognized constant name (the same one wp-config.php normally defines); prefixing it would make WP core stop recognizing it.
			define( 'DISALLOW_FILE_EDIT', true );
		}

		return __CLASS__;
	}

	private static function uploads_htaccess_path() {
		$uploads = wp_get_upload_dir();
		return trailingslashit( $uploads['basedir'] ) . '.htaccess';
	}

	const UPLOADS_GUARD_MARKER = '# BEGIN Thessley Security Hardening uploads guard';

	/**
	 * Blocks PHP execution inside wp-content/uploads. Any attacker who gets
	 * an arbitrary-file-upload primitive lands here first, and a .php file
	 * that can't execute is inert.
	 *
	 * Apache-only: nginx ignores .htaccess entirely, so on nginx this has to
	 * be a server-block rule instead, and the UI says so rather than
	 * pretending it worked.
	 */
	public static function write_uploads_guard() {
		$path = self::uploads_htaccess_path();

		$rules = self::UPLOADS_GUARD_MARKER . "\n"
			. "<FilesMatch \"\\.(?i:php|phtml|phps|phar|php[0-9]?)$\">\n"
			. "\tRequire all denied\n"
			. "</FilesMatch>\n"
			. "# END Thessley Security Hardening uploads guard\n";

		$existing = file_exists( $path ) ? (string) file_get_contents( $path ) : '';

		if ( false !== strpos( $existing, self::UPLOADS_GUARD_MARKER ) ) {
			return true; // already present
		}

		return false !== file_put_contents( $path, $rules . $existing, LOCK_EX );
	}

	public static function remove_uploads_guard() {
		$path = self::uploads_htaccess_path();
		if ( ! file_exists( $path ) ) {
			return;
		}

		$content = (string) file_get_contents( $path );
		$cleaned = preg_replace(
			'/' . preg_quote( self::UPLOADS_GUARD_MARKER, '/' ) . '.*?# END Thessley Security Hardening uploads guard\s*/s',
			'',
			$content
		);

		if ( '' === trim( (string) $cleaned ) ) {
			Thessley_Module_Loader::filesystem()->delete( $path );
		} elseif ( $cleaned !== $content ) {
			file_put_contents( $path, $cleaned, LOCK_EX );
		}
	}

	public static function uploads_guard_active() {
		$path = self::uploads_htaccess_path();
		return file_exists( $path ) && false !== strpos( (string) file_get_contents( $path ), self::UPLOADS_GUARD_MARKER );
	}

	private static function is_apache() {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- read-only substring check against the server's own software banner, never stored or output.
		return function_exists( 'apache_get_modules' ) || false !== stripos( (string) ( $_SERVER['SERVER_SOFTWARE'] ?? '' ), 'apache' );
	}

	/**
	 * Finds plugins that don't show up where an admin would look for them.
	 *
	 * A malicious plugin hides by filtering `all_plugins`, which is what the
	 * Plugins screen renders from. Note that get_plugins() does *not* run that
	 * filter, so comparing disk against get_plugins() would miss the trick
	 * entirely — the comparison has to be against the filtered list, i.e.
	 * what the admin actually sees.
	 *
	 * Both comparisons are kept: disk-vs-filtered catches the `all_plugins`
	 * trick, and disk-vs-get_plugins() catches a file whose header WordPress
	 * fails to parse at all.
	 */
	public static function scan_hidden_plugins() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$raw      = get_plugins();
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- this is WordPress core's own filter hook (fired by the Plugins screen), not one this plugin defines.
		$shown    = (array) apply_filters( 'all_plugins', $raw );
		$reported = array_keys( $shown );
		$on_disk  = array();

		$dir = WP_PLUGIN_DIR;
		foreach ( (array) glob( $dir . '/*' ) as $entry ) {
			if ( is_dir( $entry ) ) {
				foreach ( (array) glob( $entry . '/*.php' ) as $php ) {
					if ( self::has_plugin_header( $php ) ) {
						$on_disk[] = basename( $entry ) . '/' . basename( $php );
					}
				}
			} elseif ( '.php' === substr( $entry, -4 ) && self::has_plugin_header( $entry ) ) {
				$on_disk[] = basename( $entry );
			}
		}

		$hidden = array_values( array_diff( $on_disk, $reported ) );

		// A plugin filtering itself out of the list it doesn't otherwise
		// belong out of is worth naming explicitly, since it's deliberate
		// concealment rather than a parsing quirk.
		$filtered_out = array_values( array_diff( array_keys( $raw ), $reported ) );
		foreach ( $filtered_out as $f ) {
			if ( ! in_array( $f, $hidden, true ) ) {
				$hidden[] = $f;
			}
		}

		// mu-plugins never appear in the normal plugin list and are a classic
		// persistence spot, so surface them for eyeballing rather than as a
		// finding — this plugin legitimately installs one itself.
		$mu = array();
		if ( defined( 'WPMU_PLUGIN_DIR' ) && is_dir( WPMU_PLUGIN_DIR ) ) {
			foreach ( (array) glob( WPMU_PLUGIN_DIR . '/*.php' ) as $php ) {
				$mu[] = basename( $php );
			}
		}

		$result = array( 'at' => time(), 'hidden' => $hidden, 'mu_plugins' => $mu );
		update_option( 'thessley_hardening_hidden_result', $result, false );

		if ( $hidden ) {
			thessley_log_event(
				'hardening',
				'hidden_plugin',
				'noted',
				sprintf( '%d plugin file(s) on disk but absent from the plugin list: %s', count( $hidden ), implode( ', ', array_slice( $hidden, 0, 5 ) ) )
			);
		}

		return $result;
	}

	private static function has_plugin_header( $file ) {
		$data = @file_get_contents( $file, false, null, 0, 8192 );
		return $data && preg_match( '/^[ \t\/*#@]*Plugin Name:/mi', $data );
	}

	public static function handle_scan_now() {
		check_admin_referer( 'thessley_hd_scan_now' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}
		self::scan_hidden_plugins();
		wp_safe_redirect( add_query_arg( 'scanned', '1', wp_get_referer() ) );
		exit;
	}

	public static function handle_save_settings() {
		check_admin_referer( 'thessley_hd_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		update_option( 'thessley_hardening_disable_file_edit', isset( $_POST['disable_file_edit'] ) );

		$want_guard = isset( $_POST['uploads_guard'] );
		update_option( 'thessley_hardening_uploads_guard', $want_guard );

		$notice = '1';
		if ( $want_guard ) {
			if ( ! self::write_uploads_guard() ) {
				$notice = 'guardfail';
			}
		} else {
			self::remove_uploads_guard();
		}

		wp_safe_redirect( add_query_arg( 'saved', $notice, wp_get_referer() ) );
		exit;
	}


	public static function render_page() {
		$hidden_result = get_option( 'thessley_hardening_hidden_result', array() );
		$guard_active  = self::uploads_guard_active();
		$file_edit_off = defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT;
		$hidden        = (array) ( $hidden_result['hidden'] ?? array() );

		Thessley_UI::open( 'hardening' );

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only result flags set only by this module's own admin-post redirects, which already check_admin_referer() before redirecting.
		if ( isset( $_GET['saved'] ) && '1' === $_GET['saved'] ) {
			Thessley_UI::notice( 'success', 'Settings saved.' );
		} elseif ( isset( $_GET['saved'] ) && 'guardfail' === $_GET['saved'] ) {
			Thessley_UI::notice( 'error', 'Could not write ' . self::uploads_htaccess_path() . ' — check filesystem permissions.' );
		}
		if ( isset( $_GET['scanned'] ) ) {
			Thessley_UI::notice( 'success', 'Scan complete.' );
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		Thessley_UI::tiles(
			array(
				array(
					'icon'  => $file_edit_off ? 'yes-alt' : 'warning',
					'tone'  => $file_edit_off ? 'good' : 'warn',
					'value' => $file_edit_off ? 'Disabled' : 'Enabled',
					'label' => 'dashboard file editor',
				),
				array(
					'icon'  => $guard_active ? 'yes-alt' : 'warning',
					'tone'  => $guard_active ? 'good' : 'warn',
					'value' => $guard_active ? 'Guarded' : 'Unguarded',
					'label' => 'PHP in uploads',
				),
				array(
					'icon'  => $hidden ? 'dismiss' : 'yes-alt',
					'tone'  => $hidden ? 'bad' : 'good',
					'value' => $hidden ? (string) count( $hidden ) : '0',
					'label' => 'hidden plugins',
				),
			)
		);

		Thessley_UI::section( 'Hidden plugins', 'visibility' );
		echo '<p class="thessley-help" style="margin-top:0">Files with a plugin header that exist on disk but do not appear in the Plugins screen. A backdoor can filter itself out of that list while staying active, so this compares against the filtered list the admin actually sees.</p>';

		if ( empty( $hidden_result ) ) {
			echo '<div class="thessley-empty"><span class="dashicons dashicons-marker" style="color:#646970"></span><p>Not scanned yet.</p></div>';
		} elseif ( empty( $hidden ) ) {
			echo '<div class="thessley-empty"><span class="dashicons dashicons-yes-alt"></span><p>No hidden plugins found.</p></div>';
		} else {
			$list = '<p><strong>Plugin files not shown in the plugin list:</strong></p><ul>';
			foreach ( $hidden as $h ) {
				$list .= '<li><code>' . esc_html( $h ) . '</code></li>';
			}
			$list .= '</ul><p>Inspect these on disk before deleting — note the file, then read its contents.</p>';
			Thessley_UI::notice( 'error', $list, true );
		}

		if ( ! empty( $hidden_result['mu_plugins'] ) ) {
			echo '<p style="margin-bottom:4px"><strong>Must-use plugins</strong> <span class="thessley-muted">(always active, never listed on the Plugins screen)</span></p>';
			echo '<ul style="margin:0 0 0 1.4em;list-style:disc">';
			foreach ( $hidden_result['mu_plugins'] as $mu ) {
				echo '<li><code>' . esc_html( $mu ) . '</code>'
					. ( 'wp-thessley-early.php' === $mu ? ' <span class="thessley-muted">— installed by this plugin</span>' : '' )
					. '</li>';
			}
			echo '</ul>';
		}
		?>
		<div class="thessley-actions" style="margin-top:14px">
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'thessley_hd_scan_now' ); ?>
				<input type="hidden" name="action" value="thessley_hd_scan_now">
				<?php submit_button( 'Scan now', 'secondary', 'submit', false ); ?>
			</form>
		</div>
		<?php
		Thessley_UI::section_end();
		?>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'thessley_hd_save_settings' ); ?>
			<input type="hidden" name="action" value="thessley_hd_save_settings">

			<?php Thessley_UI::section( 'Settings', 'admin-generic' ); ?>
				<?php
				Thessley_UI::row(
					'Dashboard file editor',
					function () use ( $file_edit_off ) {
						?>
						<label><input type="checkbox" name="disable_file_edit" <?php checked( get_option( 'thessley_hardening_disable_file_edit', true ) ); ?>> Disable the plugin/theme code editor</label>
						<?php
						Thessley_UI::badge( $file_edit_off ? 'currently disabled' : 'currently enabled', $file_edit_off ? 'good' : 'warn' );
					},
					'Anyone who reaches wp-admin as an administrator can otherwise edit PHP straight into a live file — the shortest path from a stolen password to running code.'
				);

				$is_apache = self::is_apache();
				Thessley_UI::row(
					'PHP in uploads',
					function () use ( $guard_active, $is_apache ) {
						?>
						<label><input type="checkbox" name="uploads_guard" <?php checked( get_option( 'thessley_hardening_uploads_guard', false ) ); ?>> Block PHP execution in <code>wp-content/uploads</code></label>
						<?php
						Thessley_UI::badge( $guard_active ? 'active' : 'not active', $guard_active ? 'good' : 'warn' );
						if ( ! $is_apache ) {
							echo '<p class="thessley-help"><strong>This server does not look like Apache.</strong> nginx ignores <code>.htaccess</code>, so this needs an equivalent server-block rule instead:<br><code>location ~* /wp-content/uploads/.*\.php$ { deny all; }</code></p>';
						}
					},
					'Writes an <code>.htaccess</code> into the uploads folder. Any attacker who gets an arbitrary-file-upload primitive lands there first, and a .php file that cannot execute is inert.'
				);
				?>
			<?php Thessley_UI::section_end(); ?>

			<?php submit_button( 'Save settings' ); ?>
		</form>
		<?php
		Thessley_UI::close();
	}
}
