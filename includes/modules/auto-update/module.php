<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Automatic updates.
 *
 * Roughly 60% of WordPress infections exploit a vulnerability that already
 * had a patch, and heavily-targeted flaws reach mass exploitation in hours.
 * Reporting an available update (which vuln-scanner does) loses that race
 * if a human has to read the report first — so this closes the loop and
 * installs them.
 *
 * The "auto-update anything vuln-scanner flagged" mode is deliberately
 * separate from blanket auto-updates: some sites can't take unattended
 * feature updates, but almost every site wants the security ones.
 */
class Thessley_Module_Auto_Update {

	const CRON_HOOK = 'thessley_auto_update_sweep';

	public static function activate() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + ( 30 * MINUTE_IN_SECONDS ), 'twicedaily', self::CRON_HOOK );
		}
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	public static function register() {
		add_action( 'admin_post_thessley_au_save_settings', array( __CLASS__, 'handle_save_settings' ) );
		add_action( self::CRON_HOOK, array( __CLASS__, 'sweep' ) );

		add_filter( 'allow_major_auto_core_updates', array( __CLASS__, 'allow_major_core' ), 20 );
		add_filter( 'allow_minor_auto_core_updates', array( __CLASS__, 'allow_minor_core' ), 20 );
		add_filter( 'auto_update_plugin', array( __CLASS__, 'filter_plugin' ), 20, 2 );
		add_filter( 'auto_update_theme', array( __CLASS__, 'filter_theme' ), 20, 2 );

		// Record what WordPress actually did, so the event log shows a real
		// audit trail rather than just "an update happened at some point".
		add_action( 'automatic_updates_complete', array( __CLASS__, 'log_results' ) );

		return __CLASS__;
	}

	public static function allow_minor_core( $enabled ) {
		$mode = get_option( 'thessley_auto_update_core', 'minor' );
		return in_array( $mode, array( 'minor', 'major' ), true ) ? true : $enabled;
	}

	public static function allow_major_core( $enabled ) {
		$mode = get_option( 'thessley_auto_update_core', 'minor' );
		if ( 'major' === $mode ) {
			return true;
		}
		if ( 'off' === $mode ) {
			return false;
		}
		return $enabled;
	}

	/**
	 * @param bool|null $update
	 * @param object    $item
	 */
	public static function filter_plugin( $update, $item ) {
		$mode = get_option( 'thessley_auto_update_plugins', 'flagged' );
		$file = $item->plugin ?? '';

		// An explicit exclusion is the one case where overriding WordPress
		// downward is intended — the admin named this plugin as hands-off.
		if ( self::is_excluded( $file ) ) {
			return false;
		}

		if ( 'all' === $mode ) {
			return true;
		}

		if ( 'flagged' === $mode ) {
			// Only ever add to what WordPress already decided. Returning a
			// hard false here would silently switch off per-plugin
			// auto-updates the admin had enabled on the Plugins screen.
			return self::is_flagged_by_scanner( $file ) ? true : $update;
		}

		return $update; // 'off' — leave WordPress's own per-plugin setting alone
	}

	public static function filter_theme( $update, $item ) {
		$mode = get_option( 'thessley_auto_update_themes', 'off' );
		if ( 'all' === $mode ) {
			return true;
		}
		return $update;
	}

	private static function is_excluded( $plugin_file ) {
		$excluded = (array) get_option( 'thessley_auto_update_exclude', array() );
		return in_array( $plugin_file, $excluded, true );
	}

	/**
	 * True if vuln-scanner's last run flagged this plugin for something that
	 * an update would actually fix. "Unmaintained" is excluded on purpose:
	 * there's no newer release to install, so it can't be auto-resolved.
	 */
	private static function is_flagged_by_scanner( $plugin_file ) {
		$last = get_option( 'thessley_vuln_last_result', array() );
		if ( empty( $last['findings'] ) ) {
			return false;
		}

		foreach ( $last['findings'] as $f ) {
			if ( 'plugin' !== $f['type'] || $f['file'] !== $plugin_file ) {
				continue;
			}
			foreach ( $f['issues'] as $issue ) {
				if ( in_array( $issue['kind'], array( 'outdated', 'cve' ), true ) ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * WordPress only runs its auto-updater on its own schedule. Nudge it,
	 * after refreshing vuln-scanner data so "flagged" mode is deciding on
	 * current information rather than a stale scan.
	 */
	public static function sweep() {
		if ( 'off' === get_option( 'thessley_auto_update_plugins', 'flagged' )
			&& 'off' === get_option( 'thessley_auto_update_core', 'minor' )
			&& 'off' === get_option( 'thessley_auto_update_themes', 'off' ) ) {
			return;
		}

		if ( class_exists( 'Thessley_Module_Vuln_Scanner' ) && 'flagged' === get_option( 'thessley_auto_update_plugins', 'flagged' ) ) {
			Thessley_Module_Vuln_Scanner::run_scan();
		}

		require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
		require_once ABSPATH . 'wp-admin/includes/update.php';

		wp_update_plugins();
		wp_update_themes();

		$upgrader = new WP_Automatic_Updater();
		if ( $upgrader->is_disabled() ) {
			thessley_log_event( 'auto-update', 'updater_disabled', 'noted', 'AUTOMATIC_UPDATER_DISABLED or DISALLOW_FILE_MODS is set' );
			return;
		}

		$upgrader->run();
	}

	public static function log_results( $results ) {
		foreach ( array( 'core', 'plugin', 'theme' ) as $type ) {
			if ( empty( $results[ $type ] ) ) {
				continue;
			}
			foreach ( $results[ $type ] as $item ) {
				$name    = $item->name ?? ( $item->item->slug ?? 'unknown' );
				$success = ! empty( $item->result ) && ! is_wp_error( $item->result );

				thessley_log_event(
					'auto-update',
					$success ? 'updated' : 'update_failed',
					'noted',
					sprintf( '%s: %s', $type, $name )
				);
			}
		}
	}


	public static function handle_save_settings() {
		check_admin_referer( 'thessley_au_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		$core = sanitize_text_field( wp_unslash( $_POST['core'] ?? 'minor' ) );
		update_option( 'thessley_auto_update_core', in_array( $core, array( 'off', 'minor', 'major' ), true ) ? $core : 'minor' );

		$plugins = sanitize_text_field( wp_unslash( $_POST['plugins'] ?? 'flagged' ) );
		update_option( 'thessley_auto_update_plugins', in_array( $plugins, array( 'off', 'flagged', 'all' ), true ) ? $plugins : 'flagged' );

		$themes = sanitize_text_field( wp_unslash( $_POST['themes'] ?? 'off' ) );
		update_option( 'thessley_auto_update_themes', in_array( $themes, array( 'off', 'all' ), true ) ? $themes : 'off' );

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sanitized on the very next line via array_map( 'sanitize_text_field', ... ) before it's ever stored.
		$exclude = isset( $_POST['exclude'] ) ? (array) wp_unslash( $_POST['exclude'] ) : array();
		update_option( 'thessley_auto_update_exclude', array_map( 'sanitize_text_field', $exclude ) );

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function render_settings_page() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$core    = get_option( 'thessley_auto_update_core', 'minor' );
		$plugins = get_option( 'thessley_auto_update_plugins', 'flagged' );
		$themes  = get_option( 'thessley_auto_update_themes', 'off' );
		$exclude = (array) get_option( 'thessley_auto_update_exclude', array() );

		$scan       = get_option( 'thessley_vuln_last_result', array() );
		$flagged_ct = 0;
		foreach ( (array) ( $scan['findings'] ?? array() ) as $f ) {
			foreach ( $f['issues'] as $i ) {
				if ( in_array( $i['kind'], array( 'outdated', 'cve' ), true ) ) {
					$flagged_ct++;
					break;
				}
			}
		}

		$blocked = defined( 'AUTOMATIC_UPDATER_DISABLED' ) && AUTOMATIC_UPDATER_DISABLED;
		$no_mods = defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS;

		Thessley_UI::open( 'auto-update' );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only "settings saved" notice flag, not a state-changing action.
		if ( isset( $_GET['saved'] ) ) {
			Thessley_UI::notice( 'success', 'Settings saved.' );
		}

		if ( $blocked || $no_mods ) {
			Thessley_UI::notice(
				'error',
				'<p><strong>Automatic updates are disabled at the wp-config level</strong> ('
					. esc_html( $blocked ? 'AUTOMATIC_UPDATER_DISABLED' : 'DISALLOW_FILE_MODS' )
					. '). Nothing on this page can take effect until that constant is removed.</p>',
				true
			);
		}

		Thessley_UI::tiles(
			array(
				array(
					'icon'  => 'update',
					'tone'  => 'off' === $plugins ? 'warn' : 'good',
					'value' => 'off' === $plugins ? 'Off' : ( 'all' === $plugins ? 'All' : 'Flagged' ),
					'label' => 'plugin auto-updates',
				),
				array(
					'icon'  => 'wordpress-alt',
					'tone'  => 'off' === $core ? 'warn' : 'good',
					'value' => ucfirst( $core ),
					'label' => 'core releases',
				),
				array(
					'icon'  => $flagged_ct ? 'warning' : 'yes-alt',
					'tone'  => $flagged_ct ? 'warn' : 'good',
					'value' => (string) $flagged_ct,
					'label' => 'currently flagged',
				),
			)
		);
		?>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'thessley_au_save_settings' ); ?>
			<input type="hidden" name="action" value="thessley_au_save_settings">

			<?php Thessley_UI::section( 'What to update automatically', 'update' ); ?>
				<?php
				Thessley_UI::row(
					'WordPress core',
					function () use ( $core ) {
						?>
						<label><input type="radio" name="core" value="minor" <?php checked( $core, 'minor' ); ?>> Security &amp; maintenance releases only <?php Thessley_UI::badge( 'recommended', 'good' ); ?></label>
						<label><input type="radio" name="core" value="major" <?php checked( $core, 'major' ); ?>> All releases, including major versions</label>
						<label><input type="radio" name="core" value="off" <?php checked( $core, 'off' ); ?>> Off</label>
						<?php
					},
					'Minor releases are where core security fixes ship, and they are deliberately low-risk. Major releases can change editor behaviour.'
				);

				Thessley_UI::row(
					'Plugins',
					function () use ( $plugins, $scan, $flagged_ct ) {
						?>
						<label>
							<input type="radio" name="plugins" value="flagged" <?php checked( $plugins, 'flagged' ); ?>>
							Only plugins the vulnerability scan flagged <?php Thessley_UI::badge( 'recommended', 'good' ); ?>
							<?php if ( $scan ) : ?>
								<span class="thessley-muted">— currently <?php echo esc_html( $flagged_ct ); ?></span>
							<?php endif; ?>
						</label>
						<label><input type="radio" name="plugins" value="all" <?php checked( $plugins, 'all' ); ?>> All plugins</label>
						<label><input type="radio" name="plugins" value="off" <?php checked( $plugins, 'off' ); ?>> Off (use WordPress&#39;s own per-plugin settings)</label>
						<?php
					},
					'91% of WordPress vulnerabilities are in plugins, so this is the setting that matters most. "Flagged" re-runs the scan before each sweep so it acts on current data. These settings only ever <em>add</em> to what you have already enabled per-plugin on the Plugins screen — the exclusion list below is the only thing that turns an auto-update off.'
				);

				Thessley_UI::row(
					'Themes',
					function () use ( $themes ) {
						?>
						<label><input type="radio" name="themes" value="all" <?php checked( $themes, 'all' ); ?>> All themes</label>
						<label><input type="radio" name="themes" value="off" <?php checked( $themes, 'off' ); ?>> Off</label>
						<?php
					},
					'Leave off if you have customised a theme directly instead of using a child theme — an update would overwrite your changes.'
				);
				?>
			<?php Thessley_UI::section_end(); ?>

			<?php Thessley_UI::section( 'Never auto-update', 'dismiss', sprintf( '%d excluded', count( $exclude ) ) ); ?>
				<div class="thessley-scroll">
					<?php foreach ( get_plugins() as $file => $data ) : ?>
						<label>
							<input type="checkbox" name="exclude[]" value="<?php echo esc_attr( $file ); ?>" <?php checked( in_array( $file, $exclude, true ) ); ?>>
							<?php echo esc_html( $data['Name'] ); ?>
							<span class="thessley-muted">v<?php echo esc_html( $data['Version'] ); ?></span>
						</label>
					<?php endforeach; ?>
				</div>
				<p class="thessley-help">For plugins that are customised, licence-locked, or that you update by hand.</p>
			<?php Thessley_UI::section_end(); ?>

			<?php submit_button( 'Save settings' ); ?>
		</form>
		<?php
		Thessley_UI::close();
	}
}
