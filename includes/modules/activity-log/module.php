<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * General admin activity — posts, plugins, themes, and a curated set of
 * security-relevant settings. Deliberately scoped to avoid overlapping two
 * modules that already own adjacent ground: Event Log records what the
 * blocking/detection modules caught, and User Watchdog specifically tracks
 * privileged *accounts*. This module answers a different, mundane, and
 * frequently useful question competitors call an "audit log" — who edited
 * that page, who installed that plugin, who changed the site's URL.
 *
 * It writes into the same shared events table via thessley_log_event()
 * rather than keeping its own — the Event Log's existing filter-by-module
 * view is the browsing UI, so there is no second table or page to keep
 * in sync.
 */
class Thessley_Module_Activity_Log {

	/** Options worth a log line. Logging every option WordPress writes
	 * (transients, autoload housekeeping) would drown real changes in noise. */
	const WATCHED_OPTIONS = array(
		'siteurl', 'home', 'admin_email', 'users_can_register', 'default_role',
		'template', 'stylesheet', 'blogname', 'permalink_structure',
		'WPLANG', 'timezone_string',
	);

	public static function activate() {}
	public static function deactivate() {}

	public static function register() {
		add_action( 'admin_post_thessley_al_save_settings', array( __CLASS__, 'handle_save_settings' ) );

		$enabled = get_option( 'thessley_activity_categories', array( 'content', 'plugins_themes', 'settings' ) );

		if ( in_array( 'content', $enabled, true ) ) {
			add_action( 'transition_post_status', array( __CLASS__, 'on_transition_post_status' ), 10, 3 );
			add_action( 'before_delete_post', array( __CLASS__, 'on_before_delete_post' ) );
		}

		if ( in_array( 'plugins_themes', $enabled, true ) ) {
			add_action( 'activated_plugin', array( __CLASS__, 'on_plugin_activated' ) );
			add_action( 'deactivated_plugin', array( __CLASS__, 'on_plugin_deactivated' ) );
			add_action( 'upgrader_process_complete', array( __CLASS__, 'on_upgrader_complete' ), 10, 2 );
			add_action( 'switch_theme', array( __CLASS__, 'on_switch_theme' ), 10, 3 );
			add_action( 'delete_plugin', array( __CLASS__, 'on_delete_plugin' ) );
		}

		if ( in_array( 'settings', $enabled, true ) ) {
			foreach ( self::WATCHED_OPTIONS as $opt ) {
				add_action( "update_option_{$opt}", array( __CLASS__, 'on_watched_option' ), 10, 3 );
			}
		}

		return __CLASS__;
	}

	private static function actor() {
		$current = wp_get_current_user();
		if ( $current && $current->ID ) {
			return sprintf( '%s (#%d)', $current->user_login, $current->ID );
		}
		return defined( 'WP_CLI' ) && WP_CLI ? 'WP-CLI' : 'system';
	}

	/**
	 * Fires on every save (including autosaves and revisions), so this
	 * narrows to the transitions actually worth a log line: a post entering
	 * or leaving 'publish', and moves to/from trash. A routine "click save
	 * again with no status change" produces no entry.
	 */
	public static function on_transition_post_status( $new_status, $old_status, $post ) {
		if ( wp_is_post_revision( $post ) || wp_is_post_autosave( $post ) ) {
			return;
		}
		if ( ! in_array( $post->post_type, array( 'post', 'page' ), true ) ) {
			return; // custom post types generate too much noise to log by default
		}
		if ( $new_status === $old_status ) {
			return;
		}

		$noteworthy = array( 'publish', 'trash' );
		if ( ! in_array( $new_status, $noteworthy, true ) && ! in_array( $old_status, $noteworthy, true ) ) {
			return;
		}

		thessley_log_event(
			'activity-log',
			'post_status_changed',
			'noted',
			sprintf( '"%s" (%s #%d): %s -> %s, by %s', $post->post_title, $post->post_type, $post->ID, $old_status, $new_status, self::actor() ),
			2
		);
	}

	public static function on_before_delete_post( $post_id ) {
		$post = get_post( $post_id );
		if ( ! $post || ! in_array( $post->post_type, array( 'post', 'page' ), true ) ) {
			return;
		}
		thessley_log_event(
			'activity-log',
			'post_deleted',
			'noted',
			sprintf( '"%s" (%s #%d) permanently deleted by %s', $post->post_title, $post->post_type, $post_id, self::actor() ),
			4
		);
	}

	public static function on_plugin_activated( $plugin ) {
		thessley_log_event( 'activity-log', 'plugin_activated', 'noted', sprintf( '%s, by %s', $plugin, self::actor() ), 4 );
	}

	public static function on_plugin_deactivated( $plugin ) {
		thessley_log_event( 'activity-log', 'plugin_deactivated', 'noted', sprintf( '%s, by %s', $plugin, self::actor() ), 3 );
	}

	public static function on_delete_plugin( $plugin ) {
		thessley_log_event( 'activity-log', 'plugin_deleted', 'noted', sprintf( '%s, by %s', $plugin, self::actor() ), 4 );
	}

	public static function on_switch_theme( $new_name, $new_theme, $old_theme ) {
		$old_name = $old_theme ? $old_theme->get( 'Name' ) : 'unknown';
		thessley_log_event( 'activity-log', 'theme_switched', 'noted', sprintf( '%s -> %s, by %s', $old_name, $new_name, self::actor() ), 4 );
	}

	/**
	 * Covers plugin/theme/core updates and new installs — one hook, several
	 * kinds of action distinguished by $options['action'] / ['type'].
	 */
	public static function on_upgrader_complete( $upgrader, $options ) {
		$action = $options['action'] ?? 'update';
		$type   = $options['type'] ?? 'unknown';

		$items = array();
		if ( 'plugin' === $type ) {
			$items = $options['plugins'] ?? ( isset( $options['plugin'] ) ? array( $options['plugin'] ) : array() );
		} elseif ( 'theme' === $type ) {
			$items = $options['themes'] ?? ( isset( $options['theme'] ) ? array( $options['theme'] ) : array() );
		}

		if ( empty( $items ) && 'core' !== $type ) {
			return;
		}

		thessley_log_event(
			'activity-log',
			"{$type}_{$action}",
			'noted',
			sprintf( '%s: %s, by %s', $action, $items ? implode( ', ', $items ) : 'core', self::actor() ),
			'install' === $action ? 4 : 2
		);
	}

	public static function on_watched_option( $old_value, $new_value, $option ) {
		if ( $old_value === $new_value ) {
			return;
		}
		thessley_log_event(
			'activity-log',
			'setting_changed',
			'noted',
			sprintf(
				'%s: "%s" -> "%s", by %s',
				$option,
				substr( (string) $old_value, 0, 80 ),
				substr( (string) $new_value, 0, 80 ),
				self::actor()
			),
			6
		);
	}


	public static function handle_save_settings() {
		check_admin_referer( 'thessley_al_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- already unslashed, and array_intersect() against the fixed $allowed whitelist below discards anything not in that list; nothing unvalidated ever reaches update_option().
		$posted  = isset( $_POST['categories'] ) ? (array) wp_unslash( $_POST['categories'] ) : array();
		$allowed = array( 'content', 'plugins_themes', 'settings' );
		$enabled = array_values( array_intersect( $posted, $allowed ) );
		update_option( 'thessley_activity_categories', $enabled );
		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function render_page() {
		global $wpdb;

		$enabled = get_option( 'thessley_activity_categories', array( 'content', 'plugins_themes', 'settings' ) );
		$table   = thessley_events_table();

		Thessley_UI::open( 'activity-log' );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only "settings saved" notice flag, not a state-changing action.
		if ( isset( $_GET['saved'] ) ) {
			Thessley_UI::notice( 'success', 'Settings saved.' );
		}

		$recent = array();
		$total  = 0;
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $table is thessley_events_table() (no user input, identifiers can't use $wpdb->prepare() placeholders); the WHERE value itself is properly bound below.
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) === $table ) {
			$total  = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE module = %s", 'activity-log' ) );
			$recent = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} WHERE module = %s ORDER BY id DESC LIMIT 50", 'activity-log' ) ) ?: array();
		}
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		Thessley_UI::tiles(
			array(
				array( 'icon' => 'list-view', 'tone' => 'quiet', 'value' => number_format_i18n( $total ), 'label' => 'entries recorded' ),
			)
		);

		Thessley_UI::section( 'Recent activity', 'clock', 'showing latest 50 — full history in the ' );
		echo '<p class="thessley-help" style="margin-top:0"><a href="' . esc_url( Thessley_Menu_Router::url( 'event-log', array( 'f_module' => 'activity-log' ) ) ) . '">Event Log, filtered to this module</a>, which also supports pagination and search.</p>';

		if ( empty( $recent ) ) {
			echo '<div class="thessley-empty"><span class="dashicons dashicons-info-outline"></span><p>No activity recorded yet.</p></div>';
		} else {
			?>
			<div class="thessley-table-scroll">
			<table class="thessley-table">
				<thead><tr><th style="width:130px">Time</th><th style="width:170px">Event</th><th>Detail</th></tr></thead>
				<tbody>
				<?php foreach ( $recent as $row ) : ?>
					<tr>
						<td class="thessley-nowrap"><?php echo esc_html( mysql2date( 'M j, H:i', $row->created_at ) ); ?></td>
						<td><code><?php echo esc_html( $row->event ); ?></code></td>
						<td class="thessley-muted"><?php echo esc_html( $row->detail ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
			</div>
			<?php
		}
		Thessley_UI::section_end();
		?>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'thessley_al_save_settings' ); ?>
			<input type="hidden" name="action" value="thessley_al_save_settings">

			<?php Thessley_UI::section( 'Settings', 'admin-generic' ); ?>
				<?php
				Thessley_UI::row(
					'Categories',
					function () use ( $enabled ) {
						$labels = array(
							'content'        => 'Posts &amp; pages (publish, trash, delete)',
							'plugins_themes' => 'Plugin/theme activate, deactivate, install, update, delete',
							'settings'       => 'Security-relevant settings (site URL, admin email, permalinks, theme, registration)',
						);
						foreach ( $labels as $id => $label ) {
							?>
							<label style="display:block;margin-bottom:6px"><input type="checkbox" name="categories[]" value="<?php echo esc_attr( $id ); ?>" <?php checked( in_array( $id, $enabled, true ) ); ?>> <?php echo wp_kses_post( $label ); ?></label>
							<?php
						}
					},
					'Custom post types, and every WordPress option write, are deliberately excluded to keep this a record of things worth reading rather than a firehose.'
				);
				?>
			<?php Thessley_UI::section_end(); ?>

			<?php submit_button( 'Save settings' ); ?>
		</form>
		<?php
		Thessley_UI::close();
	}
}
