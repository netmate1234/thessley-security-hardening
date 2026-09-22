<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Central event log. Owns the table every other module writes to via
 * thessley_log_event(), plus the admin view for reading it.
 */
class Thessley_Module_Event_Log {

	const CRON_HOOK      = 'thessley_event_log_prune';
	const DB_VERSION     = 2;
	const PER_PAGE       = 50;
	const DEFAULT_RETAIN = 30; // days

	public static function activate() {
		self::install_table();

		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time(), 'daily', self::CRON_HOOK );
		}
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
		// Table is intentionally left in place — deactivating shouldn't
		// destroy the audit trail. Uninstall can drop it.
	}

	public static function register() {
		self::maybe_upgrade_table();

		add_action( self::CRON_HOOK, array( __CLASS__, 'prune' ) );
		add_action( 'admin_post_thessley_el_save_settings', array( __CLASS__, 'handle_save_settings' ) );
		add_action( 'admin_post_thessley_el_clear', array( __CLASS__, 'handle_clear' ) );

		return __CLASS__;
	}

	public static function install_table() {
		global $wpdb;

		$table   = thessley_events_table();
		$collate = $wpdb->get_charset_collate();

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		dbDelta(
			"CREATE TABLE {$table} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				created_at datetime NOT NULL,
				module varchar(32) NOT NULL DEFAULT '',
				event varchar(64) NOT NULL DEFAULT '',
				action varchar(16) NOT NULL DEFAULT '',
				severity tinyint(3) unsigned NOT NULL DEFAULT 0,
				ip varchar(45) NOT NULL DEFAULT '',
				uri varchar(255) NOT NULL DEFAULT '',
				detail text NULL,
				PRIMARY KEY  (id),
				KEY created_at (created_at),
				KEY module_event (module,event),
				KEY severity (severity),
				KEY ip (ip)
			) {$collate};"
		);

		self::backfill_severity();

		update_option( 'thessley_event_log_db_version', self::DB_VERSION, false );
	}

	/**
	 * Rows written before severity existed default to 0, which would sort
	 * below genuine "Info" events and read as "nothing to see". Score them
	 * from the same map so historic rows stay comparable.
	 */
	private static function backfill_severity() {
		global $wpdb;

		$table = thessley_events_table();

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $table is thessley_events_table() (no user input, identifiers can't use $wpdb->prepare() placeholders); $wpdb->update() below already parameterizes its own values via the format arrays.
		$pairs = $wpdb->get_results(
			"SELECT DISTINCT module, event, action FROM {$table} WHERE severity = 0",
			ARRAY_A
		);

		foreach ( (array) $pairs as $p ) {
			$wpdb->update(
				$table,
				array( 'severity' => thessley_event_severity( $p['module'], $p['event'], $p['action'] ) ),
				array( 'module' => $p['module'], 'event' => $p['event'], 'action' => $p['action'], 'severity' => 0 ),
				array( '%d' ),
				array( '%s', '%s', '%s', '%d' )
			);
		}
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
	}

	private static function maybe_upgrade_table() {
		if ( (int) get_option( 'thessley_event_log_db_version', 0 ) !== self::DB_VERSION ) {
			self::install_table();
		}
	}

	public static function prune() {
		global $wpdb;

		$days = max( 1, (int) get_option( 'thessley_event_log_retain_days', self::DEFAULT_RETAIN ) );
		$table = thessley_events_table();

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table name only, built from $wpdb->prefix, no user input; the actual value ($days) is bound via the %d placeholder above.
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$table} WHERE created_at < DATE_SUB(NOW(), INTERVAL %d DAY)",
				$days
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
	}


	public static function handle_save_settings() {
		check_admin_referer( 'thessley_el_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		$days = isset( $_POST['retain_days'] ) ? max( 1, (int) $_POST['retain_days'] ) : self::DEFAULT_RETAIN;
		update_option( 'thessley_event_log_retain_days', $days );

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function handle_clear() {
		check_admin_referer( 'thessley_el_clear' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		global $wpdb;
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table name only, built from $wpdb->prefix, no user input; identifiers can't be bound via $wpdb->prepare() placeholders.
		$wpdb->query( 'TRUNCATE TABLE ' . thessley_events_table() );

		wp_safe_redirect( add_query_arg( 'cleared', '1', wp_get_referer() ) );
		exit;
	}

	/** @return array{rows:array, total:int} */
	private static function query_events( $filters, $page ) {
		global $wpdb;

		$table  = thessley_events_table();
		$where  = array( '1=1' );
		$params = array();

		if ( ! empty( $filters['module'] ) ) {
			$where[]  = 'module = %s';
			$params[] = $filters['module'];
		}
		if ( ! empty( $filters['action'] ) ) {
			$where[]  = 'action = %s';
			$params[] = $filters['action'];
		}
		if ( ! empty( $filters['ip'] ) ) {
			$where[]  = 'ip = %s';
			$params[] = $filters['ip'];
		}
		if ( ! empty( $filters['min_sev'] ) ) {
			$where[]  = 'severity >= %d';
			$params[] = (int) $filters['min_sev'];
		}

		$order_sql = ( ! empty( $filters['sort'] ) && 'severity' === $filters['sort'] )
			? 'severity DESC, id DESC'
			: 'id DESC';

		$where_sql = implode( ' AND ', $where );

		$count_sql = "SELECT COUNT(*) FROM {$table} WHERE {$where_sql}";
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $count_sql is a query template (table name + %s/%d placeholders only), correctly bound via $wpdb->prepare() right here; the linter can't trace a template built one line above the prepare() call.
		$total     = (int) ( $params ? $wpdb->get_var( $wpdb->prepare( $count_sql, $params ) ) : $wpdb->get_var( $count_sql ) );

		$offset   = ( $page - 1 ) * self::PER_PAGE;
		$rows_sql = "SELECT * FROM {$table} WHERE {$where_sql} ORDER BY {$order_sql} LIMIT %d OFFSET %d";
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- same as $count_sql above: a placeholder-only template, bound via $wpdb->prepare() right here.
		$rows     = $wpdb->get_results( $wpdb->prepare( $rows_sql, array_merge( $params, array( self::PER_PAGE, $offset ) ) ) );

		return array( 'rows' => $rows ?: array(), 'total' => $total );
	}

	/**
	 * Country (reusing geo-blocker's compiled index, if that module has
	 * ever been activated) and reverse DNS, for display only — never on
	 * the request path, only here on the admin page. Reverse DNS is
	 * cached per IP for a week: gethostbyaddr() has no timeout parameter
	 * in PHP, so repeating it on every page view for the same IPs would
	 * make a slow/unresolvable one slow down every future page load too.
	 */
	private static function ip_info( $ip ) {
		$info = array( 'country' => '', 'host' => '' );

		if ( thessley_ip_is_reserved( $ip ) ) {
			return $info; // LAN/loopback — nothing meaningful to resolve
		}

		if ( function_exists( 'thessley_geo_lookup' ) && function_exists( 'thessley_geo_country_label' ) ) {
			$file = WPMU_PLUGIN_DIR . '/wp-thessley-checks/data/geo-country-index.bin';
			$long = ip2long( $ip );
			if ( false !== $long ) {
				$idx = thessley_geo_lookup( $file, $long );
				if ( null !== $idx ) {
					$info['country'] = thessley_geo_country_label( $idx );
				}
			}
		}

		$cache_key = 'thessley_rdns_' . md5( $ip );
		$cached    = get_transient( $cache_key );
		if ( false !== $cached ) {
			$info['host'] = $cached;
			return $info;
		}

		$host = gethostbyaddr( $ip );
		$host = ( false !== $host && $host !== $ip ) ? $host : '';
		set_transient( $cache_key, $host, WEEK_IN_SECONDS );
		$info['host'] = $host;

		return $info;
	}

	public static function render_page() {
		global $wpdb;

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only list filters/pagination, not a state-changing action; already sanitized/cast below.
		$filters = array(
			'module'  => isset( $_GET['f_module'] ) ? sanitize_text_field( wp_unslash( $_GET['f_module'] ) ) : '',
			'action'  => isset( $_GET['f_action'] ) ? sanitize_text_field( wp_unslash( $_GET['f_action'] ) ) : '',
			'ip'      => isset( $_GET['f_ip'] ) ? sanitize_text_field( wp_unslash( $_GET['f_ip'] ) ) : '',
			'min_sev' => isset( $_GET['f_sev'] ) ? max( 0, min( 20, (int) $_GET['f_sev'] ) ) : 0,
			'sort'    => isset( $_GET['sort'] ) && 'severity' === $_GET['sort'] ? 'severity' : 'time',
		);
		$page = isset( $_GET['paged'] ) ? max( 1, (int) $_GET['paged'] ) : 1;
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		$result = self::query_events( $filters, $page );
		$table  = thessley_events_table();

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $table is thessley_events_table() (no user input, identifiers can't use $wpdb->prepare() placeholders); these are fixed summary tiles, not worth an object-cache group for.
		$modules = $wpdb->get_col( "SELECT DISTINCT module FROM {$table} ORDER BY module" ) ?: array();
		$retain  = (int) get_option( 'thessley_event_log_retain_days', self::DEFAULT_RETAIN );

		$last24    = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE created_at > DATE_SUB(NOW(), INTERVAL 1 DAY)" );
		$blocked24 = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE action = 'blocked' AND created_at > DATE_SUB(NOW(), INTERVAL 1 DAY)" );
		$worst24   = (int) $wpdb->get_var( "SELECT MAX(severity) FROM {$table} WHERE created_at > DATE_SUB(NOW(), INTERVAL 1 DAY)" );
		$high_open = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE severity >= 14 AND created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)" );
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		Thessley_UI::open( 'event-log' );

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only result flags set only by this module's own admin-post redirects, which already check_admin_referer() before redirecting.
		if ( isset( $_GET['saved'] ) ) {
			Thessley_UI::notice( 'success', 'Settings saved.' );
		}
		if ( isset( $_GET['cleared'] ) ) {
			Thessley_UI::notice( 'success', 'Event log cleared.' );
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		$worst_meta = thessley_severity_meta( $worst24 );
		Thessley_UI::tiles(
			array(
				array( 'icon' => 'list-view', 'tone' => 'quiet', 'value' => number_format_i18n( $result['total'] ), 'label' => 'events stored' ),
				array( 'icon' => 'clock', 'tone' => 'quiet', 'value' => number_format_i18n( $last24 ), 'label' => 'in the last 24h' ),
				array( 'icon' => 'dismiss', 'tone' => $blocked24 ? 'bad' : 'good', 'value' => number_format_i18n( $blocked24 ), 'label' => 'blocked in 24h' ),
				array(
					'icon'  => $worst24 >= 14 ? 'warning' : 'yes-alt',
					'tone'  => $worst24 >= 18 ? 'bad' : ( $worst24 >= 10 ? 'warn' : 'good' ),
					'value' => $worst24 ? $worst24 . '/20' : '—',
					'label' => $worst24 ? 'worst in 24h · ' . $worst_meta[0] : 'nothing in 24h',
				),
			)
		);

		if ( $high_open ) {
			Thessley_UI::notice(
				'error',
				'<p><strong>' . esc_html( number_format_i18n( $high_open ) ) . '</strong> event(s) at severity 14+ in the last 7 days. '
				. '<a href="' . esc_url( Thessley_Menu_Router::url( 'event-log', array( 'f_sev' => 14, 'sort' => 'severity' ) ) ) . '">Review them →</a></p>',
				true
			);
		}

		Thessley_UI::section( 'Events', 'list-view', sprintf( '%s matching', number_format_i18n( $result['total'] ) ) );
		?>
		<form method="get" class="thessley-actions" style="margin-bottom:14px">
			<?php wp_parse_str( Thessley_Menu_Router::query( 'event-log' ), $route ); ?>
			<?php foreach ( $route as $k => $v ) : ?>
				<input type="hidden" name="<?php echo esc_attr( $k ); ?>" value="<?php echo esc_attr( $v ); ?>">
			<?php endforeach; ?>
			<select name="f_module">
				<option value="">All modules</option>
				<?php foreach ( $modules as $m ) : ?>
					<option value="<?php echo esc_attr( $m ); ?>" <?php selected( $filters['module'], $m ); ?>><?php echo esc_html( $m ); ?></option>
				<?php endforeach; ?>
			</select>
			<select name="f_action">
				<option value="">Any action</option>
				<?php foreach ( array( 'blocked', 'logged', 'noted' ) as $a ) : ?>
					<option value="<?php echo esc_attr( $a ); ?>" <?php selected( $filters['action'], $a ); ?>><?php echo esc_html( $a ); ?></option>
				<?php endforeach; ?>
			</select>
			<select name="f_sev">
				<option value="0">Any severity</option>
				<?php foreach ( array( 18 => 'Critical (18+)', 14 => 'High (14+)', 10 => 'Medium (10+)', 5 => 'Low (5+)' ) as $v => $label ) : ?>
					<option value="<?php echo esc_attr( $v ); ?>" <?php selected( $filters['min_sev'], $v ); ?>><?php echo esc_html( $label ); ?></option>
				<?php endforeach; ?>
			</select>
			<select name="sort">
				<option value="time" <?php selected( $filters['sort'], 'time' ); ?>>Newest first</option>
				<option value="severity" <?php selected( $filters['sort'], 'severity' ); ?>>Most severe first</option>
			</select>
			<input type="text" name="f_ip" value="<?php echo esc_attr( $filters['ip'] ); ?>" placeholder="IP" style="width:130px">
			<?php submit_button( 'Filter', 'secondary', 'submit', false ); ?>
		</form>

		<div class="thessley-actions" style="margin:-6px 0 14px">
			<label style="font-size:13px;font-weight:normal">
				<input type="checkbox" id="thessley-el-autorefresh"> Auto-refresh every 30s
			</label>
		</div>
		<?php
		wp_register_script( 'thessley-event-log', false, array(), THESSLEY_VERSION, true );
		wp_enqueue_script( 'thessley-event-log' );
		wp_add_inline_script(
			'thessley-event-log',
			"(function () {
				var cb  = document.getElementById( 'thessley-el-autorefresh' );
				var key = 'thessley_el_autorefresh';
				var timer = null;
				function schedule() {
					if ( timer ) { clearTimeout( timer ); }
					timer = setTimeout( function () { location.reload(); }, 30000 );
				}
				try { cb.checked = localStorage.getItem( key ) === '1'; } catch ( e ) {}
				if ( cb.checked ) { schedule(); }
				cb.addEventListener( 'change', function () {
					try { localStorage.setItem( key, cb.checked ? '1' : '0' ); } catch ( e ) {}
					if ( cb.checked ) { schedule(); } else if ( timer ) { clearTimeout( timer ); }
				} );
			})();"
		);
		?>

		<div class="thessley-table-scroll">
		<table class="thessley-table">
			<thead>
				<tr>
					<th style="width:120px">Severity</th>
					<th style="width:130px">Time</th>
					<th style="width:110px">Module</th>
					<th style="width:170px">Event</th>
					<th style="width:90px">Action</th>
					<th style="width:170px">IP</th>
					<th>Request / detail</th>
				</tr>
			</thead>
			<tbody>
			<?php if ( empty( $result['rows'] ) ) : ?>
				<tr><td colspan="7"><div class="thessley-empty"><span class="dashicons dashicons-yes-alt"></span><p>No events match.</p></div></td></tr>
			<?php else : ?>
				<?php foreach ( $result['rows'] as $row ) : ?>
					<tr>
						<td><?php Thessley_UI::severity_badge( $row->severity ); ?></td>
						<td class="thessley-nowrap"><?php echo esc_html( mysql2date( 'M j, H:i', $row->created_at ) ); ?></td>
						<td><span style="font-size:12px;font-weight:600;color:#2271b1"><?php echo esc_html( $row->module ); ?></span></td>
						<td><code><?php echo esc_html( $row->event ); ?></code></td>
						<td>
							<?php
							if ( 'blocked' === $row->action ) {
								Thessley_UI::badge( 'blocked', 'bad' );
							} elseif ( 'logged' === $row->action ) {
								Thessley_UI::badge( 'logged', 'warn' );
							} else {
								Thessley_UI::badge( 'noted', 'quiet' );
							}
							?>
						</td>
						<td style="max-width:170px">
							<code class="thessley-nowrap"><?php echo esc_html( $row->ip ); ?></code>
							<?php
							$ip_info = self::ip_info( $row->ip );
							if ( $ip_info['country'] ) {
								echo '<br><span class="thessley-muted" style="font-size:11px;word-break:break-all">' . esc_html( $ip_info['country'] ) . '</span>';
							}
							if ( $ip_info['host'] ) {
								echo '<br><span class="thessley-muted" style="font-size:11px;word-break:break-all">' . esc_html( $ip_info['host'] ) . '</span>';
							}
							?>
						</td>
						<td class="thessley-muted">
							<?php if ( $row->uri ) : ?>
								<code style="font-size:11px"><?php echo esc_html( $row->uri ); ?></code><br>
							<?php endif; ?>
							<?php echo esc_html( $row->detail ); ?>
						</td>
					</tr>
				<?php endforeach; ?>
			<?php endif; ?>
			</tbody>
		</table>
		</div>

		<?php
		$total_pages = (int) ceil( $result['total'] / self::PER_PAGE );
		if ( $total_pages > 1 ) {
			echo '<div class="tablenav" style="margin-top:12px"><div class="tablenav-pages">';
			echo wp_kses_post(
				paginate_links(
					array(
						'base'    => add_query_arg( 'paged', '%#%' ),
						'format'  => '',
						'current' => $page,
						'total'   => $total_pages,
					)
				)
			);
			echo '</div></div>';
		}

		Thessley_UI::section_end();
		?>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'thessley_el_save_settings' ); ?>
			<input type="hidden" name="action" value="thessley_el_save_settings">

			<?php Thessley_UI::section( 'Settings', 'admin-generic' ); ?>
				<?php
				Thessley_UI::row(
					'Retention',
					function () use ( $retain ) {
						?>
						Keep events for <input type="number" name="retain_days" value="<?php echo esc_attr( $retain ); ?>" min="1" style="width:6em"> days
						<?php
					},
					'Older events are deleted daily.'
				);
				?>
			<?php Thessley_UI::section_end(); ?>

			<?php submit_button( 'Save settings' ); ?>
		</form>

		<div class="thessley-actions" style="margin-top:14px">
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"
				onsubmit="return confirm('Delete all recorded events? This cannot be undone.');">
				<?php wp_nonce_field( 'thessley_el_clear' ); ?>
				<input type="hidden" name="action" value="thessley_el_clear">
				<?php submit_button( 'Clear event log', 'delete', 'submit', false ); ?>
			</form>
		</div>
		<?php
		Thessley_UI::close();
	}
}
