<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Watches privileged accounts for the changes a backdoor actually makes.
 *
 * The 2026 supply-chain backdoors (Essential Plugins et al.) didn't stop at
 * code execution — they created hidden administrator accounts, which is what
 * survives the plugin being removed. That step is loud and easy to detect
 * even when the code that did it is obfuscated or self-hiding.
 *
 * Two layers: live hooks catch changes as they happen, and a scheduled
 * snapshot diff catches anything written straight to the database, which
 * bypasses hooks entirely.
 */
class Thessley_Module_User_Watchdog {

	const CRON_HOOK = 'thessley_user_watchdog_scan';

	/** Capabilities that make an account worth alerting on. */
	const SENSITIVE_CAPS = array( 'manage_options', 'edit_users', 'install_plugins', 'edit_files', 'unfiltered_html' );

	public static function activate() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + ( 10 * MINUTE_IN_SECONDS ), 'hourly', self::CRON_HOOK );
		}
		self::snapshot(); // establish a baseline so the first scan isn't all-new
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	public static function register() {
		add_action( 'admin_post_thessley_uw_save_settings', array( __CLASS__, 'handle_save_settings' ) );
		add_action( 'admin_post_thessley_uw_scan_now', array( __CLASS__, 'handle_scan_now' ) );
		add_action( 'admin_post_thessley_uw_acknowledge', array( __CLASS__, 'handle_acknowledge' ) );
		add_action( self::CRON_HOOK, array( __CLASS__, 'scan' ) );

		if ( get_option( 'thessley_user_watchdog_enabled', true ) ) {
			add_action( 'user_register', array( __CLASS__, 'on_user_register' ), 10, 1 );
			add_action( 'set_user_role', array( __CLASS__, 'on_set_role' ), 10, 3 );
			add_action( 'profile_update', array( __CLASS__, 'on_profile_update' ), 10, 2 );
			add_action( 'deleted_user', array( __CLASS__, 'on_user_deleted' ), 10, 1 );
		}

		return __CLASS__;
	}

	private static function is_privileged( $user ) {
		foreach ( self::SENSITIVE_CAPS as $cap ) {
			if ( user_can( $user, $cap ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Roles that grant any of SENSITIVE_CAPS, so the snapshot query can ask
	 * for just those instead of walking every account.
	 *
	 * @return string[]
	 */
	private static function privileged_roles() {
		$roles = array();

		foreach ( wp_roles()->roles as $slug => $role ) {
			foreach ( self::SENSITIVE_CAPS as $cap ) {
				if ( ! empty( $role['capabilities'][ $cap ] ) ) {
					$roles[] = $slug;
					continue 2;
				}
			}
		}

		return $roles;
	}

	/**
	 * @return array<int,array> user id => identifying fields
	 *
	 * Queries only privileged roles rather than enumerating every user:
	 * this runs on user_register and profile_update, so on a membership or
	 * shop site the old "load all users, then get_userdata() each" pass
	 * turned an ordinary customer signup into thousands of queries.
	 */
	public static function build_snapshot() {
		$snapshot = array();
		$roles    = self::privileged_roles();

		$args = array(
			'fields'  => array( 'ID', 'user_login', 'user_email' ),
			'number'  => 500,
			'orderby' => 'ID',
		);

		// role__in only covers role-based privilege. A user granted a
		// capability directly (no matching role) wouldn't appear, so fall
		// back to a full pass if the site has no privileged roles at all —
		// which shouldn't happen, but silently watching nothing would be worse.
		if ( $roles ) {
			$args['role__in'] = $roles;
		}

		foreach ( get_users( $args ) as $u ) {
			$user = get_userdata( $u->ID );
			if ( ! $user || ! self::is_privileged( $user ) ) {
				continue;
			}
			$snapshot[ (int) $user->ID ] = array(
				'login' => $user->user_login,
				'email' => $user->user_email,
				'roles' => array_values( (array) $user->roles ),
			);
		}

		return $snapshot;
	}

	public static function snapshot() {
		$snap = self::build_snapshot();
		update_option( 'thessley_user_watchdog_snapshot', $snap, false );
		update_option( 'thessley_user_watchdog_snapshot_at', time(), false );
		return $snap;
	}

	private static function add_alert( $type, $message, $user_id = 0 ) {
		$alerts   = (array) get_option( 'thessley_user_watchdog_alerts', array() );
		$alerts[] = array(
			'at'      => time(),
			'type'    => $type,
			'message' => $message,
			'user_id' => (int) $user_id,
		);

		// Keep the list bounded; the event log is the durable record.
		if ( count( $alerts ) > 100 ) {
			$alerts = array_slice( $alerts, -100 );
		}

		update_option( 'thessley_user_watchdog_alerts', $alerts, false );

		if ( get_option( 'thessley_user_watchdog_email', false ) ) {
			self::send_alert_email( $type, $message );
		}
	}

	private static function send_alert_email( $type, $message ) {
		// Rate-limited: a compromise can generate a burst of changes, and
		// mailing each one risks the whole batch being throttled or spam-
		// filtered — losing the first notification, which is the useful one.
		$last = (int) get_option( 'thessley_user_watchdog_last_email', 0 );
		if ( $last > time() - ( 15 * MINUTE_IN_SECONDS ) ) {
			return;
		}
		update_option( 'thessley_user_watchdog_last_email', time(), false );

		$site = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );

		wp_mail(
			get_option( 'admin_email' ),
			sprintf( '[%s] Privileged account alert: %s', $site, $type ),
			implode(
				"\n",
				array(
					'Thessley Security Hardening detected a change to a privileged account.',
					'',
					'Type:   ' . $type,
					'Detail: ' . $message,
					'Time:   ' . current_time( 'mysql' ),
					'',
					'Review: ' . Thessley_Menu_Router::url( 'user-watchdog' ),
					'',
					'If this was not you or another administrator, treat the site as compromised:',
					'check Users for accounts you do not recognise, and run a File Integrity scan.',
					'',
					'(Further alerts are suppressed for 15 minutes to avoid mail flooding.)',
				)
			)
		);
	}

	private static function actor() {
		$current = wp_get_current_user();
		if ( $current && $current->ID ) {
			return sprintf( '%s (#%d)', $current->user_login, $current->ID );
		}
		return defined( 'WP_CLI' ) && WP_CLI ? 'WP-CLI' : 'no logged-in user';
	}

	public static function on_user_register( $user_id ) {
		$user = get_userdata( $user_id );
		if ( ! $user || ! self::is_privileged( $user ) ) {
			return;
		}

		$detail = sprintf(
			'privileged account "%s" <%s> roles=[%s] created by %s',
			$user->user_login,
			$user->user_email,
			implode( ',', (array) $user->roles ),
			self::actor()
		);

		thessley_log_event( 'user-watchdog', 'privileged_user_created', 'noted', $detail );
		self::add_alert( 'privileged_user_created', $detail, $user_id );
		self::snapshot();
	}

	public static function on_set_role( $user_id, $role, $old_roles ) {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}

		// Creating a user fires this too, with no previous roles. That's not
		// an escalation, and user_register already reports it (and snapshots
		// when the account is privileged) — so there's nothing to do here.
		if ( empty( $old_roles ) ) {
			return;
		}

		$was = self::role_list_is_privileged( (array) $old_roles );
		$now = self::is_privileged( $user );

		// A change between two unprivileged roles (subscriber -> customer on
		// a shop, say) can't affect the privileged-account snapshot, and this
		// hook fires on routine membership activity.
		if ( ! $was && ! $now ) {
			return;
		}

		if ( $now && ! $was ) {
			$detail = sprintf(
				'"%s" escalated from [%s] to [%s] by %s',
				$user->user_login,
				implode( ',', (array) $old_roles ),
				$role,
				self::actor()
			);
			thessley_log_event( 'user-watchdog', 'privilege_escalation', 'noted', $detail );
			self::add_alert( 'privilege_escalation', $detail, $user_id );
		}

		self::snapshot();
	}

	private static function role_list_is_privileged( $roles ) {
		$wp_roles = wp_roles();
		foreach ( $roles as $role ) {
			$caps = $wp_roles->roles[ $role ]['capabilities'] ?? array();
			foreach ( self::SENSITIVE_CAPS as $cap ) {
				if ( ! empty( $caps[ $cap ] ) ) {
					return true;
				}
			}
		}
		return false;
	}

	public static function on_profile_update( $user_id, $old_user_data ) {
		$user = get_userdata( $user_id );
		if ( ! $user || ! self::is_privileged( $user ) ) {
			return;
		}

		// An attacker changing an admin's email is preparing a password
		// reset they can receive — worth flagging on its own.
		if ( $old_user_data && $old_user_data->user_email !== $user->user_email ) {
			$detail = sprintf(
				'admin "%s" email changed %s -> %s by %s',
				$user->user_login,
				$old_user_data->user_email,
				$user->user_email,
				self::actor()
			);
			thessley_log_event( 'user-watchdog', 'admin_email_changed', 'noted', $detail );
			self::add_alert( 'admin_email_changed', $detail, $user_id );
		}

		self::snapshot();
	}

	public static function on_user_deleted( $user_id ) {
		$snap = (array) get_option( 'thessley_user_watchdog_snapshot', array() );
		if ( isset( $snap[ $user_id ] ) ) {
			$detail = sprintf( 'privileged account "%s" deleted by %s', $snap[ $user_id ]['login'], self::actor() );
			thessley_log_event( 'user-watchdog', 'privileged_user_deleted', 'noted', $detail );
			self::add_alert( 'privileged_user_deleted', $detail, $user_id );
		}
		self::snapshot();
	}

	/**
	 * Snapshot diff. This is the layer that catches a backdoor writing
	 * directly to wp_users/wp_usermeta with raw SQL, which fires no hooks.
	 */
	public static function scan() {
		$previous = (array) get_option( 'thessley_user_watchdog_snapshot', array() );
		$current  = self::build_snapshot();

		if ( empty( $previous ) ) {
			self::snapshot();
			return array( 'new' => array(), 'changed' => array(), 'removed' => array() );
		}

		$new     = array();
		$changed = array();

		foreach ( $current as $id => $info ) {
			if ( ! isset( $previous[ $id ] ) ) {
				$new[ $id ] = $info;
				continue;
			}
			if ( $previous[ $id ] != $info ) { // phpcs:ignore WordPress.PHP.StrictComparisons.LooseComparison -- structural compare
				$changed[ $id ] = array( 'before' => $previous[ $id ], 'after' => $info );
			}
		}

		$removed = array_diff_key( $previous, $current );

		foreach ( $new as $id => $info ) {
			$detail = sprintf(
				'privileged account "%s" <%s> roles=[%s] appeared without a matching WordPress event — possible direct database write',
				$info['login'],
				$info['email'],
				implode( ',', $info['roles'] )
			);
			thessley_log_event( 'user-watchdog', 'unexplained_privileged_user', 'noted', $detail );
			self::add_alert( 'unexplained_privileged_user', $detail, $id );
		}

		foreach ( $changed as $id => $diff ) {
			$detail = sprintf(
				'privileged account "%s" changed: roles [%s] -> [%s], email %s -> %s',
				$diff['after']['login'],
				implode( ',', $diff['before']['roles'] ),
				implode( ',', $diff['after']['roles'] ),
				$diff['before']['email'],
				$diff['after']['email']
			);
			thessley_log_event( 'user-watchdog', 'privileged_user_changed', 'noted', $detail );
			self::add_alert( 'privileged_user_changed', $detail, $id );
		}

		self::snapshot();

		return array( 'new' => $new, 'changed' => $changed, 'removed' => $removed );
	}

	public static function handle_scan_now() {
		check_admin_referer( 'thessley_uw_scan_now' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}
		self::scan();
		wp_safe_redirect( add_query_arg( 'scanned', '1', wp_get_referer() ) );
		exit;
	}

	public static function handle_acknowledge() {
		check_admin_referer( 'thessley_uw_acknowledge' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}
		update_option( 'thessley_user_watchdog_alerts', array(), false );
		wp_safe_redirect( add_query_arg( 'acknowledged', '1', wp_get_referer() ) );
		exit;
	}

	public static function handle_save_settings() {
		check_admin_referer( 'thessley_uw_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}
		update_option( 'thessley_user_watchdog_enabled', isset( $_POST['enabled'] ) );
		update_option( 'thessley_user_watchdog_email', isset( $_POST['email_alerts'] ) );
		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}


	public static function render_page() {
		$alerts   = array_reverse( (array) get_option( 'thessley_user_watchdog_alerts', array() ) );
		$snapshot = (array) get_option( 'thessley_user_watchdog_snapshot', array() );
		$snap_at  = (int) get_option( 'thessley_user_watchdog_snapshot_at', 0 );

		Thessley_UI::open( 'user-watchdog' );

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only result flags set only by this module's own admin-post redirects, which already check_admin_referer() before redirecting.
		foreach ( array( 'saved' => 'Settings saved.', 'scanned' => 'Scan complete.', 'acknowledged' => 'Alerts cleared.' ) as $k => $msg ) {
			if ( isset( $_GET[ $k ] ) ) {
				Thessley_UI::notice( 'success', $msg );
			}
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		Thessley_UI::tiles(
			array(
				array(
					'icon'  => $alerts ? 'warning' : 'yes-alt',
					'tone'  => $alerts ? 'bad' : 'good',
					'value' => (string) count( $alerts ),
					'label' => 'outstanding alerts',
				),
				array(
					'icon'  => 'admin-users',
					'tone'  => 'quiet',
					'value' => (string) count( $snapshot ),
					'label' => 'privileged accounts',
				),
				array(
					'icon'  => 'clock',
					'tone'  => 'quiet',
					'value' => $snap_at ? date_i18n( 'H:i', $snap_at ) : '—',
					'label' => $snap_at ? 'snapshot ' . date_i18n( 'M j', $snap_at ) : 'no snapshot',
				),
			)
		);

		Thessley_UI::section( 'Alerts', 'warning' );
		if ( empty( $alerts ) ) {
			echo '<div class="thessley-empty"><span class="dashicons dashicons-yes-alt"></span><p>No outstanding alerts.</p></div>';
		} else {
			?>
			<div class="thessley-table-scroll">
			<table class="thessley-table">
				<thead><tr><th style="width:140px">When</th><th style="width:210px">Type</th><th>Detail</th></tr></thead>
				<tbody>
				<?php foreach ( $alerts as $a ) : ?>
					<tr>
						<td class="thessley-nowrap"><?php echo esc_html( date_i18n( 'M j, H:i', (int) $a['at'] ) ); ?></td>
						<td><?php Thessley_UI::badge( $a['type'], 'bad' ); ?></td>
						<td class="thessley-muted"><?php echo esc_html( $a['message'] ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
			</div>
			<div class="thessley-actions" style="margin-top:14px">
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<?php wp_nonce_field( 'thessley_uw_acknowledge' ); ?>
					<input type="hidden" name="action" value="thessley_uw_acknowledge">
					<?php submit_button( 'Acknowledge &amp; clear', 'secondary', 'submit', false ); ?>
				</form>
			</div>
			<?php
		}
		Thessley_UI::section_end();

		Thessley_UI::section( 'Privileged accounts', 'admin-users', sprintf( '%d account(s)', count( $snapshot ) ) );
		?>
		<div class="thessley-table-scroll">
		<table class="thessley-table">
			<thead><tr><th style="width:60px">ID</th><th style="width:180px">Login</th><th style="width:240px">Email</th><th>Roles</th></tr></thead>
			<tbody>
			<?php foreach ( $snapshot as $id => $info ) : ?>
				<tr>
					<td><?php echo esc_html( $id ); ?></td>
					<td><strong><?php echo esc_html( $info['login'] ); ?></strong></td>
					<td class="thessley-muted"><?php echo esc_html( $info['email'] ); ?></td>
					<td><?php foreach ( $info['roles'] as $r ) { Thessley_UI::badge( $r, 'quiet' ); echo ' '; } ?></td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
		</div>
		<div class="thessley-actions" style="margin-top:14px">
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'thessley_uw_scan_now' ); ?>
				<input type="hidden" name="action" value="thessley_uw_scan_now">
				<?php submit_button( 'Scan now', 'primary', 'submit', false ); ?>
			</form>
		</div>
		<?php
		Thessley_UI::section_end();
		?>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'thessley_uw_save_settings' ); ?>
			<input type="hidden" name="action" value="thessley_uw_save_settings">

			<?php Thessley_UI::section( 'Settings', 'admin-generic' ); ?>
				<?php
				Thessley_UI::row(
					'Enabled',
					function () {
						?>
						<label><input type="checkbox" name="enabled" <?php checked( get_option( 'thessley_user_watchdog_enabled', true ) ); ?>> Watch privileged account changes</label>
						<?php
					},
					'Checked live through WordPress hooks, and by an hourly snapshot diff that also catches accounts written straight to the database.'
				);

				Thessley_UI::row(
					'Email',
					function () {
						?>
						<label><input type="checkbox" name="email_alerts" <?php checked( get_option( 'thessley_user_watchdog_email', false ) ); ?>> Email the site admin when an alert fires</label>
						<?php
					},
					'Sent to <code>' . esc_html( get_option( 'admin_email' ) ) . '</code>, rate-limited to one every 15 minutes. Note that an attacker who already has admin access can change that address — the event log is the more reliable record.'
				);
				?>
			<?php Thessley_UI::section_end(); ?>

			<?php submit_button( 'Save settings' ); ?>
		</form>
		<?php
		Thessley_UI::close();
	}
}
