<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Brute-force protection for wp-login.php and the XML-RPC login surface.
 *
 * Runs on normal WP hooks rather than the early gate: authentication
 * results only exist once WP has bootstrapped. The *enforcement* still
 * happens early, because a lockout escalates the IP into the shared local
 * blocklist, which the early gate reads on the next request.
 */
class Thessley_Module_Login_Guard {

	const CRON_HOOK = 'thessley_login_guard_prune';

	const DEFAULT_MAX_FAILS   = 8;
	const DEFAULT_WINDOW_MIN  = 15;
	const DEFAULT_LOCKOUT_MIN = 60;

	// A person cannot submit three wrong logins in ten seconds; a bot can, and
	// low-and-slow botnets deliberately stay under the per-window threshold
	// above by giving every IP only a handful of tries (one campaign here
	// tried five usernames in one second from each of ~65 shared-hosting IPs
	// and never reached 8). This burst rule is what catches them.
	const DEFAULT_BURST_FAILS = 3;
	const BURST_SECONDS       = 10;

	public static function activate() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time(), 'hourly', self::CRON_HOOK );
		}
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	public static function register() {
		add_action( 'admin_post_thessley_lg_save_settings', array( __CLASS__, 'handle_save_settings' ) );
		add_action( self::CRON_HOOK, array( __CLASS__, 'prune' ) );

		if ( get_option( 'thessley_login_guard_enabled', true ) ) {
			add_action( 'wp_login_failed', array( __CLASS__, 'on_login_failed' ) );
			add_action( 'wp_login', array( __CLASS__, 'on_login_success' ), 10, 2 );
			add_filter( 'authenticate', array( __CLASS__, 'maybe_block_login' ), 30, 3 );

			if ( get_option( 'thessley_login_guard_generic_errors', true ) ) {
				add_filter( 'login_errors', array( __CLASS__, 'genericize_errors' ) );
			}
		}

		return __CLASS__;
	}

	/**
	 * Per-IP state lives in its own transient rather than one shared option.
	 *
	 * A distributed credential-stuffing run touches a huge number of source
	 * IPs, and a single option meant every failed login unserialised,
	 * appended to and rewrote the entire structure — the attack made itself
	 * progressively more expensive to defend against. Transients also expire
	 * on their own, so lockouts release without depending on cron.
	 */
	private static function entry_key( $ip ) {
		return 'thessley_lg_' . md5( $ip );
	}

	private static function get_entry( $ip ) {
		$entry = get_transient( self::entry_key( $ip ) );
		return is_array( $entry ) ? $entry : array( 'fails' => array(), 'locked_until' => 0 );
	}

	private static function save_entry( $ip, $entry ) {
		$window  = max( 1, (int) get_option( 'thessley_login_guard_window_min', self::DEFAULT_WINDOW_MIN ) ) * MINUTE_IN_SECONDS;
		$expires = max( $window, (int) ( $entry['locked_until'] ?? 0 ) - time() );

		set_transient( self::entry_key( $ip ), $entry, $expires );
		self::remember_ip( $ip );
	}

	private static function clear_entry( $ip ) {
		delete_transient( self::entry_key( $ip ) );
		self::forget_ip( $ip );
	}

	/**
	 * Small index of currently-locked IPs, purely so the admin screen can
	 * list them — transients aren't enumerable. Only locked IPs go in here,
	 * not every IP that ever failed a login, so it stays bounded.
	 */
	private static function remember_ip( $ip ) {
		$entry = self::get_entry( $ip );
		if ( empty( $entry['locked_until'] ) || $entry['locked_until'] < time() ) {
			return;
		}

		$index = (array) get_option( 'thessley_login_guard_locked', array() );
		$index[ $ip ] = (int) $entry['locked_until'];

		// Hard cap: under a very wide attack this list is for display only,
		// and enforcement never reads it — so dropping the oldest is safe.
		if ( count( $index ) > 500 ) {
			asort( $index );
			$index = array_slice( $index, -500, null, true );
		}

		update_option( 'thessley_login_guard_locked', $index, false );
	}

	private static function forget_ip( $ip ) {
		$index = (array) get_option( 'thessley_login_guard_locked', array() );
		if ( isset( $index[ $ip ] ) ) {
			unset( $index[ $ip ] );
			update_option( 'thessley_login_guard_locked', $index, false );
		}
	}

	/** @return array<string,int> ip => locked_until, expired entries dropped */
	private static function locked_ips() {
		$index   = (array) get_option( 'thessley_login_guard_locked', array() );
		$now     = time();
		$active  = array_filter(
			$index,
			function ( $until ) use ( $now ) {
				return (int) $until > $now;
			}
		);

		if ( count( $active ) !== count( $index ) ) {
			update_option( 'thessley_login_guard_locked', $active, false );
		}

		return $active;
	}

	public static function on_login_failed( $username ) {
		$ip = thessley_client_ip();
		if ( '' === $ip ) {
			return;
		}

		// Exempt IPs are never enforced against, so don't accumulate state
		// for them — it would show up as a phantom "locked out" row that
		// never actually blocks anything.
		if ( thessley_ip_is_exempt( $ip ) ) {
			return;
		}

		$window = max( 1, (int) get_option( 'thessley_login_guard_window_min', self::DEFAULT_WINDOW_MIN ) ) * MINUTE_IN_SECONDS;
		$max    = max( 1, (int) get_option( 'thessley_login_guard_max_fails', self::DEFAULT_MAX_FAILS ) );
		$now    = time();

		$entry = self::get_entry( $ip );

		// Keep only failures inside the rolling window.
		$entry['fails'] = array_values(
			array_filter(
				$entry['fails'],
				function ( $ts ) use ( $now, $window ) {
					return $ts > $now - $window;
				}
			)
		);
		$entry['fails'][] = $now;

		$count = count( $entry['fails'] );

		$burst_max = (int) get_option( 'thessley_login_guard_burst_fails', self::DEFAULT_BURST_FAILS );
		$burst     = 0;
		if ( $burst_max > 0 ) {
			$cutoff = $now - self::BURST_SECONDS;
			$burst  = count(
				array_filter(
					$entry['fails'],
					function ( $ts ) use ( $cutoff ) {
						return $ts > $cutoff;
					}
				)
			);
		}
		$is_burst = $burst_max > 0 && $burst >= $burst_max;

		if ( $count >= $max || $is_burst ) {
			$lockout = max( 1, (int) get_option( 'thessley_login_guard_lockout_min', self::DEFAULT_LOCKOUT_MIN ) );
			$entry['locked_until'] = $now + ( $lockout * MINUTE_IN_SECONDS );
			$entry['fails']        = array();

			self::save_entry( $ip, $entry );

			thessley_log_event(
				'login-guard',
				'lockout',
				'blocked',
				$is_burst
					? sprintf( '%d failed logins in %d s (burst); locked %d min; last user "%s"', $burst, self::BURST_SECONDS, $lockout, $username )
					: sprintf( '%d failed logins in %d min; locked %d min; last user "%s"', $count, (int) get_option( 'thessley_login_guard_window_min', self::DEFAULT_WINDOW_MIN ), $lockout, $username )
			);

			// Escalate to the shared local blocklist so the early gate stops
			// this IP before WP even bootstraps on subsequent requests.
			if ( get_option( 'thessley_login_guard_escalate', true ) ) {
				thessley_local_blocklist_add( $ip, $is_burst ? 'login-guard: login burst' : 'login-guard: brute force', $lockout * MINUTE_IN_SECONDS );
			}
			return;
		}

		self::save_entry( $ip, $entry );

		thessley_log_event( 'login-guard', 'login_failed', 'noted', sprintf( 'attempt %d/%d for user "%s"', $count, $max, $username ) );
	}

	public static function on_login_success( $user_login, $user = null ) {
		$ip = thessley_client_ip();
		if ( '' === $ip ) {
			return;
		}

		// A successful login clears the counter for that IP — otherwise a
		// user who fat-fingers their password a few times, then gets in,
		// stays one typo away from a lockout for the rest of the window.
		self::clear_entry( $ip );

		thessley_log_event( 'login-guard', 'login_success', 'noted', sprintf( 'user "%s"', $user_login ) );
	}

	/**
	 * @param WP_User|WP_Error|null $user
	 * @return WP_User|WP_Error|null
	 */
	public static function maybe_block_login( $user, $username, $password ) {
		// Nothing to do for an empty submit (the login form's own first load).
		if ( empty( $username ) && empty( $password ) ) {
			return $user;
		}

		$ip = thessley_client_ip();
		if ( '' === $ip || thessley_ip_is_exempt( $ip ) ) {
			return $user; // LAN/dev/trusted crawler ranges are never locked out
		}

		$entry = self::get_entry( $ip );
		$until = (int) ( $entry['locked_until'] ?? 0 );

		if ( $until > time() ) {
			$minutes = max( 1, (int) ceil( ( $until - time() ) / MINUTE_IN_SECONDS ) );

			thessley_log_event( 'login-guard', 'locked_attempt', 'blocked', sprintf( 'attempt while locked; %d min remaining', $minutes ) );

			return new WP_Error(
				'thessley_locked_out',
				sprintf(
					/* translators: %d: minutes remaining */
					__( '<strong>Too many failed login attempts.</strong> Try again in %d minutes.', 'thessley-security-hardening' ),
					$minutes
				)
			);
		}

		return $user;
	}

	/**
	 * WP's default login errors distinguish "unknown username" from "wrong
	 * password", which confirms which accounts exist. Collapse to one
	 * message so a brute-forcer can't enumerate valid users for free.
	 */
	public static function genericize_errors( $error ) {
		// Don't mask our own lockout message — that's rate-limit state,
		// identical for every visitor regardless of what they typed, not
		// a signal about any particular account.
		//
		// Passkey Login's "Password login is disabled"/"requires app
		// confirmation" messages used to be exempted here too, on the
		// theory that a user told their password is "invalid" when it
		// was actually correct would have no way to know what's really
		// going on. Removed: both messages only ever fire *after*
		// Passkey Login's own check already confirmed the submitted
		// password was correct (see maybe_block_password_login()'s
		// `$user instanceof WP_User` guard) — exempting them handed a
		// credential-stuffing attacker an exact, distinguishable signal
		// that a guessed password was right, for any account in
		// required/2fa mode. That's precisely the username/password-
		// validity oracle this function exists to prevent. The one place
		// that message actually matters for a legitimate user — the
		// real 2fa browser flow — never reaches this filter at all (it's
		// a redirect to the app-confirmation page, not an error), so
		// genericizing here costs nothing on the path anyone actually
		// uses; it only closes the oracle on the uncommon paths
		// (required-mode's hidden-form bypass, XML-RPC, etc).
		if ( is_string( $error ) && false !== strpos( $error, 'Too many failed login attempts' ) ) {
			return $error;
		}
		return __( '<strong>Error:</strong> Invalid username, email address or password.', 'thessley-security-hardening' );
	}

	/**
	 * Per-IP state expires with its own transient now, so this only tidies
	 * the display index of locked IPs. Kept on cron so the list doesn't
	 * accumulate entries on a site nobody visits in wp-admin.
	 */
	public static function prune() {
		self::locked_ips();
	}

	/** Clears every lockout — used by the "clear all" maintenance toggle. */
	private static function clear_all_lockouts() {
		foreach ( array_keys( self::locked_ips() ) as $ip ) {
			delete_transient( self::entry_key( $ip ) );
		}
		update_option( 'thessley_login_guard_locked', array(), false );
	}


	public static function handle_save_settings() {
		check_admin_referer( 'thessley_lg_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		update_option( 'thessley_login_guard_enabled', isset( $_POST['enabled'] ) );
		update_option( 'thessley_login_guard_escalate', isset( $_POST['escalate'] ) );
		update_option( 'thessley_login_guard_generic_errors', isset( $_POST['generic_errors'] ) );
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- (int) cast is itself the sanitizer; wp_unslash() would be a no-op on values about to be cast to int.
		update_option( 'thessley_login_guard_max_fails', max( 1, (int) ( $_POST['max_fails'] ?? self::DEFAULT_MAX_FAILS ) ) );
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- same as max_fails above.
		update_option( 'thessley_login_guard_window_min', max( 1, (int) ( $_POST['window_min'] ?? self::DEFAULT_WINDOW_MIN ) ) );
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- same as max_fails above.
		update_option( 'thessley_login_guard_lockout_min', max( 1, (int) ( $_POST['lockout_min'] ?? self::DEFAULT_LOCKOUT_MIN ) ) );
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- same as max_fails above; 0 turns the burst rule off.
		update_option( 'thessley_login_guard_burst_fails', max( 0, (int) ( $_POST['burst_fails'] ?? self::DEFAULT_BURST_FAILS ) ) );

		if ( isset( $_POST['clear_lockouts'] ) ) {
			self::clear_all_lockouts();
		}

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function render_settings_page() {
		$enabled     = get_option( 'thessley_login_guard_enabled', true );
		$escalate    = get_option( 'thessley_login_guard_escalate', true );
		$generic     = get_option( 'thessley_login_guard_generic_errors', true );
		$max_fails   = (int) get_option( 'thessley_login_guard_max_fails', self::DEFAULT_MAX_FAILS );
		$window_min  = (int) get_option( 'thessley_login_guard_window_min', self::DEFAULT_WINDOW_MIN );
		$lockout_min = (int) get_option( 'thessley_login_guard_lockout_min', self::DEFAULT_LOCKOUT_MIN );
		$burst_fails = (int) get_option( 'thessley_login_guard_burst_fails', self::DEFAULT_BURST_FAILS );

		$locked = self::locked_ips();
		arsort( $locked );

		Thessley_UI::open( 'login-guard' );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only result flag set only by this module's own admin-post redirect, which already check_admin_referer()'d before redirecting.
		if ( isset( $_GET['saved'] ) ) {
			Thessley_UI::notice( 'success', 'Settings saved.' );
		}

		Thessley_UI::section( 'Currently locked out', 'lock', sprintf( '%d active', count( $locked ) ) );
		if ( empty( $locked ) ) {
			echo '<div class="thessley-empty"><span class="dashicons dashicons-yes-alt"></span><p>No IPs are locked out.</p></div>';
		} else {
			?>
			<div class="thessley-table-scroll">
			<table class="thessley-table">
				<thead><tr><th style="width:180px">IP</th><th>Locked until</th></tr></thead>
				<tbody>
				<?php foreach ( $locked as $ip => $until ) : ?>
					<tr>
						<td class="thessley-nowrap"><code><?php echo esc_html( $ip ); ?></code></td>
						<td class="thessley-nowrap"><?php echo esc_html( date_i18n( 'Y-m-d H:i', (int) $until ) ); ?></td>
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
			<?php wp_nonce_field( 'thessley_lg_save_settings' ); ?>
			<input type="hidden" name="action" value="thessley_lg_save_settings">

			<?php Thessley_UI::section( 'Settings', 'admin-generic' ); ?>

				<?php
				Thessley_UI::row(
					'Enabled',
					function () use ( $enabled ) {
						?>
						<label><input type="checkbox" name="enabled" <?php checked( $enabled ); ?>> Rate-limit failed logins</label>
						<?php
					}
				);

				Thessley_UI::row(
					'Threshold',
					function () use ( $max_fails, $window_min ) {
						?>
						<input type="number" name="max_fails" value="<?php echo esc_attr( $max_fails ); ?>" min="1" style="width:5em">
						failures within
						<input type="number" name="window_min" value="<?php echo esc_attr( $window_min ); ?>" min="1" style="width:5em">
						minutes
						<?php
					},
					'A successful login clears the counter for that IP, so a few typos before getting in do not leave someone one mistake from a lockout.'
				);

				Thessley_UI::row(
					'Burst rule',
					function () use ( $burst_fails ) {
						?>
						<input type="number" name="burst_fails" value="<?php echo esc_attr( $burst_fails ); ?>" min="0" style="width:5em">
						failures within <?php echo esc_html( self::BURST_SECONDS ); ?> seconds
						<?php
					},
					'Locks an IP immediately when it fires failed logins faster than a person can type. Catches botnets that give each IP only a few tries to stay under the threshold above. Set to 0 to turn it off.'
				);

				Thessley_UI::row(
					'Lockout length',
					function () use ( $lockout_min ) {
						?>
						<input type="number" name="lockout_min" value="<?php echo esc_attr( $lockout_min ); ?>" min="1" style="width:5em"> minutes
						<?php
					}
				);

				Thessley_UI::row(
					'On lockout',
					function () use ( $escalate ) {
						?>
						<label><input type="checkbox" name="escalate" <?php checked( $escalate ); ?>> Also add the IP to the local blocklist</label>
						<?php
					},
					'Blocks them at the early gate for the lockout duration, before WordPress loads — cheaper than serving the login page to a bot.'
				);

				Thessley_UI::row(
					'Login errors',
					function () use ( $generic ) {
						?>
						<label><input type="checkbox" name="generic_errors" <?php checked( $generic ); ?>> Use a generic "invalid credentials" message</label>
						<?php
					},
					'WordPress by default says whether the <em>username</em> exists, which confirms valid accounts to an attacker for free.'
				);

				Thessley_UI::row(
					'Maintenance',
					function () {
						?>
						<label><input type="checkbox" name="clear_lockouts"> Clear all current lockouts on save</label>
						<?php
					}
				);
				?>

			<?php Thessley_UI::section_end(); ?>

			<?php submit_button( 'Save settings' ); ?>
		</form>
		<?php
		Thessley_UI::close();
	}
}
