<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * One button to run every on-demand scan module at once, rather than
 * visiting File Integrity, Malware Scanner, Vulnerability Scan, User
 * Watchdog, and Hardening individually. Calls each module's scan method directly and
 * synchronously — the same thing each module's own "Scan Now" button
 * already does, just chained. An earlier version tried scheduling each
 * as an immediate one-off wp-cron event instead, to avoid making the
 * admin wait: that turned out to be unreliable rather than just slower,
 * since wp_schedule_single_event() silently refuses to add a new event
 * for a hook that already has ANY pending occurrence — and several
 * modules already register their own recurring schedule on activation,
 * so the one-off routinely got dropped with no error and no scan ran.
 * A raised time limit plus an honest "this may take a moment" in the UI
 * is the reliable version of the same idea.
 *
 * IP Blocklist and Geo Blocker have their own "Refresh now" actions but
 * aren't included here: those refresh external reputation data, not scan
 * this install for problems — a different kind of action than what
 * this page covers.
 */
class Thessley_Module_Scan_All {

	/** module slug => title, for the summary table. */
	private static function scans() {
		return array(
			'file-integrity'  => 'File Integrity',
			'malware-scanner' => 'Malware Scanner',
			'vuln-scanner'    => 'Vulnerability Scan',
			'user-watchdog'   => 'User Watchdog',
			'hardening'       => 'Hardening',
		);
	}

	public static function activate() {}
	public static function deactivate() {}

	public static function register() {
		add_action( 'admin_post_thessley_sa_run', array( __CLASS__, 'handle_run' ) );
		// JS runs each scan one at a time via this and updates the page as
		// each finishes; the admin_post handler above is the no-JS fallback,
		// still fully functional (one request, all five, then a redirect)
		// if JS is disabled or the fetch calls fail for some reason.
		add_action( 'wp_ajax_thessley_sa_run_one', array( __CLASS__, 'handle_run_one' ) );
		return __CLASS__;
	}

	private static function run_scan_for( $slug ) {
		switch ( $slug ) {
			case 'file-integrity':
				if ( class_exists( 'Thessley_Module_File_Integrity' ) ) {
					Thessley_Module_File_Integrity::run_scan();
				}
				break;
			case 'malware-scanner':
				if ( class_exists( 'Thessley_Module_Malware_Scanner' ) ) {
					Thessley_Module_Malware_Scanner::run_scan();
				}
				break;
			case 'vuln-scanner':
				if ( class_exists( 'Thessley_Module_Vuln_Scanner' ) ) {
					Thessley_Module_Vuln_Scanner::run_scan();
				}
				break;
			case 'user-watchdog':
				if ( class_exists( 'Thessley_Module_User_Watchdog' ) ) {
					Thessley_Module_User_Watchdog::scan();
				}
				break;
			case 'hardening':
				// Only the two read-only detection scans — not
				// write_root_guard()/write_uploads_guard(), which are a
				// different, mutating action (actually writing .htaccess
				// rules) that belongs to Save Settings, not a bulk "scan
				// everything" trigger.
				if ( class_exists( 'Thessley_Module_Hardening' ) ) {
					Thessley_Module_Hardening::scan_hidden_plugins();
					Thessley_Module_Hardening::scan_exposed_files();
				}
				break;
		}
	}

	/** Runs exactly one scan and returns its result — called once per scan by the JS, in sequence. */
	public static function handle_run_one() {
		check_ajax_referer( 'thessley_sa_run' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'Forbidden' ), 403 );
		}

		$scans = self::scans();
		$slug  = isset( $_POST['which'] ) ? sanitize_text_field( wp_unslash( $_POST['which'] ) ) : '';
		if ( ! isset( $scans[ $slug ] ) ) {
			wp_send_json_error( array( 'message' => 'Unknown scan' ), 400 );
		}

		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 60 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, Squiz.PHP.DiscouragedFunctions.Discouraged -- some hosts disable this; failing quietly is correct, not a bug to surface. Explicit, admin-triggered action, not something on the request path for a site visitor.
		}

		self::run_scan_for( $slug );
		update_option( 'thessley_scan_all_last_triggered', time(), false );

		list( $at, $count, $count_label ) = self::summary_row( $slug );

		wp_send_json_success(
			array(
				'label'       => $scans[ $slug ],
				'count'       => $count,
				'count_label' => $count_label,
				'at'          => $at ? date_i18n( 'M j, H:i', $at ) : '',
			)
		);
	}

	public static function handle_run() {
		check_admin_referer( 'thessley_sa_run' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		// File Integrity alone budgets up to 25s; the combined run of all
		// five can exceed a typical 30s default. This is an explicit,
		// admin-triggered action (not something on the request path for a
		// site visitor), so a generous ceiling here is the right trade-off.
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 120 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, Squiz.PHP.DiscouragedFunctions.Discouraged -- some hosts disable set_time_limit(); failing quietly is correct here, not a bug to surface. Explicit, admin-triggered action, not something on the request path for a site visitor.
		}

		foreach ( array_keys( self::scans() ) as $slug ) {
			self::run_scan_for( $slug );
		}

		update_option( 'thessley_scan_all_last_triggered', time(), false );

		wp_safe_redirect( add_query_arg( 'triggered', '1', wp_get_referer() ) );
		exit;
	}

	private static function summary_row( $module_slug ) {
		switch ( $module_slug ) {
			case 'file-integrity':
				// baseline_at is when a baseline was last (re)taken, not when
				// this routine check last ran — last_result.at is the one
				// that updates on every scan, same as the other three below.
				$last   = get_option( 'thessley_integrity_last_result', array() );
				$at     = (int) ( $last['at'] ?? 0 );
				$issues = count( (array) ( $last['core']['modified'] ?? array() ) )
					+ count( (array) ( $last['core']['missing'] ?? array() ) )
					+ count( (array) ( $last['diff']['added'] ?? array() ) )
					+ count( (array) ( $last['diff']['modified'] ?? array() ) );
				return array( $at, $issues, 'change(s)' );

			case 'malware-scanner':
				$last = get_option( 'thessley_malware_last_result', array() );
				$at   = (int) ( $last['at'] ?? 0 );
				return array( $at, count( (array) ( $last['findings'] ?? array() ) ), 'finding(s)' );

			case 'vuln-scanner':
				$last = get_option( 'thessley_vuln_last_result', array() );
				$at   = (int) ( $last['at'] ?? 0 );
				return array( $at, count( (array) ( $last['findings'] ?? array() ) ), 'finding(s)' );

			case 'user-watchdog':
				// snapshot() runs unconditionally at the end of every scan()
				// call (not just the first), so this timestamp does track
				// "last routine scan", unlike file-integrity's baseline_at.
				$at = (int) get_option( 'thessley_user_watchdog_snapshot_at', 0 );
				return array( $at, count( (array) get_option( 'thessley_user_watchdog_alerts', array() ) ), 'alert(s)' );

			case 'hardening':
				// Two separate scans, one combined row — same "at" either
				// way once both have actually run together via this page,
				// but take the later of the two rather than assume that.
				$exposed = get_option( 'thessley_hardening_exposed_result', array() );
				$hidden  = get_option( 'thessley_hardening_hidden_result', array() );
				$at      = max( (int) ( $exposed['at'] ?? 0 ), (int) ( $hidden['at'] ?? 0 ) );
				$count   = count( (array) ( $exposed['files'] ?? array() ) ) + count( (array) ( $hidden['hidden'] ?? array() ) );
				return array( $at, $count, 'issue(s)' );
		}
		return array( 0, 0, '' );
	}

	public static function render_page() {
		Thessley_UI::open( 'scan-all' );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only result flag set only by this module's own admin-post redirect, which already check_admin_referer()'d before redirecting.
		if ( isset( $_GET['triggered'] ) ) {
			Thessley_UI::notice( 'success', 'All five scans finished — see updated results below.' );
		}

		$last_triggered = (int) get_option( 'thessley_scan_all_last_triggered', 0 );

		Thessley_UI::tiles(
			array(
				array(
					'icon'  => 'search',
					'tone'  => 'quiet',
					'value' => '5',
					'label' => 'scans included',
				),
				array(
					'icon'  => 'clock',
					'tone'  => 'quiet',
					'value' => $last_triggered ? human_time_diff( $last_triggered ) . ' ago' : '—',
					'label' => 'last triggered',
				),
			)
		);

		?>
		<div class="thessley-actions" style="margin-bottom:14px">
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" id="thessley-sa-form">
				<?php wp_nonce_field( 'thessley_sa_run' ); ?>
				<input type="hidden" name="action" value="thessley_sa_run">
				<?php submit_button( 'Scan everything now', 'primary', 'submit', false, array( 'id' => 'thessley-sa-button' ) ); ?>
			</form>
			<p class="thessley-help" style="margin-top:6px" id="thessley-sa-help">
				Runs File Integrity, Malware Scanner, Vulnerability Scan, User Watchdog, and Hardening one at a time, updating the table below as each finishes.
			</p>
		</div>

		<?php Thessley_UI::section( 'Included scans', 'list-view' ); ?>
			<div class="thessley-table-scroll">
			<table class="thessley-table">
				<thead><tr><th>Scan</th><th style="width:130px">Last ran</th><th style="width:150px">Result</th><th style="width:110px"></th></tr></thead>
				<tbody>
				<?php foreach ( self::scans() as $slug => $title ) : ?>
					<?php list( $at, $count, $count_label ) = self::summary_row( $slug ); ?>
					<tr data-thessley-sa-slug="<?php echo esc_attr( $slug ); ?>">
						<td><?php echo esc_html( $title ); ?></td>
						<td class="thessley-nowrap thessley-sa-at"><?php echo $at ? esc_html( date_i18n( 'M j, H:i', $at ) ) : 'never'; ?></td>
						<td class="thessley-sa-result">
							<?php if ( ! $at ) : ?>
								<span class="thessley-muted">—</span>
							<?php elseif ( $count > 0 ) : ?>
								<?php Thessley_UI::badge( $count . ' ' . $count_label, 'bad', 'warning' ); ?>
							<?php else : ?>
								<?php Thessley_UI::badge( 'clean', 'good', 'yes-alt' ); ?>
							<?php endif; ?>
						</td>
						<td><a href="<?php echo esc_url( Thessley_Menu_Router::url( $slug ) ); ?>">View →</a></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
			</div>
		<?php Thessley_UI::section_end(); ?>

		<?php
		$thessley_sa_js = <<<'JS'
		(function () {
			var form = document.getElementById( 'thessley-sa-form' );
			var btn  = document.getElementById( 'thessley-sa-button' );
			var help = document.getElementById( 'thessley-sa-help' );
			if ( ! form || ! btn || ! window.fetch ) {
				return; // no JS / no fetch: form still submits normally, admin_post handles it
			}

			var slugs = __THESSLEY_SA_SLUGS__;
			var nonce = form.querySelector( 'input[name="_wpnonce"]' ).value;
			var ajaxUrl = '__THESSLEY_SA_AJAX_URL__';

			function setRowRunning( slug ) {
				var row = document.querySelector( '[data-thessley-sa-slug="' + slug + '"]' );
				if ( row ) {
					row.querySelector( '.thessley-sa-result' ).innerHTML = '<span class="thessley-muted">Running…</span>';
				}
			}

			function setRowDone( slug, data ) {
				var row = document.querySelector( '[data-thessley-sa-slug="' + slug + '"]' );
				if ( ! row ) { return; }
				if ( data.at ) {
					row.querySelector( '.thessley-sa-at' ).textContent = data.at;
				}
				var badge = ( data.count > 0 )
					? '<span class="thessley-badge thessley-badge--warn"><span class="dashicons dashicons-warning"></span>' + data.count + ' ' + data.count_label + '</span>'
					: '<span class="thessley-badge thessley-badge--good"><span class="dashicons dashicons-yes-alt"></span>clean</span>';
				row.querySelector( '.thessley-sa-result' ).innerHTML = badge;
			}

			function setRowFailed( slug ) {
				var row = document.querySelector( '[data-thessley-sa-slug="' + slug + '"]' );
				if ( row ) {
					row.querySelector( '.thessley-sa-result' ).innerHTML = '<span class="thessley-badge thessley-badge--bad">failed</span>';
				}
			}

			function runOne( slug ) {
				setRowRunning( slug );
				var body = new URLSearchParams();
				body.set( 'action', 'thessley_sa_run_one' );
				body.set( 'which', slug );
				body.set( '_wpnonce', nonce );
				return fetch( ajaxUrl, { method: 'POST', credentials: 'same-origin', body: body } )
					.then( function ( r ) { return r.json(); } )
					.then( function ( json ) {
						if ( json && json.success ) {
							setRowDone( slug, json.data );
						} else {
							setRowFailed( slug );
						}
					} )
					.catch( function () { setRowFailed( slug ); } );
			}

			form.addEventListener( 'submit', function ( e ) {
				e.preventDefault();
				btn.disabled = true;
				btn.textContent = 'Scanning…';
				help.textContent = 'Running now — each row below updates as its scan finishes.';

				var chain = Promise.resolve();
				slugs.forEach( function ( slug ) {
					chain = chain.then( function () { return runOne( slug ); } );
				} );
				chain.then( function () {
					btn.disabled = false;
					btn.textContent = 'Scan everything now';
					help.textContent = 'All five finished.';
				} );
			} );
		})();
		JS;

		$thessley_sa_js = str_replace(
			array( '__THESSLEY_SA_SLUGS__', '__THESSLEY_SA_AJAX_URL__' ),
			array( wp_json_encode( array_keys( self::scans() ) ), esc_url( admin_url( 'admin-ajax.php' ) ) ),
			$thessley_sa_js
		);

		wp_register_script( 'thessley-scan-all', false, array(), THESSLEY_VERSION, true );
		wp_enqueue_script( 'thessley-scan-all' );
		wp_add_inline_script( 'thessley-scan-all', $thessley_sa_js );

		Thessley_UI::close();
	}
}
