<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Flags installed components that are plausible attack surface.
 *
 * Three signals, in decreasing order of certainty:
 *
 *  1. Outdated — an update is available. Taken from WordPress's own update
 *     data, so it's exact and needs no third-party service.
 *  2. Removed/abandoned — the plugin is gone from the .org directory (very
 *     often a pulled-for-security event) or hasn't been touched in years.
 *  3. Known CVEs — real vulnerability records, but this needs a WPScan API
 *     token. Optional: everything above still works without one.
 */
class Thessley_Module_Vuln_Scanner {

	const CRON_HOOK      = 'thessley_vuln_scan';
	const STALE_YEARS    = 2;
	const WPSCAN_API     = 'https://wpscan.com/api/v3/';

	public static function activate() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + ( 2 * HOUR_IN_SECONDS ), 'daily', self::CRON_HOOK );
		}
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	public static function register() {
		add_action( self::CRON_HOOK, array( __CLASS__, 'run_scan' ) );
		add_action( 'admin_post_thessley_vs_scan_now', array( __CLASS__, 'handle_scan_now' ) );
		add_action( 'admin_post_thessley_vs_save_settings', array( __CLASS__, 'handle_save_settings' ) );

		return __CLASS__;
	}

	/** @return array<int,array> installed plugins + themes, normalised */
	private static function installed_components() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$out    = array();
		$active = (array) get_option( 'active_plugins', array() );

		foreach ( get_plugins() as $file => $data ) {
			$out[] = array(
				'type'    => 'plugin',
				'file'    => $file,
				'slug'    => dirname( $file ) !== '.' ? dirname( $file ) : basename( $file, '.php' ),
				'name'    => $data['Name'],
				'version' => $data['Version'],
				'active'  => in_array( $file, $active, true ),
			);
		}

		$current_theme = get_stylesheet();
		$parent_theme  = get_template();

		foreach ( wp_get_themes() as $slug => $theme ) {
			$out[] = array(
				'type'    => 'theme',
				'file'    => $slug,
				'slug'    => $slug,
				'name'    => $theme->get( 'Name' ),
				'version' => $theme->get( 'Version' ),
				'active'  => in_array( $slug, array( $current_theme, $parent_theme ), true ),
			);
		}

		return $out;
	}

	/** Pending updates, straight from WP's own update transients. */
	private static function pending_updates() {
		$out = array( 'plugins' => array(), 'themes' => array(), 'core' => null );

		if ( ! function_exists( 'get_plugin_updates' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}

		wp_update_plugins();
		wp_update_themes();

		foreach ( (array) get_plugin_updates() as $file => $data ) {
			$out['plugins'][ $file ] = $data->update->new_version ?? '';
		}
		foreach ( (array) get_theme_updates() as $slug => $data ) {
			$out['themes'][ $slug ] = $data->update['new_version'] ?? '';
		}

		$core = get_site_transient( 'update_core' );
		if ( ! empty( $core->updates[0] ) && 'upgrade' === $core->updates[0]->response ) {
			$out['core'] = $core->updates[0]->current;
		}

		return $out;
	}

	/**
	 * @return array{closed:bool,last_updated:string,error:string}
	 */
	private static function directory_status( $slug ) {
		$cache_key = 'thessley_dirstat_' . md5( $slug );
		$cached    = get_transient( $cache_key );
		if ( is_array( $cached ) ) {
			return $cached;
		}

		$response = wp_remote_get(
			'https://api.wordpress.org/plugins/info/1.0/' . rawurlencode( $slug ) . '.json',
			array( 'timeout' => 15 )
		);

		$status = array( 'closed' => false, 'last_updated' => '', 'error' => '' );

		if ( is_wp_error( $response ) ) {
			$status['error'] = $response->get_error_message();
			// Don't cache transport failures for long — the plugin isn't
			// necessarily gone, we just couldn't reach the API.
			set_transient( $cache_key, $status, HOUR_IN_SECONDS );
			return $status;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( ! empty( $body['closed'] ) ) {
			$status['closed'] = true;
		}
		if ( ! empty( $body['last_updated'] ) ) {
			$status['last_updated'] = $body['last_updated'];
		}
		if ( isset( $body['error'] ) ) {
			// "Plugin not found" — either never on .org (custom/premium) or
			// removed. Reported as unknown rather than assumed malicious.
			$status['error'] = (string) $body['error'];
		}

		set_transient( $cache_key, $status, DAY_IN_SECONDS );
		return $status;
	}

	/** @return array{items:array,error:string} */
	private static function wpscan_lookup( $components ) {
		$token = trim( (string) get_option( 'thessley_vuln_wpscan_token', '' ) );
		if ( '' === $token ) {
			return array( 'items' => array(), 'error' => '' );
		}

		$found = array();
		$error = '';

		foreach ( $components as $c ) {
			if ( 'plugin' !== $c['type'] ) {
				continue; // themes use a different endpoint; plugins are the bulk of real risk
			}

			$cache_key = 'thessley_wpscan_' . md5( $c['slug'] . '|' . $c['version'] );
			$cached    = get_transient( $cache_key );
			if ( is_array( $cached ) ) {
				if ( $cached ) {
					$found[ $c['slug'] ] = $cached;
				}
				continue;
			}

			$response = wp_remote_get(
				self::WPSCAN_API . 'plugins/' . rawurlencode( $c['slug'] ),
				array(
					'timeout' => 20,
					'headers' => array( 'Authorization' => 'Token token=' . $token ),
				)
			);

			if ( is_wp_error( $response ) ) {
				$error = $response->get_error_message();
				break;
			}

			$code = wp_remote_retrieve_response_code( $response );
			if ( 429 === $code ) {
				$error = 'WPScan API rate limit reached — remaining components were skipped this run.';
				break;
			}
			if ( 401 === $code || 403 === $code ) {
				$error = 'WPScan API rejected the token.';
				break;
			}
			if ( 200 !== $code ) {
				set_transient( $cache_key, array(), HOUR_IN_SECONDS );
				continue;
			}

			$body  = json_decode( wp_remote_retrieve_body( $response ), true );
			$vulns = $body[ $c['slug'] ]['vulnerabilities'] ?? array();

			$relevant = array();
			foreach ( (array) $vulns as $v ) {
				$fixed = $v['fixed_in'] ?? null;
				// No fixed_in means unpatched — always relevant. Otherwise
				// only flag if the installed version predates the fix.
				if ( null === $fixed || version_compare( $c['version'], $fixed, '<' ) ) {
					$relevant[] = array(
						'title'    => $v['title'] ?? 'Unknown',
						'fixed_in' => $fixed,
					);
				}
			}

			set_transient( $cache_key, $relevant, DAY_IN_SECONDS );
			if ( $relevant ) {
				$found[ $c['slug'] ] = $relevant;
			}
		}

		return array( 'items' => $found, 'error' => $error );
	}

	public static function run_scan() {
		$components = self::installed_components();
		$updates    = self::pending_updates();

		$findings = array();

		foreach ( $components as $c ) {
			$issues = array();

			$new_version = 'plugin' === $c['type']
				? ( $updates['plugins'][ $c['file'] ] ?? null )
				: ( $updates['themes'][ $c['file'] ] ?? null );

			if ( $new_version ) {
				$issues[] = array(
					'kind'   => 'outdated',
					'detail' => sprintf( 'Update available: %s → %s', $c['version'], $new_version ),
				);
			}

			if ( 'plugin' === $c['type'] && get_option( 'thessley_vuln_check_directory', true ) ) {
				$status = self::directory_status( $c['slug'] );

				if ( $status['closed'] ) {
					$issues[] = array(
						'kind'   => 'closed',
						'detail' => 'Removed from the WordPress.org directory — often a pulled-for-security event.',
					);
				} elseif ( '' !== $status['last_updated'] ) {
					$ts = strtotime( $status['last_updated'] );
					if ( $ts && $ts < strtotime( '-' . self::STALE_YEARS . ' years' ) ) {
						$issues[] = array(
							'kind'   => 'stale',
							'detail' => sprintf( 'No release since %s — likely unmaintained.', gmdate( 'Y-m-d', $ts ) ),
						);
					}
				}
			}

			if ( $issues ) {
				$findings[] = array_merge( $c, array( 'issues' => $issues ) );
			}
		}

		$wpscan = self::wpscan_lookup( $components );

		// Index by slug and assign through it: an earlier version walked
		// $findings by reference and left $f dangling when it took `continue 2`,
		// so a later by-value foreach over the same array overwrote the last
		// element on every iteration.
		$index_by_slug = array();
		foreach ( $findings as $i => $f ) {
			$index_by_slug[ $f['slug'] ] = $i;
		}

		foreach ( $wpscan['items'] as $slug => $vulns ) {
			$issues = array();
			foreach ( $vulns as $v ) {
				$issues[] = array(
					'kind'   => 'cve',
					'detail' => $v['title'] . ( $v['fixed_in'] ? sprintf( ' (fixed in %s)', $v['fixed_in'] ) : ' (no fix available)' ),
				);
			}

			if ( isset( $index_by_slug[ $slug ] ) ) {
				$findings[ $index_by_slug[ $slug ] ]['issues'] = array_merge(
					$findings[ $index_by_slug[ $slug ] ]['issues'],
					$issues
				);
				continue;
			}

			// Component had no other issue but does have a CVE.
			foreach ( $components as $c ) {
				if ( $c['slug'] === $slug ) {
					$findings[]                  = array_merge( $c, array( 'issues' => $issues ) );
					$index_by_slug[ $c['slug'] ] = count( $findings ) - 1;
					break;
				}
			}
		}

		$result = array(
			'at'            => time(),
			'core_update'   => $updates['core'],
			'findings'      => $findings,
			'scanned_count' => count( $components ),
			'wpscan_error'  => $wpscan['error'],
		);

		update_option( 'thessley_vuln_last_result', $result, false );

		$critical = 0;
		foreach ( $findings as $f ) {
			foreach ( $f['issues'] as $i ) {
				if ( in_array( $i['kind'], array( 'cve', 'closed' ), true ) ) {
					$critical++;
				}
			}
		}

		if ( $findings ) {
			thessley_log_event(
				'vuln-scanner',
				'scan_findings',
				'noted',
				sprintf( '%d component(s) flagged, %d high-severity, of %d scanned', count( $findings ), $critical, count( $components ) )
			);
		}

		return $result;
	}

	public static function handle_scan_now() {
		check_admin_referer( 'thessley_vs_scan_now' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}
		self::run_scan();
		wp_safe_redirect( add_query_arg( 'scanned', '1', wp_get_referer() ) );
		exit;
	}

	public static function handle_save_settings() {
		check_admin_referer( 'thessley_vs_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		update_option( 'thessley_vuln_check_directory', isset( $_POST['check_directory'] ) );
		update_option( 'thessley_vuln_wpscan_token', sanitize_text_field( wp_unslash( $_POST['wpscan_token'] ?? '' ) ) );

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}


	private static function kind_tone( $kind ) {
		$map = array(
			'cve'      => array( 'Known vulnerability', 'bad' ),
			'closed'   => array( 'Removed from directory', 'bad' ),
			'stale'    => array( 'Unmaintained', 'warn' ),
			'outdated' => array( 'Update available', 'warn' ),
		);
		return $map[ $kind ] ?? array( $kind, 'quiet' );
	}

	public static function render_page() {
		$last  = get_option( 'thessley_vuln_last_result', array() );
		$token = (string) get_option( 'thessley_vuln_wpscan_token', '' );

		Thessley_UI::open( 'vuln-scanner' );

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only result flags set only by this module's own admin-post redirects, which already check_admin_referer() before redirecting.
		if ( isset( $_GET['saved'] ) ) {
			Thessley_UI::notice( 'success', 'Settings saved.' );
		}
		if ( isset( $_GET['scanned'] ) ) {
			Thessley_UI::notice( 'success', 'Scan complete.' );
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		if ( empty( $last ) ) {
			Thessley_UI::notice( 'info', 'No scan has run yet.' );
		} else {
			$findings = (array) $last['findings'];
			$critical = 0;
			foreach ( $findings as $f ) {
				foreach ( $f['issues'] as $i ) {
					if ( in_array( $i['kind'], array( 'cve', 'closed' ), true ) ) {
						$critical++;
						break;
					}
				}
			}

			Thessley_UI::tiles(
				array(
					array(
						'icon'  => $findings ? 'warning' : 'yes-alt',
						'tone'  => $critical ? 'bad' : ( $findings ? 'warn' : 'good' ),
						'value' => (string) count( $findings ),
						'label' => 'components flagged',
					),
					array(
						'icon'  => 'shield-alt',
						'tone'  => $critical ? 'bad' : 'good',
						'value' => (string) $critical,
						'label' => 'high severity',
					),
					array(
						'icon'  => 'search',
						'tone'  => 'quiet',
						'value' => (string) (int) ( $last['scanned_count'] ?? 0 ),
						'label' => 'components checked',
					),
					array(
						'icon'  => 'clock',
						'tone'  => 'quiet',
						'value' => date_i18n( 'H:i', (int) $last['at'] ),
						'label' => 'last scan ' . date_i18n( 'M j', (int) $last['at'] ),
					),
				)
			);

			if ( ! empty( $last['wpscan_error'] ) ) {
				Thessley_UI::notice( 'warning', $last['wpscan_error'] );
			}
			if ( ! empty( $last['core_update'] ) ) {
				Thessley_UI::notice( 'warning', 'WordPress core update available: ' . $last['core_update'] );
			}

			Thessley_UI::section( 'Findings', 'warning' );
			if ( empty( $findings ) ) {
				echo '<div class="thessley-empty"><span class="dashicons dashicons-yes-alt"></span><p>Nothing flagged.</p></div>';
			} else {
				?>
				<div class="thessley-table-scroll">
				<table class="thessley-table">
					<thead>
						<tr>
							<th style="width:230px">Component</th>
							<th style="width:70px">Type</th>
							<th style="width:80px">Version</th>
							<th style="width:70px">Active</th>
							<th>Findings</th>
						</tr>
					</thead>
					<tbody>
					<?php foreach ( $findings as $f ) : ?>
						<tr>
							<td>
								<strong><?php echo esc_html( $f['name'] ); ?></strong><br>
								<code style="font-size:11px"><?php echo esc_html( $f['slug'] ); ?></code>
							</td>
							<td class="thessley-muted"><?php echo esc_html( $f['type'] ); ?></td>
							<td><?php echo esc_html( $f['version'] ); ?></td>
							<td>
								<?php if ( $f['active'] ) : ?>
									<?php Thessley_UI::badge( 'active', 'warn' ); ?>
								<?php else : ?>
									<span class="thessley-muted">no</span>
								<?php endif; ?>
							</td>
							<td>
								<?php foreach ( $f['issues'] as $issue ) : ?>
									<?php list( $label, $tone ) = self::kind_tone( $issue['kind'] ); ?>
									<div style="margin-bottom:5px">
										<?php Thessley_UI::badge( $label, $tone ); ?>
										<span class="thessley-muted"><?php echo esc_html( $issue['detail'] ); ?></span>
									</div>
								<?php endforeach; ?>
							</td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
				</div>
				<p class="thessley-help">An inactive plugin still has files on disk that can be reached directly — uninstall what you do not use rather than just deactivating it.</p>
				<?php
			}
			Thessley_UI::section_end();
		}
		?>

		<div class="thessley-actions" style="margin-bottom:18px">
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'thessley_vs_scan_now' ); ?>
				<input type="hidden" name="action" value="thessley_vs_scan_now">
				<?php submit_button( 'Scan now', 'primary', 'submit', false ); ?>
			</form>
		</div>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'thessley_vs_save_settings' ); ?>
			<input type="hidden" name="action" value="thessley_vs_save_settings">

			<?php Thessley_UI::section( 'Settings', 'admin-generic' ); ?>
				<?php
				Thessley_UI::row(
					'Directory checks',
					function () {
						?>
						<label><input type="checkbox" name="check_directory" <?php checked( get_option( 'thessley_vuln_check_directory', true ) ); ?>> Check WordPress.org for removed / unmaintained plugins</label>
						<?php
					},
					'Results are cached for a day. Plugins that were never on .org (premium, custom) are simply not reported on.'
				);

				Thessley_UI::row(
					'WPScan API token',
					function () use ( $token ) {
						?>
						<input type="text" name="wpscan_token" value="<?php echo esc_attr( $token ); ?>" style="width:26em" autocomplete="off">
						<?php
						if ( '' !== $token ) {
							echo ' ';
							Thessley_UI::badge( 'configured', 'good', 'yes-alt' );
						}
					},
					'Optional. Adds real CVE data from <a href="https://wpscan.com/api" target="_blank" rel="noopener">wpscan.com/api</a> (free tier: 25 requests/day, which is why results are cached for 24h). Everything else on this page works without a token.'
				);
				?>
			<?php Thessley_UI::section_end(); ?>

			<?php submit_button( 'Save settings' ); ?>
		</form>
		<?php
		Thessley_UI::close();
	}
}
