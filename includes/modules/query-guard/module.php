<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Thessley_Module_Query_Guard {

	const CATEGORIES = array(
		'sqli'      => 'SQL injection',
		'xss'       => 'Cross-site scripting',
		'traversal' => 'Path traversal / file inclusion',
		'cmdi'      => 'Command injection / webshell probes',
		'other'     => 'Misc (null bytes, etc.)',
	);

	const JETPACK_IP_SOURCE = 'https://jetpack.com/ips-v4.txt';
	const XMLRPC_CRON_HOOK  = 'thessley_qg_xmlrpc_allow_refresh';

	public static function check_dest() {
		return THESSLEY_CHECKS_DIR . '/query-guard.php';
	}

	public static function activate() {
		self::deploy_check_file();

		if ( ! wp_next_scheduled( self::XMLRPC_CRON_HOOK ) ) {
			wp_schedule_event( time(), 'daily', self::XMLRPC_CRON_HOOK );
		}
		// No Jetpack IP fetch here: refresh_xmlrpc_allowlist() (below)
		// already no-ops while xmlrpc blocking is off (the default) — the
		// fetched list only ever matters once the admin turns that on, and
		// activating the plugin must never by itself contact a third party.
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( self::XMLRPC_CRON_HOOK );

		if ( file_exists( self::check_dest() ) ) {
			Thessley_Module_Loader::fs_delete( self::check_dest() );
		}
	}

	public static function register() {
		self::deploy_check_file();

		add_action( 'admin_post_thessley_qg_save_settings', array( __CLASS__, 'handle_save_settings' ) );
		add_action( 'admin_post_thessley_qg_refresh_xmlrpc_allow', array( __CLASS__, 'handle_refresh_xmlrpc_allow' ) );
		add_action( self::XMLRPC_CRON_HOOK, array( __CLASS__, 'refresh_xmlrpc_allowlist' ) );

		// POST scanning can't run in the early gate: it needs
		// is_user_logged_in(), which depends on pluggable.php, not loaded at
		// mu-plugin time. It hooks `init` rather than `plugins_loaded`
		// because register() is itself called during plugins_loaded — a
		// callback added there would be scheduled at a priority that has
		// already passed and would silently never run. `init` still fires
		// before request routing, admin-ajax handlers and REST dispatch.
		if ( get_option( 'thessley_query_guard_scan_post', true ) ) {
			add_action( 'init', array( __CLASS__, 'scan_request_body' ), 0 );
		}

		add_filter( 'rest_pre_dispatch', array( __CLASS__, 'block_batch_route' ), 5, 3 );

		return __CLASS__;
	}

	/**
	 * CVE-2026-63030/CVE-2026-60137 ("wp2shell"): core's REST batch endpoint
	 * short-circuits inside WP_REST_Server::dispatch() itself, matched on
	 * $request->get_route() === '/batch/v1' before normal route callbacks
	 * ever run — the check.php early-gate signature only sees the raw
	 * request line, so it catches ?rest_route=/batch/v1 but never the
	 * pretty-permalink /wp-json/batch/v1 form, since that only resolves to
	 * the same route string after WP finishes bootstrapping. Confirmed live
	 * on a client site: the pretty-permalink form got through untouched and
	 * was only blocked as a side effect of the attacker's IP already being
	 * escalated to the local blocklist from an earlier query-string-form
	 * hit — a request that used only the path form first would have gone
	 * straight through. rest_pre_dispatch fires after WP has normalized
	 * both URL forms to the same route, so this closes the gap regardless
	 * of which one an attacker uses. Gutenberg's own batch calls are always
	 * authenticated, so requiring a logged-in user costs nothing real.
	 */
	public static function block_batch_route( $result, $server, $request ) {
		if ( null !== $result || '/batch/v1' !== $request->get_route() ) {
			return $result;
		}

		$categories = get_option( 'thessley_query_guard_categories', array( 'sqli', 'xss', 'traversal', 'cmdi', 'other' ) );
		if ( ! in_array( 'other', $categories, true ) ) {
			return $result;
		}

		if ( is_user_logged_in() ) {
			return $result;
		}

		$ip = thessley_client_ip();
		if ( '' !== $ip && thessley_ip_is_exempt( $ip ) ) {
			return $result;
		}

		$mode   = get_option( 'thessley_query_guard_mode', 'log' );
		// The route match above already decided this request; the URI is only
		// diagnostic text for the event log, so it's stored sanitized (same
		// esc_url_raw() the early gate applies to the logged uri column).
		$detail = 'anonymous /batch/v1 request (path: ' . substr( esc_url_raw( wp_unslash( (string) ( $_SERVER['REQUEST_URI'] ?? '' ) ) ), 0, 200 ) . ')';

		if ( 'block' !== $mode ) {
			thessley_log_event( 'query-guard', 'other_wp2shell_batch_route_cve202663030', 'logged', $detail );
			return $result;
		}

		thessley_log_event( 'query-guard', 'other_wp2shell_batch_route_cve202663030', 'blocked', $detail );

		if ( '' !== $ip ) {
			thessley_local_blocklist_add( $ip, 'query-guard: other_wp2shell_batch_route_cve202663030' );
		}

		return new WP_Error(
			'thessley_batch_forbidden',
			__( 'Authentication required.', 'thessley-security-hardening' ),
			array( 'status' => 401 )
		);
	}

	/**
	 * Patterns for request bodies. Deliberately much narrower than the
	 * query-string set: no XSS/SQLi signatures here, because legitimate
	 * content genuinely contains those strings. These target code execution,
	 * file inclusion and upload abuse — things that have no business in a
	 * form submission from a visitor.
	 */
	private static function body_patterns() {
		return array(
			array( 'id' => 'body_php_open_tag', 'regex' => '/<\?php\b/i' ),
			array( 'id' => 'body_php_wrapper', 'regex' => '#\b(php|data|expect|phar)://#i' ),
			array( 'id' => 'body_eval_exec', 'regex' => '/\b(eval|assert|create_function|shell_exec|passthru|proc_open|popen|system)\s*\(/i' ),
			array( 'id' => 'body_base64_payload', 'regex' => '/base64_decode\s*\(/i' ),
			array( 'id' => 'body_traversal', 'regex' => '#\.\./\.\./#' ),
			array( 'id' => 'body_null_byte', 'regex' => '/%00|\x00/' ),
		);
	}

	/** Executable extensions that should never arrive via an upload field. */
	private static function dangerous_upload_regex() {
		return '/\.(php[0-9]?|phtml|phps|phar|pht|shtml|cgi|pl|py|jsp|asp|aspx|htaccess)(\.|$)/i';
	}

	public static function scan_request_body() {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- read-only method comparison, never stored or output.
		if ( 'POST' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) && 'PUT' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) ) {
			return;
		}

		$ip = thessley_client_ip();
		if ( '' !== $ip && thessley_ip_is_exempt( $ip ) ) {
			return;
		}

		// Authenticated users legitimately post PHP-ish content: the block
		// editor, code snippet plugins, support forms. Unauthenticated POST is
		// where the bulk of exploitable plugin bugs are actually reached, so
		// that's the default scope. Checked with a real cookie validation,
		// not just cookie presence, so a forged cookie can't opt out of it.
		if ( 'all' !== get_option( 'thessley_query_guard_post_scope', 'anon' ) ) {
			if ( is_user_logged_in() ) {
				return;
			}
		}

		$hit = self::find_body_hit();
		if ( ! $hit ) {
			return;
		}

		$mode = get_option( 'thessley_query_guard_mode', 'log' );

		if ( 'block' !== $mode ) {
			thessley_log_event( 'query-guard', $hit['id'], 'logged', $hit['detail'] );
			return;
		}

		thessley_log_event( 'query-guard', $hit['id'], 'blocked', $hit['detail'] );

		if ( '' !== $ip ) {
			thessley_local_blocklist_add( $ip, "query-guard: {$hit['id']}" );
		}

		status_header( 403 );
		nocache_headers();
		wp_die( 'Access denied.', '403 Forbidden', array( 'response' => 403 ) );
	}

	/** @return array{id:string,detail:string}|null */
	private static function find_body_hit() {
		// Uploaded filenames first — an executable extension arriving from an
		// anonymous visitor is about as unambiguous as a signal gets. The raw
		// filename must reach preg_match() and the stored log detail
		// unsanitized: sanitizing it would strip or alter exactly the
		// characters (the dangerous extension) this check exists to detect,
		// and the detail is a truncated (100 char) plain-text log entry,
		// never echoed as HTML.
		// phpcs:disable WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- this is a WAF-style scanner that must inspect every anonymous POST/PUT request site-wide for malicious payloads; a real attacker will never send a valid nonce, so nonce-gating would defeat the check entirely.
		foreach ( (array) $_FILES as $field => $file ) {
			// A multi-dimensional field name (e.g. upload[file][]) nests
			// 'name' more than one level deep — flatten() (already used for
			// $_POST below) handles arbitrary nesting instead of the single
			// is_array() check this used to do, which only unwrapped one
			// level and passed a leftover array into preg_match() otherwise.
			foreach ( self::flatten( $file['name'] ?? '' ) as $name ) {
				if ( '' !== $name && is_string( $name ) && preg_match( self::dangerous_upload_regex(), $name ) ) {
					return array(
						'id'     => 'upload_executable_ext',
						'detail' => sprintf( 'field "%s" filename "%s"', $field, substr( (string) $name, 0, 100 ) ),
					);
				}
			}
		}
		// phpcs:enable WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized

		$patterns = self::body_patterns();

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- same reason as the $_FILES loop above: a WAF-style scan of anonymous POST bodies can't require a nonce without defeating its own purpose.
		foreach ( self::flatten( $_POST ) as $key => $value ) {
			if ( ! is_string( $value ) || '' === $value ) {
				continue;
			}
			foreach ( $patterns as $p ) {
				if ( preg_match( $p['regex'], $value ) ) {
					return array(
						'id'     => $p['id'],
						'detail' => sprintf( 'field "%s": %s', $key, substr( preg_replace( '/\s+/', ' ', $value ), 0, 120 ) ),
					);
				}
			}
		}

		return null;
	}

	/** @return array<string,mixed> dot-joined key => scalar */
	private static function flatten( $data, $prefix = '', $depth = 0 ) {
		$out = array();
		if ( $depth > 6 ) {
			return $out;
		}
		foreach ( (array) $data as $k => $v ) {
			$key = '' === $prefix ? (string) $k : $prefix . '.' . $k;
			if ( is_array( $v ) ) {
				$out += self::flatten( $v, $key, $depth + 1 );
			} else {
				$out[ $key ] = $v;
			}
		}
		return $out;
	}

	/**
	 * Jetpack is the one common legitimate xmlrpc.php consumer, and
	 * Automattic publishes a live, auto-updating IP list for exactly this
	 * purpose rather than a static one that goes stale — fetch and cache
	 * it, same daily-refresh pattern as ip-blocklist's sources. Anything
	 * else (other providers) goes through the existing trusted-networks
	 * file instead of us guessing at more hardcoded IP data.
	 */
	public static function refresh_xmlrpc_allowlist() {
		// This list only ever matters once xmlrpc.php blocking is actually
		// on — pointless (and an unwanted third-party contact) to fetch it
		// while block_xmlrpc is still off, the default.
		if ( ! get_option( 'thessley_query_guard_block_xmlrpc', false ) ) {
			return;
		}

		$response = wp_remote_get( self::JETPACK_IP_SOURCE, array( 'timeout' => 15, 'user-agent' => 'wp-thessley/' . THESSLEY_VERSION ) );
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return false;
		}

		$ranges = array();
		foreach ( preg_split( '/\r\n|\r|\n/', wp_remote_retrieve_body( $response ) ) as $line ) {
			$line = trim( $line );
			if ( '' === $line || false === strpos( $line, '/' ) ) {
				continue;
			}
			$ranges[] = thessley_cidr_to_range( $line );
		}

		update_option( 'thessley_qg_xmlrpc_allow_ranges', $ranges, false );
		update_option( 'thessley_qg_xmlrpc_allow_updated_at', time(), false );

		return count( $ranges );
	}

	public static function handle_refresh_xmlrpc_allow() {
		check_admin_referer( 'thessley_qg_refresh_xmlrpc_allow' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		self::refresh_xmlrpc_allowlist();
		wp_safe_redirect( add_query_arg( 'refreshed', '1', wp_get_referer() ) );
		exit;
	}

	private static function deploy_check_file() {
		$dir = dirname( self::check_dest() );
		if ( ! file_exists( $dir ) ) {
			wp_mkdir_p( $dir );
		}

		$source = __DIR__ . '/check.php';
		if ( ! file_exists( self::check_dest() ) || md5_file( self::check_dest() ) !== md5_file( $source ) ) {
			Thessley_Module_Loader::fs_copy( $source, self::check_dest(), true );
			// Without this, a worker process that already opcache-compiled the
			// old bytecode can keep serving stale check logic across multiple
			// requests until that cache entry's own revalidation timer fires —
			// a real, confirmed-live gap (hit an actual admin session's request
			// once via the mu-loader's own version of this same miss).
			if ( function_exists( 'opcache_invalidate' ) ) {
				opcache_invalidate( self::check_dest(), true );
			}
		}
	}


	public static function handle_save_settings() {
		check_admin_referer( 'thessley_qg_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		$mode = ( isset( $_POST['mode'] ) && 'block' === $_POST['mode'] ) ? 'block' : 'log';
		update_option( 'thessley_query_guard_mode', $mode );

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- already unslashed, and array_intersect() against self::CATEGORIES below discards anything not a real category id; nothing unvalidated ever reaches update_option().
		$posted     = isset( $_POST['categories'] ) ? (array) wp_unslash( $_POST['categories'] ) : array();
		$categories = array_values( array_intersect( $posted, array_keys( self::CATEGORIES ) ) );
		update_option( 'thessley_query_guard_categories', $categories );

		$block_xmlrpc = isset( $_POST['block_xmlrpc'] );
		update_option( 'thessley_query_guard_block_xmlrpc', $block_xmlrpc );
		update_option( 'thessley_qg_allow_jetpack', isset( $_POST['allow_jetpack'] ) );

		if ( $block_xmlrpc ) {
			// This save is what just turned xmlrpc blocking on — the
			// admin's own action, and exactly when the Jetpack allowlist
			// actually starts mattering. Fetch it now rather than waiting
			// for tomorrow's cron.
			self::refresh_xmlrpc_allowlist();
		}

		update_option( 'thessley_query_guard_scan_post', isset( $_POST['scan_post'] ) );
		$scope = sanitize_text_field( wp_unslash( $_POST['post_scope'] ?? 'anon' ) );
		update_option( 'thessley_query_guard_post_scope', in_array( $scope, array( 'anon', 'all' ), true ) ? $scope : 'anon' );

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function render_settings_page() {
		$mode          = get_option( 'thessley_query_guard_mode', 'log' );
		$categories    = get_option( 'thessley_query_guard_categories', array_keys( self::CATEGORIES ) );
		$block_xmlrpc  = get_option( 'thessley_query_guard_block_xmlrpc', false );
		$allow_jetpack = get_option( 'thessley_qg_allow_jetpack', true );
		$jp_ranges     = get_option( 'thessley_qg_xmlrpc_allow_ranges', array() );
		$jp_updated_at = get_option( 'thessley_qg_xmlrpc_allow_updated_at', 0 );

		Thessley_UI::open( 'query-guard' );

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only result flags set only by this module's own admin-post redirects, which already check_admin_referer() before redirecting.
		if ( isset( $_GET['saved'] ) ) {
			Thessley_UI::notice( 'success', 'Settings saved.' );
		}
		if ( isset( $_GET['refreshed'] ) ) {
			Thessley_UI::notice( 'success', 'Jetpack IP list refreshed.' );
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		Thessley_UI::tiles(
			array(
				array(
					'icon'  => 'block' === $mode ? 'shield-alt' : 'visibility',
					'tone'  => 'block' === $mode ? 'good' : 'warn',
					'value' => 'block' === $mode ? 'Blocking' : 'Log only',
					'label' => 'enforcement mode',
				),
				array(
					'icon'  => 'filter',
					'tone'  => 'quiet',
					'value' => (string) count( (array) $categories ),
					'label' => 'signature categories on',
				),
				array(
					'icon'  => get_option( 'thessley_query_guard_scan_post', true ) ? 'yes-alt' : 'minus',
					'tone'  => get_option( 'thessley_query_guard_scan_post', true ) ? 'good' : 'warn',
					'value' => get_option( 'thessley_query_guard_scan_post', true ) ? 'GET + POST' : 'GET only',
					'label' => 'request scanning',
				),
			)
		);
		?>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'thessley_qg_save_settings' ); ?>
			<input type="hidden" name="action" value="thessley_qg_save_settings">

			<?php Thessley_UI::section( 'Query string signatures', 'filter' ); ?>
				<?php
				Thessley_UI::row(
					'Categories',
					function () use ( $categories ) {
						foreach ( self::CATEGORIES as $id => $label ) {
							?>
							<label>
								<input type="checkbox" name="categories[]" value="<?php echo esc_attr( $id ); ?>" <?php checked( in_array( $id, $categories, true ) ); ?>>
								<?php echo esc_html( $label ); ?>
							</label>
							<?php
						}
					},
					'Applies to the GET query string. POST bodies are scanned separately with a much narrower set — real content legitimately contains XSS and SQL-looking strings.'
				);
				?>
			<?php Thessley_UI::section_end(); ?>

			<?php Thessley_UI::section( 'Request bodies', 'upload' ); ?>
				<?php
				Thessley_UI::row(
					'POST scanning',
					function () {
						?>
						<label><input type="checkbox" name="scan_post" <?php checked( get_option( 'thessley_query_guard_scan_post', true ) ); ?>> Scan POST data and file uploads</label>
						<?php
					},
					'Code execution, file wrappers, traversal and executable file uploads only — no XSS/SQLi patterns.'
				);

				Thessley_UI::row(
					'Who to scan',
					function () {
						$scope = get_option( 'thessley_query_guard_post_scope', 'anon' );
						?>
						<label><input type="radio" name="post_scope" value="anon" <?php checked( $scope, 'anon' ); ?>> Logged-out visitors only <?php Thessley_UI::badge( 'recommended', 'good' ); ?></label>
						<label><input type="radio" name="post_scope" value="all" <?php checked( $scope, 'all' ); ?>> Everyone, including logged-in users</label>
						<?php
					},
					'43% of plugin vulnerabilities are exploitable without logging in, which is what the first option covers. Scanning logged-in POSTs as well will flag the block editor and any code-snippet plugin.'
				);
				?>
			<?php Thessley_UI::section_end(); ?>

			<?php Thessley_UI::section( 'xmlrpc.php', 'rest-api' ); ?>
				<?php
				Thessley_UI::row(
					'Block access',
					function () use ( $block_xmlrpc ) {
						?>
						<label><input type="checkbox" name="block_xmlrpc" <?php checked( $block_xmlrpc ); ?>> Block access to xmlrpc.php entirely</label>
						<?php
					},
					'Off by default — xmlrpc.php is needed by Jetpack, the WordPress mobile app, desktop blog clients and pingbacks. Enable only if you know this site uses none of them. Pingback-based DDoS amplification and password guessing via multicall are the common abuses.'
				);

				Thessley_UI::row(
					'Jetpack exemption',
					function () use ( $allow_jetpack, $jp_ranges, $jp_updated_at ) {
						?>
						<label><input type="checkbox" name="allow_jetpack" <?php checked( $allow_jetpack ); ?>> Still allow Jetpack (Automattic) IPs through</label>
						<?php
						if ( $jp_updated_at ) {
							Thessley_UI::badge( count( $jp_ranges ) . ' ranges · ' . date_i18n( 'M j', $jp_updated_at ), 'good', 'yes-alt' );
						} else {
							Thessley_UI::badge( 'not fetched yet', 'warn' );
						}
					},
					'Fetched from Automattic&#39;s own published list, refreshed daily. For other providers, add their IPs to the trusted networks file on the <a href="' . esc_url( Thessley_Menu_Router::url( 'ip-blocklist' ) ) . '">IP Blocklist</a> page — that list is exempt here too.'
				);
				?>
			<?php Thessley_UI::section_end(); ?>

			<?php Thessley_UI::section( 'Mode', 'admin-generic' ); ?>
				<?php
				Thessley_UI::row(
					'Enforcement',
					function () use ( $mode ) {
						?>
						<label><input type="radio" name="mode" value="log" <?php checked( $mode, 'log' ); ?>> Log only</label>
						<label><input type="radio" name="mode" value="block" <?php checked( $mode, 'block' ); ?>> Block (403)</label>
						<?php
					},
					'Start in log-only mode, confirm the Event Log shows no false positives, then switch to block.'
				);
				?>
			<?php Thessley_UI::section_end(); ?>

			<?php submit_button( 'Save settings' ); ?>
		</form>

		<div class="thessley-actions" style="margin-top:14px">
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'thessley_qg_refresh_xmlrpc_allow' ); ?>
				<input type="hidden" name="action" value="thessley_qg_refresh_xmlrpc_allow">
				<?php submit_button( 'Refresh Jetpack IP list now', 'secondary', 'submit', false ); ?>
			</form>
		</div>
		<?php
		Thessley_UI::close();
	}
}
