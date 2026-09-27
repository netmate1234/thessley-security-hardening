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
		self::remove_root_guard();
	}

	public static function register() {
		add_action( 'admin_post_thessley_hd_save_settings', array( __CLASS__, 'handle_save_settings' ) );
		add_action( 'admin_post_thessley_hd_scan_now', array( __CLASS__, 'handle_scan_now' ) );
		add_action( self::CRON_HOOK, array( __CLASS__, 'scan_hidden_plugins' ) );
		add_action( self::CRON_HOOK, array( __CLASS__, 'scan_exposed_files' ) );

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

		$fs       = Thessley_Module_Loader::filesystem();
		$existing = ( $fs && $fs->exists( $path ) ) ? (string) $fs->get_contents( $path ) : '';

		if ( false !== strpos( $existing, self::UPLOADS_GUARD_MARKER ) ) {
			return true; // already present
		}

		return (bool) Thessley_Module_Loader::fs_put_contents( $path, $rules . $existing );
	}

	public static function remove_uploads_guard() {
		$path = self::uploads_htaccess_path();
		$fs   = Thessley_Module_Loader::filesystem();
		if ( ! $fs || ! $fs->exists( $path ) ) {
			return;
		}

		$content = (string) $fs->get_contents( $path );
		$cleaned = preg_replace(
			'/' . preg_quote( self::UPLOADS_GUARD_MARKER, '/' ) . '.*?# END Thessley Security Hardening uploads guard\s*/s',
			'',
			$content
		);

		if ( '' === trim( (string) $cleaned ) ) {
			Thessley_Module_Loader::fs_delete( $path );
		} elseif ( $cleaned !== $content ) {
			Thessley_Module_Loader::fs_put_contents( $path, $cleaned );
		}
	}

	public static function uploads_guard_active() {
		$path = self::uploads_htaccess_path();
		return file_exists( $path ) && false !== strpos( (string) file_get_contents( $path ), self::UPLOADS_GUARD_MARKER );
	}


	const ROOT_GUARD_MARKER = 'Thessley Security Hardening web-root guard';

	/**
	 * The plugin's checks only run when PHP runs. A file that physically
	 * exists is handed to the client by the web server directly, so a
	 * leftover wp-config.php.bak, a database dump or an error_log is
	 * downloadable no matter what any blocking module says (a real
	 * wp-config.php.bak was fetched twice this way while every signature
	 * for it was active). This finds such files; it cannot delete them for
	 * you — that is a decision about your data — but it names them and, on
	 * Apache, can deny them at the server with a marked block in .htaccess.
	 *
	 * @return array<int, array{path:string,size:int,kind:string,level:string}>
	 */
	public static function find_exposed_files() {
		$roots = array(
			''                                  => untrailingslashit( ABSPATH ),
			'wp-admin'                          => untrailingslashit( ABSPATH ) . '/wp-admin',
			'wp-content'                        => untrailingslashit( WP_CONTENT_DIR ),
			'wp-content/themes'                 => untrailingslashit( get_theme_root() ),
			'wp-content/plugins'                => untrailingslashit( WP_PLUGIN_DIR ),
			'wp-content/uploads'                => untrailingslashit( (string) ( wp_get_upload_dir()['basedir'] ?? '' ) ),
		);

		// [ regex on the file name, kind, level ]
		$rules = array(
			array( '/^wp-config(?!-sample)[^\/]*\.(?:bak|old|orig|save|swp|txt|zip|php~|copy|backup|1|2)$|^wp-config\.php[.~].+$|^wp-config\.[^.]+\.php$/i', 'wp-config backup', 'critical' ),
			array( '/^\.env(?:\..+)?$|^\.htpasswd$|^\.git-credentials$/i', 'credentials file', 'critical' ),
			array( '/\.(?:sql|sqlite3?|db)(?:\.gz|\.zip|\.bz2)?$|^(?:dump|backup|database)[\w.-]*\.(?:gz|zip)$/i', 'database dump', 'critical' ),
			array( '/\.(?:zip|tar|tgz|gz|rar|7z)$/i', 'archive', 'high' ),
			array( '/^(?:phpinfo|info|test|adminer[\w.-]*|shell|cmd|c99|r57)\.php$/i', 'debug / webshell-style script', 'high' ),
			array( '/\.(?:bak|old|orig|save|swp)$|~$/i', 'backup copy', 'high' ),
			array( '/^(?:error_log|debug\.log|php_errorlog)$|\.log$/i', 'log file', 'medium' ),
			array( '/^(?:readme\.html|license\.txt|wp-config-sample\.php)$/i', 'version / install disclosure', 'low' ),
		);

		$found = array();
		foreach ( $roots as $rel_root => $dir ) {
			if ( '' === $dir || ! is_dir( $dir ) || ! is_readable( $dir ) ) {
				continue;
			}
			foreach ( (array) scandir( $dir ) as $name ) {
				if ( '.' === $name || '..' === $name ) {
					continue;
				}
				$full = $dir . '/' . $name;
				$rel  = ltrim( $rel_root . '/' . $name, '/' );

				if ( is_dir( $full ) ) {
					if ( in_array( strtolower( $name ), array( '.git', '.svn', '.hg' ), true ) && '' === $rel_root ) {
						$found[] = array( 'path' => $rel . '/', 'size' => 0, 'kind' => 'source-control folder', 'level' => 'critical' );
					}
					continue;
				}

				foreach ( $rules as $rule ) {
					if ( preg_match( $rule[0], $name ) ) {
						// Archives under uploads are ordinary media downloads and
						// logs under themes/plugins are rare; only flag them where
						// they do not belong.
						if ( 'wp-content/uploads' === $rel_root && in_array( $rule[1], array( 'archive', 'log file', 'backup copy' ), true ) ) {
							continue 2;
						}
						$found[] = array( 'path' => $rel, 'size' => (int) filesize( $full ), 'kind' => $rule[1], 'level' => $rule[2] );
						continue 2;
					}
				}
			}
		}

		return $found;
	}

	/**
	 * Cron/manual entry point: stores the findings and logs one event only
	 * when the set of findings changes, so a file that stays put does not
	 * re-alert twice a day.
	 */
	public static function scan_exposed_files() {
		$files = self::find_exposed_files();
		$sig   = md5( wp_json_encode( wp_list_pluck( $files, 'path' ) ) );
		$prev  = get_option( 'thessley_hardening_exposed_result', array() );

		update_option( 'thessley_hardening_exposed_result', array( 'at' => time(), 'files' => $files, 'sig' => $sig ), false );

		$serious = array_filter(
			$files,
			function ( $f ) {
				return in_array( $f['level'], array( 'critical', 'high' ), true );
			}
		);

		if ( $serious && ( $prev['sig'] ?? '' ) !== $sig ) {
			$critical = array_filter(
				$serious,
				function ( $f ) {
					return 'critical' === $f['level'];
				}
			);
			thessley_log_event(
				'hardening',
				'exposed_files',
				'noted',
				sprintf( '%d sensitive file(s) in the web root the web server will hand out: %s', count( $serious ), implode( ', ', array_slice( wp_list_pluck( $serious, 'path' ), 0, 5 ) ) ),
				$critical ? 18 : 12
			);
		}

		return $files;
	}

	private static function root_htaccess_path() {
		if ( ! function_exists( 'get_home_path' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		return get_home_path() . '.htaccess';
	}

	/**
	 * Server-level deny rules for the files above, written with WordPress'
	 * own insert_with_markers() between marked lines so they can be removed
	 * cleanly. Apache only (mod_rewrite, which permalinks already need).
	 * Nothing here can be reached by PHP, which is exactly why it has to
	 * live in the server config.
	 *
	 * @return string[]
	 */
	/**
	 * Every condition tests %{REQUEST_URI} — the full original request path
	 * — rather than encoding the path into the RewriteRule pattern itself.
	 * Confirmed live on a real site: a bundled plugin's own .htaccess under
	 * wp-content/ (WP Fastest Cache, Converter for Media, etc.) turns
	 * RewriteEngine on again with RewriteOptions Inherit, which re-runs the
	 * inherited rules against the path *relative to that subdirectory* —
	 * stripping the "wp-content/" prefix a RewriteRule pattern was
	 * anchored to, so it silently never matched a theme's leftover .zip
	 * there. %{REQUEST_URI} is always the full path regardless of which
	 * per-directory context is currently evaluating it, so it isn't
	 * affected by that stripping.
	 */
	public static function root_guard_rules() {
		return array(
			'<IfModule mod_rewrite.c>',
			'RewriteEngine On',
			'# Version / install disclosure — only the well-known files at the site root.',
			'RewriteCond %{REQUEST_URI} ^/(?:readme\.html|license\.txt|wp-config-sample\.php)$ [NC,OR]',
			'RewriteCond %{REQUEST_URI} ^/wp-includes/ID3/license\.txt$ [NC]',
			'RewriteRule ^ - [F,L]',
			'# wp-config backups, at the site root only (where wp-config.php itself lives).',
			'RewriteCond %{REQUEST_URI} ^/wp-config(?!-sample)[^/]*$ [NC]',
			'RewriteRule ^ - [F,L]',
			'# Database dumps, backup copies and tilde-backups, anywhere.',
			'RewriteCond %{REQUEST_URI} \.(?:sql|sqlite3?|bak|old|orig|save|swp)(?:\.gz|\.zip)?$ [NC,OR]',
			'RewriteCond %{REQUEST_URI} ~$ [NC]',
			'RewriteRule ^ - [F,L]',
			'# Archives anywhere except inside uploads (a real uploaded file can legitimately be a .zip there).',
			'RewriteCond %{REQUEST_URI} !/wp-content/uploads/',
			'RewriteCond %{REQUEST_URI} \.(?:zip|tar|tgz|gz|rar|7z)$ [NC]',
			'RewriteRule ^ - [F,L]',
			'# Log files, anywhere.',
			'RewriteCond %{REQUEST_URI} (?:^|/)(?:error_log|php_errorlog|debug\.log|[^/]*\.log)$ [NC]',
			'RewriteRule ^ - [F,L]',
			'</IfModule>',
		);
	}

	public static function write_root_guard() {
		if ( ! function_exists( 'insert_with_markers' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
		}
		$file = self::root_htaccess_path();
		if ( ! wp_is_writable( dirname( $file ) ) && ! ( file_exists( $file ) && wp_is_writable( $file ) ) ) {
			return false;
		}
		return (bool) insert_with_markers( $file, self::ROOT_GUARD_MARKER, self::root_guard_rules() );
	}

	public static function remove_root_guard() {
		$file = self::root_htaccess_path();
		if ( ! file_exists( $file ) ) {
			return;
		}
		$content = (string) file_get_contents( $file );
		$cleaned = preg_replace(
			'/\n?# BEGIN ' . preg_quote( self::ROOT_GUARD_MARKER, '/' ) . '.*?# END ' . preg_quote( self::ROOT_GUARD_MARKER, '/' ) . '\n?/s',
			'',
			$content
		);
		if ( $cleaned === $content ) {
			return;
		}
		$cleaned = '' === trim( (string) $cleaned ) ? '' : rtrim( (string) $cleaned ) . "\n";
		// Only this plugin's block is removed; if nothing else was in the
		// file, the file this plugin created goes with it.
		if ( '' === trim( (string) $cleaned ) ) {
			Thessley_Module_Loader::fs_delete( $file );
		} else {
			Thessley_Module_Loader::fs_put_contents( $file, $cleaned );
		}
	}

	public static function root_guard_active() {
		$file = self::root_htaccess_path();
		if ( ! file_exists( $file ) ) {
			return false;
		}
		$content = (string) file_get_contents( $file );
		return false !== strpos( $content, '# BEGIN ' . self::ROOT_GUARD_MARKER ) && false !== strpos( $content, 'RewriteRule' );
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
		self::scan_exposed_files();
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

		$want_root = isset( $_POST['root_guard'] );
		update_option( 'thessley_hardening_root_guard', $want_root );
		if ( $want_root ) {
			if ( ! self::write_root_guard() ) {
				$notice = 'rootfail';
			}
		} else {
			self::remove_root_guard();
		}

		wp_safe_redirect( add_query_arg( 'saved', $notice, wp_get_referer() ) );
		exit;
	}


	public static function render_page() {
		$hidden_result = get_option( 'thessley_hardening_hidden_result', array() );
		$guard_active  = self::uploads_guard_active();
		$file_edit_off = defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT;
		$hidden        = (array) ( $hidden_result['hidden'] ?? array() );
		$exposed_res   = get_option( 'thessley_hardening_exposed_result', array() );
		$exposed       = (array) ( $exposed_res['files'] ?? array() );
		$root_active   = self::root_guard_active();
		$serious       = array_filter(
			$exposed,
			function ( $f ) {
				return in_array( $f['level'], array( 'critical', 'high' ), true );
			}
		);

		Thessley_UI::open( 'hardening' );

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only result flags set only by this module's own admin-post redirects, which already check_admin_referer() before redirecting.
		if ( isset( $_GET['saved'] ) && '1' === $_GET['saved'] ) {
			Thessley_UI::notice( 'success', 'Settings saved.' );
		} elseif ( isset( $_GET['saved'] ) && 'guardfail' === $_GET['saved'] ) {
			Thessley_UI::notice( 'error', 'Could not write ' . self::uploads_htaccess_path() . ' — check filesystem permissions.' );
		} elseif ( isset( $_GET['saved'] ) && 'rootfail' === $_GET['saved'] ) {
			Thessley_UI::notice( 'error', 'Could not write ' . self::root_htaccess_path() . ' — check filesystem permissions.' );
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
				array(
					'icon'  => $serious ? 'dismiss' : 'yes-alt',
					'tone'  => $serious ? 'bad' : 'good',
					'value' => (string) count( $serious ),
					'label' => 'sensitive files exposed',
				),
			)
		);

		Thessley_UI::section( 'Exposed files', 'media-archive' );
		echo '<p class="thessley-help" style="margin-top:0">Blocking modules only run when PHP runs. A file that physically exists in the web root is served by the web server itself, so a leftover backup, database dump or error log can be downloaded no matter what the blocking modules say. Delete or move these; the web-root protection below denies them at the server as a safety net.</p>';
		if ( empty( $exposed_res ) ) {
			echo '<div class="thessley-empty"><span class="dashicons dashicons-marker" style="color:#646970"></span><p>Not scanned yet.</p></div>';
		} elseif ( empty( $exposed ) ) {
			echo '<div class="thessley-empty"><span class="dashicons dashicons-yes-alt"></span><p>No sensitive files found in the web root.</p></div>';
		} else {
			echo '<table class="widefat striped" style="max-width:820px"><thead><tr><th>File</th><th>What it is</th><th>Size</th><th>Risk</th></tr></thead><tbody>';
			foreach ( $exposed as $f ) {
				$tone = 'critical' === $f['level'] ? 'bad' : ( 'high' === $f['level'] ? 'warn' : 'quiet' );
				echo '<tr><td><code>' . esc_html( $f['path'] ) . '</code></td><td>' . esc_html( $f['kind'] ) . '</td><td>' . esc_html( $f['size'] ? size_format( $f['size'] ) : '' ) . '</td><td>';
				Thessley_UI::badge( $f['level'], $tone );
				echo '</td></tr>';
			}
			echo '</tbody></table>';
		}
		Thessley_UI::section_end();

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

				Thessley_UI::row(
					'Web-root protection',
					function () use ( $root_active, $is_apache ) {
						?>
						<label><input type="checkbox" name="root_guard" <?php checked( get_option( 'thessley_hardening_root_guard', false ) ); ?>> Deny backups, dumps, logs, archives and version files at the web server</label>
						<?php
						Thessley_UI::badge( $root_active ? 'active' : 'not active', $root_active ? 'good' : 'warn' );
						if ( ! $is_apache ) {
							echo '<p class="thessley-help"><strong>This server does not look like Apache.</strong> nginx ignores <code>.htaccess</code>, so add an equivalent rule to the server block:<br><code>location ~* (?:^/(?:readme\.html|license\.txt|wp-config-sample\.php)$|wp-config[^/]*$|\.(?:sql|bak|old|orig|save|swp|log)$|/error_log$|~$) { deny all; }</code></p>';
						}
					},
					'Adds a marked block to the site\'s root <code>.htaccess</code> (removed again when unchecked or when this plugin is deactivated). Stops the server handing out files such as <code>wp-config.php.bak</code>, <code>*.sql</code>, <code>error_log</code>, <code>readme.html</code> and archives left in the web root, none of which the blocking modules can see.'
				);
				?>
			<?php Thessley_UI::section_end(); ?>

			<?php submit_button( 'Save settings' ); ?>
		</form>
		<?php
		Thessley_UI::close();
	}
}
