<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * File integrity monitoring.
 *
 * Two independent checks, because they answer different questions:
 *
 *  - Core files are verified against WordPress.org's published checksums.
 *    That's authoritative: it detects tampering even if the attacker got
 *    in before this plugin was ever installed.
 *  - Plugins/themes/uploads have no published checksums, so those are
 *    compared against a baseline snapshot taken on this site. That only
 *    detects change *since the baseline*, which is why the baseline is
 *    re-taken explicitly (after an update) rather than silently.
 */
class Thessley_Module_File_Integrity {

	const CRON_HOOK  = 'thessley_file_integrity_scan';
	const DB_VERSION = 1;
	const TIME_LIMIT = 25; // seconds per scan pass, to stay well inside PHP limits

	public static function table() {
		global $wpdb;
		return $wpdb->prefix . 'thessley_baseline';
	}

	public static function activate() {
		self::install_table();

		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CRON_HOOK );
		}
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	public static function register() {
		if ( (int) get_option( 'thessley_integrity_db_version', 0 ) !== self::DB_VERSION ) {
			self::install_table();
		}

		add_action( self::CRON_HOOK, array( __CLASS__, 'run_scan' ) );
		add_action( 'admin_post_thessley_fi_scan_now', array( __CLASS__, 'handle_scan_now' ) );
		add_action( 'admin_post_thessley_fi_rebaseline', array( __CLASS__, 'handle_rebaseline' ) );
		add_action( 'admin_post_thessley_fi_save_settings', array( __CLASS__, 'handle_save_settings' ) );

		return __CLASS__;
	}

	public static function install_table() {
		global $wpdb;

		$collate = $wpdb->get_charset_collate();
		$table   = self::table();

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		// path_hash is an indexed md5 of the path: real paths can exceed
		// MySQL's index key length, so index the digest instead.
		dbDelta(
			"CREATE TABLE {$table} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				path_hash char(32) NOT NULL,
				path varchar(500) NOT NULL,
				file_hash char(32) NOT NULL,
				size bigint(20) unsigned NOT NULL DEFAULT 0,
				recorded_at datetime NOT NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY path_hash (path_hash)
			) {$collate};"
		);

		update_option( 'thessley_integrity_db_version', self::DB_VERSION, false );
	}

	/**
	 * Directories to baseline. Entries are relative to ABSPATH when the
	 * content directory lives inside it, and absolute otherwise —
	 * WP_CONTENT_DIR is allowed to sit outside ABSPATH, and a naive
	 * str_replace there produced a path that never resolved, so plugins and
	 * themes were skipped while the UI still reported "no changes".
	 */
	private static function scan_roots() {
		$roots = array( 'wp-admin', 'wp-includes' );

		$abs     = trailingslashit( ABSPATH );
		$content = trailingslashit( WP_CONTENT_DIR );
		$inside  = ( 0 === strpos( $content, $abs ) );
		$base    = $inside ? substr( $content, strlen( $abs ) ) : $content;
		$base    = rtrim( $base, '/' );

		foreach ( array( 'plugins', 'themes', 'mu-plugins' ) as $sub ) {
			$roots[] = $base . '/' . $sub;
		}

		return $roots;
	}

	private static function watched_extensions() {
		return array( 'php', 'phtml', 'phar', 'js', 'htaccess' );
	}

	/**
	 * @return array{files:array<string,array{hash:string,size:int}>, partial:bool, errors:string[]}
	 *
	 * `partial` is the important part of the contract: a crawl cut short by
	 * the time budget must never be compared against a complete baseline, or
	 * every file it didn't reach looks deleted. Callers have to check it.
	 */
	public static function collect_files() {
		$files    = array();
		$errors   = array();
		$partial  = false;
		$abs  = trailingslashit( ABSPATH );
		$exts = self::watched_extensions();

		// Filterable so a large site that legitimately can't finish in the
		// default budget can raise it rather than living with permanently
		// partial scans (which suppress deleted-file detection).
		$budget   = max( 1, (int) apply_filters( 'thessley_integrity_time_limit', self::TIME_LIMIT ) );
		$deadline = time() + $budget;

		// Root-level PHP (wp-config.php, index.php, xmlrpc.php, ...)
		foreach ( (array) glob( $abs . '*.php' ) as $file ) {
			$files[ self::relative_path( $file ) ] = self::file_info( $file );
		}

		foreach ( self::scan_roots() as $root ) {
			$dir = self::root_to_dir( $root );
			if ( ! is_dir( $dir ) ) {
				continue;
			}

			try {
				$iter = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ),
					// SELF_FIRST so directories are visited too: CATCH_GET_CHILD
					// stops an unreadable one from throwing, but it also
					// swallows it silently, and a directory we couldn't read is
					// exactly the case that must not be mistaken for "no files
					// here". Seeing the directory lets us flag it.
					RecursiveIteratorIterator::SELF_FIRST,
					RecursiveIteratorIterator::CATCH_GET_CHILD
				);

				foreach ( $iter as $file ) {
					if ( time() > $deadline ) {
						$partial  = true;
						$errors[] = sprintf( 'time limit (%ds) reached while scanning %s — raise it with the thessley_integrity_time_limit filter', $budget, $root );
						break 2;
					}

					if ( $file->isDir() ) {
						if ( ! $file->isReadable() ) {
							$partial  = true;
							$errors[] = sprintf( 'directory not readable, contents unchecked: %s', self::relative_path( $file->getPathname() ) );
						}
						continue;
					}

					if ( ! $file->isFile() ) {
						continue;
					}
					$ext = strtolower( $file->getExtension() );
					if ( ! in_array( $ext, $exts, true ) && '.htaccess' !== $file->getFilename() ) {
						continue;
					}
					$path = self::relative_path( $file->getPathname() );
					if ( false !== strpos( $path, '/wp-thessley-checks/data/' ) ) {
						// Compiled data this plugin regenerates on its own schedule
						// (IP-reputation ranges daily, local-blocklist ranges on every
						// new escalation, geo country names on refresh) — a diff here
						// is expected behavior, not drift worth an alert.
						continue;
					}
					$files[ $path ] = self::file_info( $file->getPathname() );
				}
			} catch ( Exception $e ) {
				// Unreadable root, or anything else the iterator couldn't
				// recover from: report it rather than returning a short list
				// that would read as "files were deleted".
				$partial  = true;
				$errors[] = sprintf( 'could not fully read %s: %s', $root, $e->getMessage() );
			}
		}

		return array( 'files' => $files, 'partial' => $partial, 'errors' => $errors );
	}

	/** Path as stored in the baseline: relative to ABSPATH when inside it. */
	private static function relative_path( $absolute ) {
		$abs = trailingslashit( ABSPATH );
		return 0 === strpos( $absolute, $abs ) ? substr( $absolute, strlen( $abs ) ) : $absolute;
	}

	/**
	 * Roots may be relative to ABSPATH or absolute (wp-content moved out).
	 * path_is_absolute() (WP core) recognizes Windows drive-letter and UNC
	 * paths too — a leading-"/" check alone misses "C:\content" and treats
	 * it as ABSPATH-relative.
	 */
	private static function root_to_dir( $root ) {
		return path_is_absolute( $root ) ? $root : trailingslashit( ABSPATH ) . $root;
	}

	private static function file_info( $path ) {
		return array(
			'hash' => (string) @md5_file( $path ),
			'size' => (int) @filesize( $path ),
		);
	}

	public static function rebaseline() {
		global $wpdb;

		$scan  = self::collect_files();
		$files = $scan['files'];
		$table = self::table();
		$now   = current_time( 'mysql' );

		// Refuse to overwrite a good baseline with a truncated crawl: the
		// missing files would show up as "added" on the next scan, which is
		// indistinguishable from an attacker dropping files.
		if ( $scan['partial'] ) {
			thessley_log_event(
				'file-integrity',
				'baseline_aborted',
				'noted',
				'incomplete crawl, baseline left unchanged: ' . implode( '; ', $scan['errors'] )
			);
			return new WP_Error( 'thessley_partial_scan', implode( '; ', $scan['errors'] ) );
		}

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table name only, built from $wpdb->prefix, no user input; identifiers can't be bound via $wpdb->prepare() placeholders anyway.
		$wpdb->query( "TRUNCATE TABLE {$table}" );

		foreach ( array_chunk( array_keys( $files ), 200 ) as $chunk ) {
			$values = array();
			foreach ( $chunk as $path ) {
				$values[] = $wpdb->prepare(
					'(%s,%s,%s,%d,%s)',
					md5( $path ),
					substr( $path, 0, 500 ),
					$files[ $path ]['hash'],
					$files[ $path ]['size'],
					$now
				);
			}
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $values is an array of already-prepared '(%s,%s,%s,%d,%s)' fragments (see $wpdb->prepare() calls just above), each independently safe; only the table name (no user input) is otherwise interpolated.
			$wpdb->query( "INSERT INTO {$table} (path_hash,path,file_hash,size,recorded_at) VALUES " . implode( ',', $values ) );
		}

		update_option( 'thessley_integrity_baseline_at', time(), false );
		update_option( 'thessley_integrity_baseline_count', count( $files ), false );

		thessley_log_event( 'file-integrity', 'baseline_taken', 'noted', sprintf( '%d files hashed', count( $files ) ) );

		return count( $files );
	}

	/**
	 * Verify core files against WordPress.org's published checksums.
	 * @return array{checked:int,modified:array,missing:array,error:string}
	 */
	public static function verify_core() {
		global $wp_version;

		$locale = get_locale();
		$url    = add_query_arg(
			array( 'version' => $wp_version, 'locale' => $locale ),
			'https://api.wordpress.org/core/checksums/1.0/'
		);

		$response = wp_remote_get( $url, array( 'timeout' => 20 ) );
		if ( is_wp_error( $response ) ) {
			return array( 'checked' => 0, 'modified' => array(), 'missing' => array(), 'error' => $response->get_error_message() );
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( empty( $body['checksums'] ) || ! is_array( $body['checksums'] ) ) {
			return array( 'checked' => 0, 'modified' => array(), 'missing' => array(), 'error' => 'No checksums returned for this version/locale.' );
		}

		$modified = array();
		$missing  = array();
		$abs      = trailingslashit( ABSPATH );

		foreach ( $body['checksums'] as $file => $expected ) {
			// wp-content is deliberately excluded: it's the user's own files,
			// and the checksum list covers only shipped defaults there.
			if ( 0 === strpos( $file, 'wp-content/' ) ) {
				continue;
			}
			$path = $abs . $file;
			if ( ! file_exists( $path ) ) {
				$missing[] = $file;
				continue;
			}
			if ( @md5_file( $path ) !== $expected ) {
				$modified[] = $file;
			}
		}

		return array(
			'checked'  => count( $body['checksums'] ),
			'modified' => $modified,
			'missing'  => $missing,
			'error'    => '',
		);
	}

	/** Compare current files against the stored baseline. */
	public static function diff_baseline() {
		global $wpdb;

		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table name only, built from $wpdb->prefix, no user input.
		$rows  = $wpdb->get_results( "SELECT path, file_hash, size FROM {$table}", ARRAY_A );
		if ( empty( $rows ) ) {
			return array( 'added' => array(), 'modified' => array(), 'deleted' => array(), 'no_baseline' => true );
		}

		$baseline = array();
		foreach ( $rows as $row ) {
			$baseline[ $row['path'] ] = $row['file_hash'];
		}

		$scan     = self::collect_files();
		$current  = $scan['files'];
		$added    = array();
		$modified = array();

		foreach ( $current as $path => $info ) {
			if ( ! isset( $baseline[ $path ] ) ) {
				$added[] = $path;
			} elseif ( $baseline[ $path ] !== $info['hash'] ) {
				$modified[] = $path;
			}
		}

		// Only meaningful if the crawl actually finished. On a partial pass
		// everything not reached would otherwise be reported as deleted.
		$deleted = $scan['partial']
			? array()
			: array_values( array_diff( array_keys( $baseline ), array_keys( $current ) ) );

		return array(
			'added'       => $added,
			'modified'    => $modified,
			'deleted'     => $deleted,
			'no_baseline' => false,
			'partial'     => $scan['partial'],
			'errors'      => $scan['errors'],
		);
	}

	public static function run_scan() {
		$result = array( 'at' => time() );

		if ( get_option( 'thessley_integrity_check_core', true ) ) {
			$core             = self::verify_core();
			$result['core']   = $core;
			$core_problems    = count( $core['modified'] ) + count( $core['missing'] );

			if ( $core_problems > 0 ) {
				thessley_log_event(
					'file-integrity',
					'core_mismatch',
					'noted',
					sprintf( '%d modified, %d missing vs WordPress.org checksums: %s', count( $core['modified'] ), count( $core['missing'] ), implode( ', ', array_slice( array_merge( $core['modified'], $core['missing'] ), 0, 5 ) ) )
				);
			}
		}

		if ( get_option( 'thessley_integrity_check_baseline', true ) ) {
			$diff             = self::diff_baseline();
			$result['diff']   = $diff;

			if ( ! empty( $diff['partial'] ) ) {
				thessley_log_event(
					'file-integrity',
					'scan_incomplete',
					'noted',
					'results are partial and may under-report: ' . implode( '; ', (array) $diff['errors'] )
				);
			}

			if ( empty( $diff['no_baseline'] ) ) {
				$changes = count( $diff['added'] ) + count( $diff['modified'] ) + count( $diff['deleted'] );
				if ( $changes > 0 ) {
					thessley_log_event(
						'file-integrity',
						'baseline_drift',
						'noted',
						sprintf(
							'%d added, %d modified, %d deleted since baseline: %s',
							count( $diff['added'] ),
							count( $diff['modified'] ),
							count( $diff['deleted'] ),
							implode( ', ', array_slice( array_merge( $diff['added'], $diff['modified'] ), 0, 5 ) )
						)
					);
				}
			}
		}

		update_option( 'thessley_integrity_last_result', $result, false );

		return $result;
	}

	public static function handle_scan_now() {
		check_admin_referer( 'thessley_fi_scan_now' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}
		self::run_scan();
		wp_safe_redirect( add_query_arg( 'scanned', '1', wp_get_referer() ) );
		exit;
	}

	public static function handle_rebaseline() {
		check_admin_referer( 'thessley_fi_rebaseline' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		$result = self::rebaseline();
		if ( is_wp_error( $result ) ) {
			wp_safe_redirect( add_query_arg( 'rebaselined', 'partial', wp_get_referer() ) );
			exit;
		}

		self::run_scan();
		wp_safe_redirect( add_query_arg( 'rebaselined', '1', wp_get_referer() ) );
		exit;
	}

	public static function handle_save_settings() {
		check_admin_referer( 'thessley_fi_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}
		update_option( 'thessley_integrity_check_core', isset( $_POST['check_core'] ) );
		update_option( 'thessley_integrity_check_baseline', isset( $_POST['check_baseline'] ) );
		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}


	private static function render_file_list( $label, $files, $tone = 'warn' ) {
		if ( empty( $files ) ) {
			return;
		}
		echo '<div class="thessley-files"><p class="thessley-files__title">';
		Thessley_UI::badge( $label . ' (' . count( $files ) . ')', $tone );
		echo '</p><ul>';
		foreach ( array_slice( $files, 0, 50 ) as $f ) {
			echo '<li><code>' . esc_html( $f ) . '</code></li>';
		}
		if ( count( $files ) > 50 ) {
			echo '<li class="thessley-muted">… and ' . esc_html( count( $files ) - 50 ) . ' more</li>';
		}
		echo '</ul></div>';
	}

	public static function render_page() {
		$last        = get_option( 'thessley_integrity_last_result', array() );
		$baseline_at = (int) get_option( 'thessley_integrity_baseline_at', 0 );
		$baseline_ct = (int) get_option( 'thessley_integrity_baseline_count', 0 );

		Thessley_UI::open( 'file-integrity' );

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only result flags set only by this module's own admin-post redirects, which already check_admin_referer() before redirecting.
		if ( isset( $_GET['saved'] ) ) {
			Thessley_UI::notice( 'success', 'Settings saved.' );
		}
		if ( isset( $_GET['scanned'] ) ) {
			Thessley_UI::notice( 'success', 'Scan complete.' );
		}
		if ( isset( $_GET['rebaselined'] ) && 'partial' === $_GET['rebaselined'] ) {
			Thessley_UI::notice( 'error', 'The scan could not read every file, so the baseline was left unchanged — replacing it with a partial crawl would make the unread files look like new files on the next scan.' );
		} elseif ( isset( $_GET['rebaselined'] ) ) {
			Thessley_UI::notice( 'success', 'Baseline re-taken.' );
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		if ( ! empty( $last['diff']['partial'] ) ) {
			$msg = '<p><strong>Last scan was incomplete</strong> — results below may under-report:</p><ul>';
			foreach ( (array) $last['diff']['errors'] as $err ) {
				$msg .= '<li>' . esc_html( $err ) . '</li>';
			}
			$msg .= '</ul><p>Deleted-file detection is skipped while a scan is partial.</p>';
			Thessley_UI::notice( 'warning', $msg, true );
		}

		$core_issues = count( (array) ( $last['core']['modified'] ?? array() ) ) + count( (array) ( $last['core']['missing'] ?? array() ) );
		$drift       = count( (array) ( $last['diff']['added'] ?? array() ) )
			+ count( (array) ( $last['diff']['modified'] ?? array() ) )
			+ count( (array) ( $last['diff']['deleted'] ?? array() ) );

		Thessley_UI::tiles(
			array(
				array(
					'icon'  => $core_issues ? 'dismiss' : 'yes-alt',
					'tone'  => $core_issues ? 'bad' : 'good',
					'value' => (string) $core_issues,
					'label' => 'core file issues',
				),
				array(
					'icon'  => $drift ? 'warning' : 'yes-alt',
					'tone'  => $drift ? 'bad' : 'good',
					'value' => (string) $drift,
					'label' => 'changes since baseline',
				),
				array(
					'icon'  => 'media-code',
					'tone'  => $baseline_at ? 'quiet' : 'warn',
					'value' => $baseline_at ? number_format_i18n( $baseline_ct ) : '—',
					'label' => $baseline_at ? 'files baselined ' . date_i18n( 'M j', $baseline_at ) : 'no baseline yet',
				),
			)
		);

		Thessley_UI::section( 'Core files', 'wordpress-alt' );
		echo '<p class="thessley-help" style="margin-top:0">Verified against WordPress.org&#39;s published checksums for your exact version and locale — authoritative, and valid even if this plugin was installed after a compromise.</p>';
		if ( empty( $last['core'] ) ) {
			echo '<div class="thessley-empty"><span class="dashicons dashicons-marker" style="color:#646970"></span><p>Not checked yet.</p></div>';
		} elseif ( ! empty( $last['core']['error'] ) ) {
			Thessley_UI::notice( 'warning', $last['core']['error'] );
		} elseif ( empty( $last['core']['modified'] ) && empty( $last['core']['missing'] ) ) {
			echo '<div class="thessley-empty"><span class="dashicons dashicons-yes-alt"></span><p>All '
				. esc_html( number_format_i18n( $last['core']['checked'] ) ) . ' core files match.</p></div>';
		} else {
			self::render_file_list( 'Modified core files', $last['core']['modified'], 'bad' );
			self::render_file_list( 'Missing core files', $last['core']['missing'], 'bad' );
			echo '<p class="thessley-help">Dashboard → Updates → "Re-install now" restores core files without touching your content.</p>';
		}
		Thessley_UI::section_end();

		Thessley_UI::section( 'Plugins, themes &amp; mu-plugins', 'admin-plugins' );
		echo '<p class="thessley-help" style="margin-top:0">No published checksums exist for these, so they are compared against a snapshot taken on this site.</p>';
		if ( empty( $last['diff'] ) ) {
			echo '<div class="thessley-empty"><span class="dashicons dashicons-marker" style="color:#646970"></span><p>Not checked yet.</p></div>';
		} elseif ( ! empty( $last['diff']['no_baseline'] ) ) {
			Thessley_UI::notice( 'info', 'Take a baseline to start detecting changes.' );
		} else {
			$d = $last['diff'];
			if ( empty( $d['added'] ) && empty( $d['modified'] ) && empty( $d['deleted'] ) ) {
				echo '<div class="thessley-empty"><span class="dashicons dashicons-yes-alt"></span><p>No changes since the baseline.</p></div>';
			} else {
				self::render_file_list( 'Added', $d['added'], 'bad' );
				self::render_file_list( 'Modified', $d['modified'], 'bad' );
				self::render_file_list( 'Deleted', $d['deleted'], 'warn' );
				echo '<p class="thessley-help">Updating or installing a plugin/theme legitimately changes these files. Re-take the baseline once you have confirmed the changes are yours.</p>';
			}
		}
		Thessley_UI::section_end();
		?>

		<div class="thessley-actions" style="margin-bottom:18px">
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'thessley_fi_scan_now' ); ?>
				<input type="hidden" name="action" value="thessley_fi_scan_now">
				<?php submit_button( 'Scan now', 'primary', 'submit', false ); ?>
			</form>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"
				onsubmit="return confirm('Re-take the baseline? Current files become the new known-good reference — only do this if you trust the current state.');">
				<?php wp_nonce_field( 'thessley_fi_rebaseline' ); ?>
				<input type="hidden" name="action" value="thessley_fi_rebaseline">
				<?php submit_button( 'Take / re-take baseline', 'secondary', 'submit', false ); ?>
			</form>
		</div>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'thessley_fi_save_settings' ); ?>
			<input type="hidden" name="action" value="thessley_fi_save_settings">

			<?php Thessley_UI::section( 'Settings', 'admin-generic' ); ?>
				<?php
				Thessley_UI::row(
					'Daily scan checks',
					function () {
						?>
						<label><input type="checkbox" name="check_core" <?php checked( get_option( 'thessley_integrity_check_core', true ) ); ?>> Core files vs WordPress.org checksums</label>
						<label><input type="checkbox" name="check_baseline" <?php checked( get_option( 'thessley_integrity_check_baseline', true ) ); ?>> Plugins/themes vs local baseline</label>
						<?php
					},
					'Findings are written to the Event Log. A scan that cannot finish within its time budget is reported as partial rather than treated as complete.'
				);
				?>
			<?php Thessley_UI::section_end(); ?>

			<?php submit_button( 'Save settings' ); ?>
		</form>
		<?php
		Thessley_UI::close();
	}
}
