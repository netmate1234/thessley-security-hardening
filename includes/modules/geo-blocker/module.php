<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require_once __DIR__ . '/class-country-codes.php';

/**
 * Country-level blocking.
 *
 * IP-to-country data comes from DB-IP's free "Country Lite" database
 * (CC BY 4.0, no registration required) — roughly 358,000 IPv4 ranges,
 * updated monthly. That's ~19x larger than any other list this plugin
 * compiles, and a plain PHP-array-plus-binary-search (the pattern used for
 * ip-blocklist) would mean a multi-megabyte array baked into opcache on
 * every server running this plugin. Instead the compiled data is a flat
 * binary file of fixed 9-byte records (4-byte start, 4-byte end, 1-byte
 * country index), sorted by start, and the early-gate check does a
 * classic on-disk binary search via fseek/fread — no PHP array, no
 * meaningful per-request memory cost, ~19 seeks per lookup.
 *
 * The check itself never needs country *names* — the admin's blocked/
 * allowed selection is converted to a small set of integer indices at
 * save time, and the hot path only ever compares integers.
 */
class Thessley_Module_Geo_Blocker {

	const CRON_HOOK    = 'thessley_geo_refresh';
	const RECORD_SIZE  = 9; // 4 + 4 + 1 bytes
	const SOURCE_BASE  = 'https://download.db-ip.com/free/dbip-country-lite-';

	public static function data_file() {
		return THESSLEY_CHECKS_DIR . '/data/geo-country-index.bin';
	}

	public static function activate() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + ( 50 * MINUTE_IN_SECONDS ), 'weekly', self::CRON_HOOK );
		}
		self::deploy_check_file();
		// No DB-IP download here — refresh() (below) won't actually fetch
		// anything, cron-triggered or otherwise, until the admin has saved
		// this module's settings or clicked "Refresh Now" at least once.
		// Activating the plugin must never by itself start pulling a ~15MB
		// dataset from a third party.
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
		if ( file_exists( self::check_dest() ) ) {
			Thessley_Module_Loader::fs_delete( self::check_dest() );
		}
	}

	public static function check_dest() {
		return THESSLEY_CHECKS_DIR . '/geo-blocker.php';
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

	public static function register() {
		self::deploy_check_file();

		add_action( self::CRON_HOOK, array( __CLASS__, 'refresh' ) );
		add_action( 'admin_post_thessley_geo_save_settings', array( __CLASS__, 'handle_save_settings' ) );
		add_action( 'admin_post_thessley_geo_refresh_now', array( __CLASS__, 'handle_refresh_now' ) );

		return __CLASS__;
	}

	/**
	 * DB-IP publishes monthly; try the current month, fall back a month if
	 * not out yet. Streams straight to a local temp file via WP's own
	 * download_url() (used by core for the same reason: a ~15MB response
	 * body never has to sit in PHP memory just to be written back out).
	 */
	private static function download_csv_gz() {
		if ( ! function_exists( 'download_url' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}

		foreach ( array( 0, 1, 2 ) as $months_back ) {
			$ts   = strtotime( "-{$months_back} months" );
			$url  = self::SOURCE_BASE . gmdate( 'Y-m', $ts ) . '.csv.gz';
			$path = download_url( $url, 60 );
			if ( ! is_wp_error( $path ) ) {
				return $path;
			}
		}
		return false;
	}

	/**
	 * Parses the gzipped CSV a line at a time via gzgets() — never holds
	 * the ~15MB decompressed CSV, or a ~358k-element array of its lines,
	 * in memory at once. Each valid row is kept as its already-packed
	 * 9-byte binary record instead of a 3-element PHP array; a plain array
	 * carries per-element/per-array overhead that dwarfs the 9 bytes of
	 * actual data at this row count, so this alone cuts the peak array
	 * size by roughly an order of magnitude.
	 */
	public static function refresh() {
		// Set only by handle_save_settings()/handle_refresh_now() — both
		// direct admin actions. Blocks the cron-triggered call (and any
		// stray call from elsewhere) from ever fetching DB-IP's dataset
		// before the admin has done something with this module themselves.
		if ( ! get_option( 'thessley_geo_blocker_initialized', false ) ) {
			return false;
		}

		$gz_path = self::download_csv_gz();
		if ( false === $gz_path ) {
			thessley_log_event( 'geo-blocker', 'refresh_failed', 'noted', 'could not download the DB-IP country dataset', 6 );
			return false;
		}

		$gz = @gzopen( $gz_path, 'rb' );
		if ( false === $gz ) {
			Thessley_Module_Loader::fs_delete( $gz_path );
			thessley_log_event( 'geo-blocker', 'refresh_failed', 'noted', 'downloaded dataset was not readable gzip', 6 );
			return false;
		}

		$indices    = Thessley_Geo_Country_Codes::indices();
		$records    = array();
		$prev_start = -1;
		$sorted     = true;

		while ( false !== ( $line = gzgets( $gz ) ) ) {
			$line = rtrim( $line, "\r\n" );
			if ( '' === $line || false !== strpos( $line, ':' ) ) {
				continue; // blank line, or IPv6 (always contains a colon) — IPv4-only, matching the rest of the plugin
			}
			$fields = explode( ',', $line, 4 );
			if ( count( $fields ) < 3 ) {
				continue;
			}
			$start = ip2long( $fields[0] );
			$end   = ip2long( $fields[1] );
			$idx   = $indices[ trim( $fields[2] ) ] ?? null;
			if ( false === $start || false === $end || null === $idx ) {
				continue;
			}

			if ( $start < $prev_start ) {
				$sorted = false;
			}
			$prev_start = $start;

			$records[] = pack( 'NNC', $start, $end, $idx );
		}
		gzclose( $gz );
		Thessley_Module_Loader::fs_delete( $gz_path );

		$count = count( $records );
		if ( $count < 1000 ) {
			// Sanity floor: a parse gone wrong (format change upstream)
			// should never silently replace a good index with an empty one.
			thessley_log_event( 'geo-blocker', 'refresh_suspicious', 'noted', sprintf( 'only %d ranges parsed, keeping previous index', $count ), 8 );
			return false;
		}

		if ( ! $sorted ) {
			// DB-IP ships pre-sorted; only pay for an actual sort on the
			// (rare) run where that invariant doesn't hold, instead of
			// unconditionally re-sorting a third of a million records every
			// refresh. Comparing the packed binary records byte-for-byte is
			// equivalent to a numeric comparison on the big-endian start
			// (then end, then country index) they're packed from.
			usort( $records, 'strcmp' );
		}

		self::write_index( $records );
		self::write_names_map();

		update_option( 'thessley_geo_stats', array( 'count' => $count, 'updated_at' => time() ), false );
		thessley_log_event( 'geo-blocker', 'refreshed', 'noted', sprintf( '%d ranges compiled', $count ), 2 );

		return $count;
	}

	/** @param string[] $records each element an already-packed 9-byte 'NNC' record. */
	private static function write_index( array $records ) {
		$file = self::data_file();
		$dir  = dirname( $file );
		if ( ! file_exists( $dir ) ) {
			wp_mkdir_p( $dir );
		}

		$tmp = $file . '.tmp-' . bin2hex( random_bytes( 4 ) );
		Thessley_Module_Loader::fs_put_contents( $tmp, implode( '', $records ) );
		Thessley_Module_Loader::fs_move( $tmp, $file, true );

		// Not opcache-relevant (this isn't PHP source), but the file is
		// reopened per request via fopen/fseek, so no cache to invalidate —
		// noted here only so the parallel with the other compiled sources is explicit.
	}

	/**
	 * A tiny index-to-"Name (CODE)" map, written alongside the binary
	 * index so check.php — which runs pre-bootstrap and can't load this
	 * plugin's classes — can turn a match into a readable log line without
	 * carrying the full ~250-entry country list into the early gate.
	 */
	private static function write_names_map() {
		$codes = array_keys( Thessley_Geo_Country_Codes::all() );
		$names = array_values( Thessley_Geo_Country_Codes::all() );

		$labels = array();
		foreach ( $names as $i => $name ) {
			$labels[ $i ] = "{$name} ({$codes[ $i ]})";
		}

		$file   = dirname( self::data_file() ) . '/geo-country-names.php';
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- serialization format for this auto-generated cache file, not leftover debug output.
		$export = "<?php\n// Auto-generated by wp-thessley geo-blocker module. Do not edit.\nreturn " . var_export( $labels, true ) . ";\n";

		$tmp = $file . '.tmp-' . bin2hex( random_bytes( 4 ) );
		Thessley_Module_Loader::fs_put_contents( $tmp, $export );
		Thessley_Module_Loader::fs_move( $tmp, $file, true );

		if ( function_exists( 'opcache_invalidate' ) ) {
			opcache_invalidate( $file, true );
		}
	}

	public static function handle_save_settings() {
		check_admin_referer( 'thessley_geo_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		$mode = ( isset( $_POST['mode'] ) && 'allowlist' === $_POST['mode'] ) ? 'allowlist' : 'blocklist';
		update_option( 'thessley_geo_mode', $mode );

		update_option( 'thessley_geo_enforce_mode', ( isset( $_POST['enforce'] ) && 'block' === $_POST['enforce'] ) ? 'block' : 'log' );

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- already unslashed, and array_intersect() against the real country-code list below discards anything not in it; nothing unvalidated ever reaches update_option().
		$posted = isset( $_POST['countries'] ) ? (array) wp_unslash( $_POST['countries'] ) : array();
		$codes  = array_values( array_intersect( $posted, array_keys( Thessley_Geo_Country_Codes::all() ) ) );
		update_option( 'thessley_geo_countries', $codes );

		// Pre-compute the index set the hot path actually reads, so the
		// early gate never has to load the country-name list at all.
		$indices = array();
		foreach ( $codes as $code ) {
			$i = Thessley_Geo_Country_Codes::index_of( $code );
			if ( null !== $i ) {
				$indices[] = $i;
			}
		}
		update_option( 'thessley_geo_country_indices', $indices, false );

		update_option( 'thessley_geo_blocker_initialized', true );

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function handle_refresh_now() {
		check_admin_referer( 'thessley_geo_refresh_now' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}
		update_option( 'thessley_geo_blocker_initialized', true );
		self::refresh();
		wp_safe_redirect( add_query_arg( 'refreshed', '1', wp_get_referer() ) );
		exit;
	}


	public static function render_page() {
		$stats     = get_option( 'thessley_geo_stats', array() );
		$mode      = get_option( 'thessley_geo_mode', 'blocklist' );
		$enforce   = get_option( 'thessley_geo_enforce_mode', 'log' );
		$selected  = (array) get_option( 'thessley_geo_countries', array() );

		Thessley_UI::open( 'geo-blocker' );

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only result flags set only by this module's own admin-post redirects, which already check_admin_referer() before redirecting.
		if ( isset( $_GET['saved'] ) ) {
			Thessley_UI::notice( 'success', 'Settings saved.' );
		}
		if ( isset( $_GET['refreshed'] ) ) {
			Thessley_UI::notice( 'success', 'Country index refreshed.' );
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		Thessley_UI::tiles(
			array(
				array(
					'icon'  => 'block' === $enforce ? 'shield-alt' : 'visibility',
					'tone'  => 'block' === $enforce ? 'good' : 'warn',
					'value' => 'block' === $enforce ? 'Blocking' : 'Log only',
					'label' => 'enforcement mode',
				),
				array(
					'icon'  => 'admin-site-alt3',
					'tone'  => 'quiet',
					'value' => 'allowlist' === $mode ? 'Allow-list' : 'Block-list',
					'label' => 'allowlist' === $mode ? 'only listed countries' : 'listed countries blocked',
				),
				array(
					'icon'  => 'admin-site',
					'tone'  => 'quiet',
					'value' => ! empty( $stats['count'] ) ? number_format_i18n( $stats['count'] ) : '—',
					'label' => ! empty( $stats['updated_at'] ) ? 'ranges, updated ' . date_i18n( 'M j', $stats['updated_at'] ) : 'not fetched yet',
				),
			)
		);

		?>
		<div class="thessley-actions" style="margin-bottom:18px">
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'thessley_geo_refresh_now' ); ?>
				<input type="hidden" name="action" value="thessley_geo_refresh_now">
				<?php submit_button( 'Refresh country index now', 'secondary', 'submit', false ); ?>
			</form>
		</div>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'thessley_geo_save_settings' ); ?>
			<input type="hidden" name="action" value="thessley_geo_save_settings">

			<?php Thessley_UI::section( 'Mode', 'admin-site-alt3' ); ?>
				<?php
				Thessley_UI::row(
					'List type',
					function () use ( $mode ) {
						?>
						<label><input type="radio" name="mode" value="blocklist" <?php checked( $mode, 'blocklist' ); ?>> Block-list — deny the countries checked below, allow everyone else</label>
						<label><input type="radio" name="mode" value="allowlist" <?php checked( $mode, 'allowlist' ); ?>> Allow-list — allow only the countries checked below, deny everyone else</label>
						<?php
					},
					'Allow-list is a hard lockdown, appropriate for a site with a genuinely regional audience. IP-to-country data is inherently approximate — VPNs, satellite links and mobile carriers routinely appear to originate from the wrong country — so treat this as a coarse filter, not a guarantee.'
				);

				Thessley_UI::row(
					'Enforcement',
					function () use ( $enforce ) {
						?>
						<label><input type="radio" name="enforce" value="log" <?php checked( $enforce, 'log' ); ?>> Log only</label>
						<label><input type="radio" name="enforce" value="block" <?php checked( $enforce, 'block' ); ?>> Block (403)</label>
						<?php
					},
					'As with every other blocking module: your LAN, reserved IP space, and anything in the trusted-networks file are permanently exempt, regardless of what country they resolve to.'
				);
				?>
			<?php Thessley_UI::section_end(); ?>

			<?php Thessley_UI::section( 'Countries', 'admin-site' ); ?>
				<div class="thessley-scroll" style="max-height:320px">
					<?php foreach ( Thessley_Geo_Country_Codes::all() as $code => $name ) : ?>
						<?php if ( 'ZZ' === $code ) { continue; } /* reserved space, not a real country to pick */ ?>
						<label style="display:inline-block;width:47%">
							<input type="checkbox" name="countries[]" value="<?php echo esc_attr( $code ); ?>" <?php checked( in_array( $code, $selected, true ) ); ?>>
							<?php echo esc_html( $name ); ?> <span class="thessley-muted">(<?php echo esc_html( $code ); ?>)</span>
						</label>
					<?php endforeach; ?>
				</div>
				<p class="thessley-help">IP geolocation data: <a href="https://db-ip.com" target="_blank" rel="noopener">DB-IP.com</a> Country Lite, used under CC BY 4.0, refreshed weekly.</p>
			<?php Thessley_UI::section_end(); ?>

			<?php submit_button( 'Save settings' ); ?>
		</form>
		<?php
		Thessley_UI::close();
	}
}
