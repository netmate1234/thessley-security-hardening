<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Required from this plugin's own folder by wp-thessley-early.php while the
// geo-blocker module is enabled.
//
// Binary search over a flat file of fixed 9-byte records (4-byte start,
// 4-byte end, 1-byte country index) rather than loading ~358,000 ranges
// into a PHP array — see the module.php header comment for why.
//
// Deliberately raw fopen()/fseek()/fread(), not WP_Filesystem: this runs
// pre-bootstrap, on every single front-end request, and does a seekable
// partial read at an arbitrary byte offset per binary-search step —
// WP_Filesystem's API only exposes whole-file get_contents()/put_contents(),
// which would mean reading this entire multi-megabyte index into memory on
// every request, exactly what the binary-search design exists to avoid.
// WP_Filesystem() also needs wp-admin/includes/file.php and can prompt for
// credentials on some hosts, neither appropriate for a per-request hot path
// that must stay usable before WordPress finishes loading at all.

if ( ! function_exists( 'thessley_geo_lookup' ) ) {
	/** @return int|null country index, or null if the file is missing/IP not found */
	function thessley_geo_lookup( $file, $needle ) {
		static $fh = null;
		static $opened_path = null;
		static $count = null;
		$record_size = 9; // 4-byte start + 4-byte end + 1-byte country index

		if ( '' === $file ) {
			return null; // data folder not created yet
		}

		if ( $opened_path !== $file ) {
			if ( is_resource( $fh ) ) {
				fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- see file header
			}
			$fh = @fopen( $file, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- see file header
			$opened_path = $file;
			$count = $fh ? (int) ( filesize( $file ) / $record_size ) : 0;
		}

		if ( ! $fh || $count < 1 ) {
			return null;
		}

		$lo = 0;
		$hi = $count - 1;

		while ( $lo <= $hi ) {
			$mid = (int) ( ( $lo + $hi ) / 2 );
			fseek( $fh, $mid * $record_size );
			$data = fread( $fh, $record_size ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- see file header
			if ( false === $data || strlen( $data ) < $record_size ) {
				return null;
			}
			$rec = unpack( 'Nstart/Nend/Cidx', $data );

			if ( $needle < $rec['start'] ) {
				$hi = $mid - 1;
			} elseif ( $needle > $rec['end'] ) {
				$lo = $mid + 1;
			} else {
				return $rec['idx'];
			}
		}

		return null;
	}
}

if ( ! function_exists( 'thessley_geo_country_label' ) ) {
	/**
	 * Only called on an actual match (rare), so loading the small names
	 * map here — rather than carrying the full country list into every
	 * request — costs nothing on the hot path.
	 */
	function thessley_geo_country_label( $idx ) {
		static $labels = null;
		if ( null === $labels ) {
			$file    = thessley_data_file( 'geo-country-names.json' );
			$decoded = ( '' !== $file && is_readable( $file ) ) ? json_decode( (string) file_get_contents( $file ), true ) : null;
			$labels  = is_array( $decoded ) ? $decoded : array();
		}
		return $labels[ $idx ] ?? "index {$idx}";
	}
}

thessley_register_check(
	function () {
		$indices = get_option( 'thessley_geo_country_indices', array() );
		if ( empty( $indices ) ) {
			return null; // nothing configured to block or allow
		}

		$ip = thessley_client_ip();
		if ( '' === $ip || false === strpos( $ip, '.' ) || thessley_ip_is_exempt( $ip ) ) {
			return null;
		}

		$needle = ip2long( $ip );
		if ( false === $needle ) {
			return null;
		}

		$idx = thessley_geo_lookup( thessley_data_file( 'geo-country-index.bin' ), $needle );
		if ( null === $idx ) {
			return null; // unknown to the dataset — fail open, not closed
		}

		$mode    = get_option( 'thessley_geo_mode', 'blocklist' );
		$in_list = in_array( $idx, $indices, true );

		// blocklist: block if the country IS in the list.
		// allowlist: block if the country is NOT in the list.
		$should_block = ( 'allowlist' === $mode ) ? ! $in_list : $in_list;
		if ( ! $should_block ) {
			return null;
		}

		$enforce = get_option( 'thessley_geo_enforce_mode', 'log' );
		$label   = thessley_geo_country_label( $idx );

		if ( 'block' !== $enforce ) {
			thessley_log_event( 'geo-blocker', 'country_match', 'logged', "country {$label}, mode={$mode} (log-only)", 6 );
			return null;
		}

		thessley_log_event( 'geo-blocker', 'country_match', 'blocked', "country {$label}, mode={$mode}", 8 );

		return array( 'reason' => 'Access denied.' );
	}
);
