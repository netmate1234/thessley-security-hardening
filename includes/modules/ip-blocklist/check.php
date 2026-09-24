<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Required from this plugin's own folder by wp-thessley-early.php while this
// module is enabled.

thessley_register_check(
	function () {
		static $ranges = null;

		// Flat binary file of 8-byte [start, end] records, searched in place.
		if ( null === $ranges ) {
			$data_file = thessley_data_file( 'ip-blocklist-ranges.bin' );
			$ranges    = ( '' !== $data_file && is_readable( $data_file ) ) ? (string) file_get_contents( $data_file ) : '';
		}
		if ( '' === $ranges && ! get_option( 'thessley_local_blocklist', array() ) ) {
			return null;
		}

		$ip = thessley_client_ip();
		if ( '' === $ip || false === strpos( $ip, '.' ) ) {
			return null; // no IPv4 to check (IPv6 not covered by these sources)
		}

		if ( thessley_ip_is_exempt( $ip ) ) {
			return null; // LAN/reserved/trusted/allowlisted — same shared rule every other module follows
		}

		$needle = ip2long( $ip );
		if ( false === $needle ) {
			return null;
		}

		$source = null;
		$label  = '';
		if ( thessley_local_blocklist_has( $ip ) ) {
			$source = 'local';
			$label  = 'local blocklist';
		} elseif ( thessley_ip_in_packed_ranges( $needle, $ranges ) ) {
			$source     = 'reputation list';
			$src_labels = thessley_ip_reputation_sources( $needle );
			$label      = $src_labels ? implode( ', ', $src_labels ) : 'reputation list';
		}

		if ( null === $source ) {
			return null;
		}

		$mode = get_option( 'thessley_ip_blocklist_mode', 'log' );

		if ( 'block' !== $mode ) {
			thessley_log_event( 'ip-blocklist', 'listed_ip', 'logged', "matched {$label} (log-only mode)" );
			return null;
		}

		thessley_log_event( 'ip-blocklist', 'listed_ip', 'blocked', "matched {$label}" );

		return array( 'reason' => 'Access denied.' );
	}
);

if ( ! function_exists( 'thessley_ip_reputation_sources' ) ) {
	/**
	 * Only called after a reputation-list hit is already decided — never
	 * on the hot path for the vast majority of requests that don't match
	 * anything. The merged range file used for the block decision itself
	 * has no per-source attribution left (overlapping ranges from
	 * different feeds get coalesced into one span on compile), so this
	 * re-checks the same IP against each source's own unmerged ranges,
	 * purely for a readable Event Log line.
	 *
	 * @return string[] human labels of every source whose range covers $needle
	 */
	function thessley_ip_reputation_sources( $needle ) {
		static $by_source = null;
		if ( null === $by_source ) {
			$file      = thessley_data_file( 'ip-blocklist-by-source.json' );
			$decoded   = ( '' !== $file && is_readable( $file ) ) ? json_decode( (string) file_get_contents( $file ), true ) : null;
			$by_source = is_array( $decoded ) ? $decoded : array();
		}

		$labels = array();
		foreach ( $by_source as $label => $source_ranges ) {
			if ( thessley_ip_in_packed_ranges( $needle, (string) base64_decode( $source_ranges ) ) ) {
				$labels[] = $label;
			}
		}
		return $labels;
	}
}

if ( ! function_exists( 'thessley_ip_in_packed_ranges' ) ) {
	/**
	 * @param int    $needle IPv4 as an integer.
	 * @param string $packed Sorted, non-overlapping ranges, 8 bytes each: big-endian uint32 start then end.
	 */
	function thessley_ip_in_packed_ranges( $needle, $packed ) {
		$lo = 0;
		$hi = (int) ( strlen( $packed ) / 8 ) - 1;

		while ( $lo <= $hi ) {
			$mid   = (int) ( ( $lo + $hi ) / 2 );
			$range = unpack( 'Nstart/Nend', substr( $packed, $mid * 8, 8 ) );

			if ( $needle < $range['start'] ) {
				$hi = $mid - 1;
			} elseif ( $needle > $range['end'] ) {
				$lo = $mid + 1;
			} else {
				return true;
			}
		}

		return false;
	}
}
