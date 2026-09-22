<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Copied verbatim into wp-content/mu-plugins/wp-thessley-checks/ by the
// ip-blocklist module on activation. Runs inside wp-thessley-early.php.

thessley_register_check(
	function () {
		static $ranges = null;
		static $local  = null;

		if ( null === $ranges ) {
			$data_file = __DIR__ . '/data/ip-blocklist-ranges.php';
			$ranges    = file_exists( $data_file ) ? require $data_file : array();
		}
		if ( null === $local ) {
			$local = file_exists( thessley_local_blocklist_file() ) ? require thessley_local_blocklist_file() : array();
		}

		if ( empty( $ranges ) && empty( $local ) ) {
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
		if ( thessley_ip_in_ranges( $needle, $local ) ) {
			$source = 'local';
			$label  = 'local blocklist';
		} elseif ( thessley_ip_in_ranges( $needle, $ranges ) ) {
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
			$file      = __DIR__ . '/data/ip-blocklist-by-source.php';
			$by_source = file_exists( $file ) ? require $file : array();
		}

		$labels = array();
		foreach ( $by_source as $label => $source_ranges ) {
			if ( thessley_ip_in_ranges( $needle, $source_ranges ) ) {
				$labels[] = $label;
			}
		}
		return $labels;
	}
}

if ( ! function_exists( 'thessley_ip_in_ranges' ) ) {
	/** @param array<int, array{0:int,1:int}> $ranges sorted, non-overlapping */
	function thessley_ip_in_ranges( $needle, array $ranges ) {
		$lo = 0;
		$hi = count( $ranges ) - 1;

		while ( $lo <= $hi ) {
			$mid   = (int) ( ( $lo + $hi ) / 2 );
			$range = $ranges[ $mid ];

			if ( $needle < $range[0] ) {
				$hi = $mid - 1;
			} elseif ( $needle > $range[1] ) {
				$lo = $mid + 1;
			} else {
				return true;
			}
		}

		return false;
	}
}
