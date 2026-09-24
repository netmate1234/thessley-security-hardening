<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Merges raw ranges into a sorted, non-overlapping list and writes it out
 * as a flat binary file the early gate can search with no DB dependency.
 */
class Thessley_IP_Blocklist_Compiler {

	/**
	 * @param array<int, array{0:int,1:int,2:string}> $ranges
	 * @return array{count_raw:int, count_merged:int, by_source:array<string,int>}
	 */
	public static function compile( array $ranges ) {
		$by_source = array();
		foreach ( $ranges as $r ) {
			$src               = $r[2] ?? 'unknown';
			$by_source[ $src ] = ( $by_source[ $src ] ?? 0 ) + 1;
		}

		$merged = self::merge( $ranges );
		$merged = self::exclude( $merged, thessley_reserved_ranges() );
		$merged = self::exclude( $merged, thessley_trusted_ranges() );
		self::write( $merged );
		self::write_by_source( $ranges );

		return array(
			'count_raw'    => count( $ranges ),
			'count_merged' => count( $merged ),
			'by_source'    => $by_source,
		);
	}

	/** @return array<int, array{0:int,1:int}> sorted, non-overlapping */
	private static function merge( array $ranges ) {
		if ( empty( $ranges ) ) {
			return array();
		}

		usort(
			$ranges,
			function ( $a, $b ) {
				return $a[0] <=> $b[0];
			}
		);

		$merged  = array();
		$current = array( $ranges[0][0], $ranges[0][1] );

		for ( $i = 1, $n = count( $ranges ); $i < $n; $i++ ) {
			list( $start, $end ) = $ranges[ $i ];

			if ( $start <= $current[1] + 1 ) {
				$current[1] = max( $current[1], $end );
			} else {
				$merged[] = $current;
				$current  = array( $start, $end );
			}
		}
		$merged[] = $current;

		return $merged;
	}

	/**
	 * @param array<int, array{0:int,1:int}> $merged
	 * @param array<int, array{0:int,1:int}> $cut ranges to remove
	 * @return array<int, array{0:int,1:int}> $merged with $cut ranges removed
	 * Used for both reserved space and the operator-supplied trusted-networks
	 * file, via the shared mu-loader definitions, so the external list and
	 * the local-escalation list can never disagree about what's exempt.
	 */
	private static function exclude( array $merged, array $cut ) {
		foreach ( $cut as $r ) {
			$next = array();
			foreach ( $merged as $piece ) {
				if ( $piece[1] < $r[0] || $piece[0] > $r[1] ) {
					$next[] = $piece; // no overlap
					continue;
				}
				if ( $piece[0] < $r[0] ) {
					$next[] = array( $piece[0], $r[0] - 1 ); // keep the part before
				}
				if ( $piece[1] > $r[1] ) {
					$next[] = array( $r[1] + 1, $piece[1] ); // keep the part after
				}
			}
			$merged = $next;
		}

		return $merged;
	}

	/**
	 * A second, per-source-labeled copy of the raw ranges, kept only so
	 * the Event Log can say *which* feed(s) actually listed a blocked IP
	 * instead of a generic "reputation list". Not used for the block
	 * decision itself — the merged, exemption-stripped file from write()
	 * still is — and never loaded on the hot path: check.php only reads
	 * this lazily, after a block is already decided, so its size costs
	 * nothing on every other request.
	 */
	private static function write_by_source( array $ranges ) {
		$grouped = array();
		foreach ( $ranges as $r ) {
			$id                 = $r[2] ?? 'unknown';
			$grouped[ $id ][] = array( $r[0], $r[1] );
		}

		$packed = array();
		foreach ( $grouped as $id => $group ) {
			$label            = Thessley_IP_Blocklist_Fetcher::SOURCES[ $id ]['label'] ?? ucfirst( $id );
			$packed[ $label ] = base64_encode( Thessley_Module_Loader::pack_ranges( self::merge( $group ) ) );
		}

		Thessley_Module_Loader::write_data_file( 'ip-blocklist-by-source.json', wp_json_encode( $packed ) );
	}

	private static function write( array $merged ) {
		Thessley_Module_Loader::write_data_file( 'ip-blocklist-ranges.bin', Thessley_Module_Loader::pack_ranges( $merged ) );
	}
}
