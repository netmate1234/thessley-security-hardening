<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Pulls known-bad IP ranges from public reputation lists and normalizes
 * them to a flat list of [start, end] IPv4 integer ranges.
 */
class Thessley_IP_Blocklist_Fetcher {

	/**
	 * Source registry. 'type' selects the parser:
	 *   ip_list    - one bare IPv4 per line, '#' comments
	 *   range_list - "start end ..." whitespace-delimited per line, '#' comments
	 *   cidr_list  - CIDR or bare IPv4 per line, '#' full-line or ';' inline comments
	 */
	const SOURCES = array(
		'cins'           => array(
			'label' => 'CINS Army (poor-reputation IPs)',
			'url'   => 'https://cinsscore.com/list/ci-badguys.txt',
			'type'  => 'ip_list',
		),
		'dshield'        => array(
			'label' => 'DShield (top attacker /24s)',
			'url'   => 'https://feeds.dshield.org/block.txt',
			'type'  => 'range_list',
		),
		'spamhaus_drop'  => array(
			'label' => 'Spamhaus DROP (hijacked/spammer netblocks)',
			'url'   => 'https://www.spamhaus.org/drop/drop.txt',
			'type'  => 'cidr_list',
		),
		'firehol_level1' => array(
			'label' => 'FireHOL level1 (DShield+Spamhaus DROP+bogons+Feodo, merged, low-FP)',
			'url'   => 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- a plain-text threat-feed URL fetched server-side (wp_remote_get) to compile a local blocklist, not a front-end JS/CSS/image asset.
			'type'  => 'cidr_list',
		),
		'firehol_level2' => array(
			'label' => 'FireHOL level2 (48h recent-attacker feed, large & volatile)',
			'url'   => 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset', // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- same as firehol_level1 above.
			'type'  => 'cidr_list',
		),
		'et_tor'         => array(
			'label' => 'ET Tor (Emerging Threats Tor exit nodes)',
			'url'   => 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/et_tor.ipset', // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- same as firehol_level1 above.
			'type'  => 'ip_list',
		),
		'unwantedip_wp'  => array(
			'label' => 'unwantedip.eagleeye-intelligence.com (WordPress-targeting IPs, 90d)',
			'url'   => 'https://unwantedip.eagleeye-intelligence.com/api/v1/feed/wordpress',
			'type'  => 'ip_list',
			// Requires the same API key as the IP Sharing tab — set up there
			// first, since a key with report-write access also gets read
			// access to this feed. Silently skipped (not a fetch failure) if
			// no key is configured, same as any other not-yet-set-up source.
			'auth'  => 'unwantedip_key',
		),
	);

	const DEFAULT_ENABLED = array( 'cins', 'dshield' );

	/**
	 * @param string[] $enabled source ids from self::SOURCES to fetch
	 * @return array<int, array{0:int,1:int,2:string}> ranges as [start, end, source]
	 */
	public static function fetch_all( array $enabled ) {
		$ranges         = array();
		self::$problems = array();

		foreach ( self::SOURCES as $id => $source ) {
			if ( ! in_array( $id, $enabled, true ) ) {
				continue;
			}

			$headers = array();
			if ( 'unwantedip_key' === ( $source['auth'] ?? '' ) ) {
				$key = trim( (string) get_option( 'thessley_unwantedip_api_key', '' ) );
				if ( '' === $key ) {
					self::$problems[ $id ] = 'needs an API key (set one on the IP Sharing tab)';
					continue; // not set up yet — not a fetch failure, just nothing to fetch with
				}
				$headers['X-API-Key'] = $key;
			}

			$body = self::download( $source['url'], $headers );
			if ( false === $body ) {
				self::$problems[ $id ] = 'download failed (' . self::$last_error . ')';
				continue;
			}

			$parsed = self::parse( $source['type'], $body );
			if ( ! $parsed ) {
				self::$problems[ $id ] = 'downloaded, but it contained no usable entries';
			}

			foreach ( $parsed as $range ) {
				$ranges[] = array( $range[0], $range[1], $id );
			}
		}

		return $ranges;
	}

	private static function parse( $type, $body ) {
		switch ( $type ) {
			case 'ip_list':
				return self::parse_ip_list( $body );
			case 'range_list':
				return self::parse_range_list( $body );
			case 'cidr_list':
				return self::parse_cidr_list( $body );
			default:
				return array();
		}
	}

	/**
	 * Enabled sources that contributed nothing on the last fetch_all(), with
	 * the reason. Without this a feed that fails (a server error, a missing
	 * key) simply never shows up in the Reputation feeds table and looks
	 * like it was never enabled.
	 *
	 * @var array<string,string>
	 */
	public static $problems = array();

	private static $last_error = '';

	private static function download( $url, array $headers = array() ) {
		self::$last_error = '';
		$response = wp_remote_get(
			$url,
			array(
				'timeout'    => 30,
				'user-agent' => 'wp-thessley/' . THESSLEY_VERSION,
				'headers'    => $headers,
			)
		);

		if ( is_wp_error( $response ) ) {
			self::$last_error = $response->get_error_message();
			return false;
		}
		if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
			self::$last_error = 'HTTP ' . wp_remote_retrieve_response_code( $response );
			return false;
		}

		return wp_remote_retrieve_body( $response );
	}

	/** One bare IPv4 per line (CINS format). */
	private static function parse_ip_list( $body ) {
		$ranges = array();

		foreach ( preg_split( '/\r\n|\r|\n/', $body ) as $line ) {
			$line = trim( $line );
			if ( '' === $line || '#' === $line[0] ) {
				continue;
			}
			$long = ip2long( $line );
			if ( false !== $long ) {
				$ranges[] = array( $long, $long );
			}
		}

		return $ranges;
	}

	/** Whitespace-delimited "start end ..." per line (DShield format). */
	private static function parse_range_list( $body ) {
		$ranges = array();

		foreach ( preg_split( '/\r\n|\r|\n/', $body ) as $line ) {
			$line = trim( $line );
			if ( '' === $line || '#' === $line[0] ) {
				continue;
			}

			$fields = preg_split( '/\s+/', $line );
			if ( count( $fields ) < 2 ) {
				continue;
			}

			$start = ip2long( $fields[0] );
			$end   = ip2long( $fields[1] );
			if ( false !== $start && false !== $end && $end >= $start ) {
				$ranges[] = array( $start, $end );
			}
		}

		return $ranges;
	}

	/**
	 * CIDR or bare IPv4 per line. '#' marks a full-line comment (FireHOL);
	 * ';' marks a trailing inline comment (Spamhaus DROP), stripped first.
	 */
	private static function parse_cidr_list( $body ) {
		$ranges = array();

		foreach ( preg_split( '/\r\n|\r|\n/', $body ) as $line ) {
			$line = trim( preg_replace( '/;.*/', '', $line ) );
			if ( '' === $line || '#' === $line[0] ) {
				continue;
			}

			$parts  = explode( '/', $line, 2 );
			$long   = ip2long( $parts[0] );
			$prefix = isset( $parts[1] ) ? (int) $parts[1] : 32;

			if ( false === $long || $prefix < 0 || $prefix > 32 ) {
				continue;
			}

			if ( 32 === $prefix ) {
				$ranges[] = array( $long, $long );
				continue;
			}

			$mask  = ( 0xFFFFFFFF << ( 32 - $prefix ) ) & 0xFFFFFFFF;
			$start = $long & $mask;
			$end   = $start | ( ~$mask & 0xFFFFFFFF );
			$ranges[] = array( $start, $end );
		}

		return $ranges;
	}
}
