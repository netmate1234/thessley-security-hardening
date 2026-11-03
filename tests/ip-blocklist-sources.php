<?php
/**
 * Offline unit test for the three new IP Blocklist sources (ipsum,
 * firehol_webserver, reportedip_cms): parser correctness against real
 * sample data, no network and no WordPress needed.
 *
 * Run: php tests/ip-blocklist-sources.php <path-to-cached-samples-dir>
 * Samples expected: ipsum.txt, firehol_webserver.txt, reportedip_cms.txt
 */
define( 'ABSPATH', '/' );
define( 'THESSLEY_VERSION', 'test' );
function get_option( $k, $d = false ) { return $d; }
require __DIR__ . '/../thessley-security-hardening/includes/modules/ip-blocklist/class-fetcher.php';

$dir = $argv[1] ?? '/tmp';
$bad = 0;

// ip_count_list (ipsum): threshold filtering.
$ref  = new ReflectionMethod( 'Thessley_IP_Blocklist_Fetcher', 'parse_ip_count_list' );
$ref->setAccessible( true );
$sample = "# comment\n1.2.3.4\t5\n5.6.7.8 2\n9.10.11.12\t3\nnot-an-ip\t9\n";
$ranges = $ref->invoke( null, $sample );
$want   = array( array( ip2long( '1.2.3.4' ), ip2long( '1.2.3.4' ) ), array( ip2long( '9.10.11.12' ), ip2long( '9.10.11.12' ) ) );
if ( $ranges !== $want ) {
	echo "ip_count_list FAILED: " . var_export( $ranges, true ) . "\n";
	++$bad;
} else {
	echo "ip_count_list threshold filtering: ok (" . count( $ranges ) . " kept of 3 valid lines, count>=3)\n";
}

if ( is_file( $dir . '/ipsum.txt' ) ) {
	$body   = file_get_contents( $dir . '/ipsum.txt' );
	$ranges = $ref->invoke( null, $body );
	$total  = count( preg_split( '/\r\n|\r|\n/', trim( $body ) ) );
	echo "ipsum.txt: {$total} lines -> " . count( $ranges ) . " ranges kept at count>=" . Thessley_IP_Blocklist_Fetcher::IPSUM_MIN_COUNT . "\n";
	if ( ! $ranges ) {
		echo "  FAILED: expected some ranges\n";
		++$bad;
	}
}

$cidr_ref = new ReflectionMethod( 'Thessley_IP_Blocklist_Fetcher', 'parse_cidr_list' );
$cidr_ref->setAccessible( true );
if ( is_file( $dir . '/firehol_webserver.txt' ) ) {
	$ranges = $cidr_ref->invoke( null, file_get_contents( $dir . '/firehol_webserver.txt' ) );
	echo "firehol_webserver.txt: " . count( $ranges ) . " ranges parsed\n";
	if ( ! $ranges ) {
		echo "  FAILED: expected some ranges\n";
		++$bad;
	}
}

$ip_ref = new ReflectionMethod( 'Thessley_IP_Blocklist_Fetcher', 'parse_ip_list' );
$ip_ref->setAccessible( true );
if ( is_file( $dir . '/reportedip_cms.txt' ) ) {
	$ranges = $ip_ref->invoke( null, file_get_contents( $dir . '/reportedip_cms.txt' ) );
	echo "reportedip_cms.txt: " . count( $ranges ) . " ranges parsed\n";
	if ( ! $ranges ) {
		echo "  FAILED: expected some ranges\n";
		++$bad;
	}
}

// SOURCES registry sanity.
foreach ( array( 'ipsum', 'firehol_webserver', 'reportedip_cms' ) as $id ) {
	if ( ! isset( Thessley_IP_Blocklist_Fetcher::SOURCES[ $id ] ) ) {
		echo "MISSING source registry entry: $id\n";
		++$bad;
	}
}

echo $bad ? "$bad problems\n" : "all ip-blocklist source tests pass\n";
exit( $bad ? 1 : 0 );
