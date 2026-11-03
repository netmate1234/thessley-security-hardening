<?php
/**
 * Offline unit test for the Query Guard path/query/User-Agent signatures.
 *
 * Run: php tests/query-guard-signatures.php
 *
 * Needs no WordPress: it stubs the two functions check.php touches at load
 * time. "should hit" lists are real probe paths seen in production logs;
 * "should miss" lists are legitimate URLs that must never be flagged.
 */
define( 'ABSPATH', '/' );
function thessley_register_check( $c, $p = 10 ) {}
function get_option( $k, $d = false ) { return $d; }
require __DIR__ . '/../thessley-security-hardening/includes/modules/query-guard/check.php';

$should_hit = array(
	'/.git/HEAD', '/.git/config', '/.git/logs/HEAD', '/.aws/credentials', '/.aws/credentials.bak', '/.docker/config.json', '/.pypirc', '/.netrc',
	'/.cursor/mcp.json', '/.vscode/settings.json', '/.continue/config.json', '/.claude/settings.json', '/.claude.json', '/.codex/auth.json',
	'/bak/.claude/credentials.json', '/.config/claude/credentials.json', '/.config/gcloud/credentials.db', '/.dev.vars', '/.firebaserc', '/id_rsa', '/backup/.ssh/id_ed25519',
	'/config.json', '/config.yml', '/config.yaml', '/secrets.json', '/credentials.json', '/google-credentials.json', '/mcp-servers.json', '/vercel.json',
	'/next.config.js', '/docker-compose.yml', '/terraform.tfstate', '/prod.tfvars', '/bootstrap/cache/config.php', '/rest/credentials', '/api/v1/credentials',
	'/package.json', '/composer.json', '/actuator/env', '/actuator/configprops', '/debug/pprof/cmdline', '/_all_dbs', '/cgi-bin/info.cgi',
	'/@fs/proc/self/environ', '/@fs/root/rootkey.csv', '/api/session/properties', '/_profiler/phpinfo',
	'/wp-content/plugins/hellopress/wp_filemanager.php', '/this_is_a_new_hello_world.php', '/shell.php',
	'/wp-login.php/wp-json/wp/v2/users/', '/wp-login.php/wp-includes/wlwmanifest.xml', "/.env\0.html", '/.env.production', '/.env.production.local',
	'/.env.development.local', '/backup/', '/backups', '/dump/',
);
$should_miss = array(
	'/', '/wp-login.php', '/wp-login.php/', '/wp-admin/', '/wp-content/plugins/foo/config.json', '/wp-content/plugins/foo/package.json',
	'/wp-content/uploads/2026/09/report.json', '/.well-known/security.txt', '/.well-known/acme-challenge/abc', '/wp-json/wp/v2/posts', '/graphql',
	'/api/graphql', '/.github/workflows/x.yml', '/.gitignore', '/sitemap.xml', '/robots.txt', '/backup-schedule/', '/backups-are-great/', '/blog/backup-tips',
	'/wp-content/themes/enfold/config-templatebuilder/avia-template-builder/assets/js/avia-modal.js', '/plomberie-belgique/installation/', '/contact',
	'/wp-cron.php', '/xmlrpc.php',
);
$qs         = array(
	'_u=6e2ed6e9' => true, 'rest_route=/batch/v1&_u=05730845' => true, 'foo=1&_u=abc' => false, 's=hello' => false, 'page_id=2' => false,
);
$ua_hit     = array(
	'crusader-worker/1.0', 'metabase-cve-2026-72898-detect', 'SmarterMail-Scanner/1.0 (authorized-research)', 'libredtail-http',
	'Mozilla/5.0 (compatible; Infrawatch/1.0; +https://x)', 'Mozilla/5.0 (compatible; CMS-Checker/1.0; +http://x)', 'AgentTrustBot/1.0 (+https://ag)',
	'Mozilla/5.0 (compatible; InternetMeasurement/1.0)',
);
$ua_miss    = array(
	'curl/8.6.0', 'python-requests/2.31', 'Go-http-client/1.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36',
	'Mozilla/5.0 (compatible; Googlebot/2.1)', 'Jetpack by WordPress.com', 'WordPress/6.6; https://example.com', '',
);

$bad = 0;
foreach ( $should_hit as $p ) {
	if ( ! thessley_query_guard_scan_path( $p ) ) {
		echo 'MISSED  ' . str_replace( "\0", '\0', $p ) . "\n";
		++$bad;
	}
}
foreach ( $should_miss as $p ) {
	$r = thessley_query_guard_scan_path( $p );
	if ( $r ) {
		echo "FALSE+  $p => {$r['id']}\n";
		++$bad;
	}
}
foreach ( $qs as $q => $expected ) {
	$r = thessley_query_guard_scan( $q, array( 'sqli', 'xss', 'traversal', 'cmdi', 'other' ) );
	if ( (bool) $r !== $expected ) {
		echo "QS MISMATCH $q\n";
		++$bad;
	}
}
foreach ( $ua_hit as $u ) {
	if ( ! thessley_query_guard_scan_ua( $u ) ) {
		echo "UA MISSED $u\n";
		++$bad;
	}
}
foreach ( $ua_miss as $u ) {
	if ( thessley_query_guard_scan_ua( $u ) ) {
		echo "UA FALSE+ $u\n";
		++$bad;
	}
}

$total = count( $should_hit ) + count( $should_miss ) + count( $qs ) + count( $ua_hit ) + count( $ua_miss );
echo $bad ? "$bad problems\n" : "all signature tests pass ($total cases)\n";
exit( $bad ? 1 : 0 );
