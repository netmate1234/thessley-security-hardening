<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Shared presentation helpers for every Thessley Security Hardening screen.
 *
 * All styling is inlined and all icons come from the Dashicons font that
 * wp-admin already loads, so the plugin's own screens keep working under a
 * strict Content-Security-Policy — which this plugin can itself set.
 */
class Thessley_UI {

	/** @var bool emitted once per request */
	private static $styles_done = false;

	/** Page-level icon + copy for each screen, keyed by module. */
	public static function meta( $key ) {
		$map = array(
			'dashboard'      => array( 'shield', 'Thessley Security Hardening', '' ),
			'event-log'      => array( 'list-view', 'Event Log', 'Everything the modules have seen, newest first. Severity runs 1–20; anything 18+ means something already happened rather than an attempt that was stopped.' ),
			'ip-blocklist'   => array( 'shield-alt', 'IP Blocklist', 'Blocks traffic from IPs on public reputation feeds, plus a local list other modules can escalate into.' ),
			'whitelist'      => array( 'yes-alt', 'Whitelist', 'A trusted-networks CIDR feed plus individually-listed IPs, both exempt from every blocking module — IP Blocklist, Geo Blocker, Geo Login, Rate Limiter, Login Guard, Query Guard, and User Enumeration all honor this same list.' ),
			'query-guard'    => array( 'filter', 'Query Guard', 'Inspects query strings and request bodies for attack signatures before WordPress finishes loading.' ),
			'login-guard'    => array( 'lock', 'Login Guard', 'Rate-limits failed logins per IP. Your LAN and anything on the Whitelist tab is never locked out.' ),
			'headers'        => array( 'shield', 'Security Headers', 'Response headers that harden the browser side. The two that can break a site are off by default.' ),
			'user-enum'      => array( 'hidden', 'User Enumeration', 'Stops anonymous visitors harvesting valid usernames — which halves the work of a brute force.' ),
			'file-integrity' => array( 'media-code', 'File Integrity', 'Verifies core against WordPress.org checksums, and plugins/themes against a local baseline.' ),
			'vuln-scanner'   => array( 'search', 'Vulnerability Scan', 'Flags outdated, removed and unmaintained components. 91% of WordPress vulnerabilities live in plugins.' ),
			'auto-update'    => array( 'update', 'Auto Updates', 'About 60% of compromises exploit an already-patched flaw. Installing the update is the fix.' ),
			'user-watchdog'  => array( 'admin-users', 'User Watchdog', 'Watches privileged accounts. A hidden administrator is how a backdoor survives removal of the code that planted it.' ),
			'hardening'      => array( 'admin-tools', 'Hardening', 'Removes the tools an attacker reaches for after getting in.' ),
			'alerts'         => array( 'testimonial', 'Alerts', 'Sends a real-time Telegram message and/or email when an event exceeds a severity threshold. The Event Log records everything regardless of this setting.' ),
			'ip-sharing'      => array( 'shield-alt', 'IP Sharing', 'Shares genuine blocks with unwantedip.eagleeye-intelligence.com, a self-hosted IP reputation tracker. Only actual blocks, at most once per IP per hour.' ),
			'scan-all'        => array( 'search', 'Scan All', 'One button for File Integrity, Malware Scanner, Vulnerability Scan, and User Watchdog — scheduled to run immediately in the background rather than blocking this page.' ),
			'malware-scanner' => array( 'warning', 'Malware Scanner', 'Scans plugin, theme and upload files for webshell, obfuscation and injected-spam signatures.' ),
			'geo-blocker'     => array( 'admin-site-alt3', 'Geo Blocker', 'Blocks or allows traffic by country, using a compiled IP-to-country dataset checked at the early gate.' ),
			'activity-log'    => array( 'edit-page', 'Activity Log', 'Records who published, deleted, installed or changed what — the mundane audit trail, not attack detections.' ),
			'bot-log'         => array( 'networking', 'Bot Log', 'Every verified visit from a known crawler on the trusted-networks list (Googlebot, Bingbot, and the rest) — separate from the Event Log, since this is expected traffic, not something to review for attacks.' ),
			'rate-limiter'    => array( 'clock', 'Rate Limiter', 'Throttles requests per IP site-wide, and escalates sustained floods to the local IP blocklist.' ),
			'geo-map'         => array( 'admin-site-alt3', 'Event Map', 'Blocked and logged events tinted on a world map by country, reusing Geo Blocker\'s dataset. Read-only — nothing here affects enforcement.' ),
			'geo-login'       => array( 'lock', 'Geo Login', 'Restricts wp-login.php to an allow-list of countries. Your LAN, reserved space, and the trusted-networks file are always exempt, so this can\'t lock out your own network.' ),
			'config-io'       => array( 'download', 'Import/Export', 'Back up every module\'s settings to a file, or restore them on another install — with each module optionally left out on either side.' ),
		);

		return $map[ $key ] ?? array( 'shield', 'Thessley Security Hardening', '' );
	}

	/** Opens .wrap and renders the page header. Pair with self::close(). */
	public static function open( $key ) {
		self::styles();
		list( $icon, $title, $desc ) = self::meta( $key );
		?>
		<div class="wrap thessley">
			<div class="thessley-head">
				<span class="thessley-head__icon dashicons dashicons-<?php echo esc_attr( $icon ); ?>"></span>
				<div>
					<h1><?php echo esc_html( $title ); ?></h1>
					<?php if ( $desc ) : ?>
						<p class="thessley-head__desc"><?php echo esc_html( $desc ); ?></p>
					<?php endif; ?>
				</div>
			</div>
		<?php
	}

	public static function close() {
		echo '</div>';
	}

	/**
	 * @param string $type success|warning|error|info
	 */
	public static function notice( $type, $message, $allow_html = false ) {
		$icons = array(
			'success' => 'yes-alt',
			'warning' => 'warning',
			'error'   => 'dismiss',
			'info'    => 'info-outline',
		);
		$icon = $icons[ $type ] ?? 'info-outline';
		?>
		<div class="thessley-notice thessley-notice--<?php echo esc_attr( $type ); ?>">
			<span class="dashicons dashicons-<?php echo esc_attr( $icon ); ?>"></span>
			<div><?php echo $allow_html ? wp_kses_post( $message ) : esc_html( $message ); ?></div>
		</div>
		<?php
	}

	/** Opens a titled section card. Pair with self::section_end(). */
	public static function section( $title, $icon = '', $subtitle = '' ) {
		?>
		<section class="thessley-section">
			<header class="thessley-section__head">
				<?php if ( $icon ) : ?>
					<span class="dashicons dashicons-<?php echo esc_attr( $icon ); ?>"></span>
				<?php endif; ?>
				<h2><?php echo esc_html( $title ); ?></h2>
				<?php if ( $subtitle ) : ?>
					<span class="thessley-section__sub"><?php echo esc_html( $subtitle ); ?></span>
				<?php endif; ?>
			</header>
			<div class="thessley-section__body">
		<?php
	}

	public static function section_end() {
		echo '</div></section>';
	}

	/**
	 * Status badge.
	 *
	 * @param string $tone good|warn|bad|quiet
	 */
	public static function badge( $text, $tone = 'quiet', $icon = '' ) {
		printf(
			'<span class="thessley-badge thessley-badge--%s">%s%s</span>',
			esc_attr( $tone ),
			$icon ? '<span class="dashicons dashicons-' . esc_attr( $icon ) . '"></span>' : '',
			esc_html( $text )
		);
	}

	/** Compact key/value tiles for a status row. */
	public static function tiles( array $tiles ) {
		echo '<div class="thessley-tiles">';
		foreach ( $tiles as $tile ) {
			printf(
				'<div class="thessley-tile thessley-tile--%s"><span class="dashicons dashicons-%s"></span><div><strong>%s</strong><span>%s</span></div></div>',
				esc_attr( $tile['tone'] ?? 'quiet' ),
				esc_attr( $tile['icon'] ?? 'marker' ),
				esc_html( $tile['value'] ),
				esc_html( $tile['label'] )
			);
		}
		echo '</div>';
	}

	/** A labelled row inside a settings card (replaces .form-table). */
	public static function row( $label, $body_cb, $help = '' ) {
		?>
		<div class="thessley-row">
			<div class="thessley-row__label"><?php echo esc_html( $label ); ?></div>
			<div class="thessley-row__field">
				<?php call_user_func( $body_cb ); ?>
				<?php if ( $help ) : ?>
					<p class="thessley-help"><?php echo wp_kses_post( $help ); ?></p>
				<?php endif; ?>
			</div>
		</div>
		<?php
	}

	public static function severity_badge( $severity, $with_label = true ) {
		list( $label, $color ) = thessley_severity_meta( $severity );
		printf(
			'<span class="thessley-sev"><span class="thessley-sev__num" style="background:%s">%d</span>%s</span>',
			esc_attr( $color ),
			(int) $severity,
			$with_label ? '<span class="thessley-sev__label">' . esc_html( $label ) . '</span>' : ''
		);
	}

	/**
	 * No-op now that the CSS is enqueued externally by
	 * Thessley_Module_Loader::enqueue_assets() (admin_enqueue_scripts) —
	 * kept as a harmless call target since open() and the dashboard both
	 * still call it, and admin_enqueue_scripts runs well before any of
	 * their render callbacks (wp-admin's <head> is already sent by then,
	 * so printing a <style> tag from here would be too late anyway).
	 */
	public static function styles() {
		self::$styles_done = true;
	}
}
