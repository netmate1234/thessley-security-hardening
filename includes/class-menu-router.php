<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Collapses the (now 17) individual module admin pages into a handful of
 * clustered pages with in-page tabs, instead of one long flat sidebar
 * list. Every module's own render_page()/render_settings_page() is
 * completely unchanged — still fully self-contained, with its own
 * Thessley_UI::open()/close() and its own header — this only changes
 * *where* that output appears (as a tab's content), not what it is.
 * Modules no longer register their own add_submenu_page(); this is the
 * single place the menu structure is defined.
 */
class Thessley_Menu_Router {

	/**
	 * cluster slug => [title, tabs => [module slug => [class, method]]].
	 * This order is the sidebar order and the in-cluster tab order.
	 */
	private static function clusters() {
		return array(
			'overview' => array(
				'title' => 'Logs',
				'tabs'  => array(
					'event-log'    => array( 'Thessley_Module_Event_Log', 'render_page' ),
					'geo-map'      => array( 'Thessley_Module_Geo_Map', 'render_page' ),
					'activity-log' => array( 'Thessley_Module_Activity_Log', 'render_page' ),
					'bot-log'      => array( 'Thessley_Module_Bot_Log', 'render_page' ),
				),
			),
			'perimeter' => array(
				'title' => 'Perimeter',
				'tabs'  => array(
					'ip-blocklist' => array( 'Thessley_Module_IP_Blocklist', 'render_settings_page' ),
				'whitelist'    => array( 'Thessley_Module_Whitelist', 'render_page' ),
					'geo-blocker'  => array( 'Thessley_Module_Geo_Blocker', 'render_page' ),
					'geo-login'    => array( 'Thessley_Module_Geo_Login', 'render_page' ),
					'rate-limiter' => array( 'Thessley_Module_Rate_Limiter', 'render_page' ),
				),
			),
			'inspection' => array(
				'title' => 'Inspection',
				'tabs'  => array(
					'query-guard' => array( 'Thessley_Module_Query_Guard', 'render_settings_page' ),
					'login-guard' => array( 'Thessley_Module_Login_Guard', 'render_settings_page' ),
				),
			),
			'detection' => array(
				'title' => 'Detection',
				'tabs'  => array(
					'file-integrity'  => array( 'Thessley_Module_File_Integrity', 'render_page' ),
					'malware-scanner' => array( 'Thessley_Module_Malware_Scanner', 'render_page' ),
					'vuln-scanner'    => array( 'Thessley_Module_Vuln_Scanner', 'render_page' ),
					'user-watchdog'   => array( 'Thessley_Module_User_Watchdog', 'render_page' ),
				),
			),
			'hardening' => array(
				'title' => 'Hardening',
				'tabs'  => array(
					'headers'   => array( 'Thessley_Module_Headers', 'render_settings_page' ),
					'user-enum' => array( 'Thessley_Module_User_Enum', 'render_settings_page' ),
					'hardening' => array( 'Thessley_Module_Hardening', 'render_page' ),
				),
			),
			'ops' => array(
				'title' => 'Other',
				'tabs'  => array(
					'auto-update'     => array( 'Thessley_Module_Auto_Update', 'render_settings_page' ),
					'alerts'          => array( 'Thessley_Module_Alerts', 'render_page' ),
				'ip-sharing'      => array( 'Thessley_Module_IP_Sharing', 'render_page' ),
				'scan-all'        => array( 'Thessley_Module_Scan_All', 'render_page' ),
				'config-io'       => array( 'Thessley_Module_Config_IO', 'render_page' ),
				),
			),
		);
	}

	/** Tab-label badge, e.g. User Watchdog's pending-alert count. Cheap to check; only real state reads happen for tabs that need one. */
	private static function badge( $module_slug ) {
		if ( 'user-watchdog' === $module_slug ) {
			$n = count( (array) get_option( 'thessley_user_watchdog_alerts', array() ) );
			return $n ? sprintf( '<span class="awaiting-mod"><span class="pending-count">%d</span></span>', $n ) : '';
		}
		return '';
	}

	public static function register() {
		// Priority 6: after the top-level page itself (registered at 5),
		// so 'wp-thessley' already exists as a parent when these attach to it.
		add_action( 'admin_menu', array( __CLASS__, 'admin_menu' ), 6 );
	}

	public static function admin_menu() {
		foreach ( self::clusters() as $slug => $cluster ) {
			add_submenu_page(
				'wp-thessley',
				$cluster['title'],
				$cluster['title'],
				'manage_options',
				'wp-thessley-' . $slug,
				function () use ( $slug ) {
					self::render( $slug );
				}
			);
		}
	}

	/** @return array<string,string> module slug => cluster slug */
	private static function module_cluster_map() {
		static $map = null;
		if ( null !== $map ) {
			return $map;
		}
		$map = array();
		foreach ( self::clusters() as $cluster_slug => $cluster ) {
			foreach ( array_keys( $cluster['tabs'] ) as $module_slug ) {
				$map[ $module_slug ] = $cluster_slug;
			}
		}
		return $map;
	}

	/**
	 * Query-string suffix (no leading "admin.php?") for linking directly to
	 * a specific module's tab from elsewhere — dashboard cards, cross-module
	 * deep links, alert text.
	 */
	public static function query( $module_slug, array $extra = array() ) {
		$cluster = self::module_cluster_map()[ $module_slug ] ?? $module_slug;
		$args    = array_merge( array( 'page' => 'wp-thessley-' . $cluster, 'tab' => $module_slug ), $extra );
		return http_build_query( $args );
	}

	public static function url( $module_slug, array $extra = array() ) {
		return admin_url( 'admin.php?' . self::query( $module_slug, $extra ) );
	}

	public static function render( $cluster_slug ) {
		$cluster = self::clusters()[ $cluster_slug ] ?? null;
		if ( ! $cluster ) {
			return;
		}

		$tabs = $cluster['tabs'];
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only tab navigation, not a state-changing action; nonce-gating it would break plain bookmarked/shared tab links for no security benefit.
		$requested_tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : '';
		$tab           = isset( $tabs[ $requested_tab ] ) ? $requested_tab : array_key_first( $tabs );

		Thessley_UI::styles();
		?>
		<div class="wrap">
			<h2 class="nav-tab-wrapper thessley-tabs">
				<?php foreach ( $tabs as $mod_slug => $cb ) : ?>
					<?php list( $icon, $title ) = Thessley_UI::meta( $mod_slug ); ?>
					<a href="<?php echo esc_url( self::url( $mod_slug ) ); ?>"
						class="nav-tab <?php echo $mod_slug === $tab ? 'nav-tab-active' : ''; ?>">
						<span class="dashicons dashicons-<?php echo esc_attr( $icon ); ?>" style="font-size:16px;vertical-align:text-bottom;margin-right:4px"></span>
						<?php echo esc_html( $title ); ?>
						<?php echo wp_kses_post( self::badge( $mod_slug ) ); ?>
					</a>
				<?php endforeach; ?>
			</h2>
		</div>
		<?php
		list( $class, $method ) = $tabs[ $tab ];
		if ( class_exists( $class ) && method_exists( $class, $method ) ) {
			call_user_func( array( $class, $method ) );
		}
	}
}
