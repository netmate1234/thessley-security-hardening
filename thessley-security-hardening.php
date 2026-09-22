<?php
/**
 * Plugin Name: Thessley Security Hardening
 * Description: General security hardening plugin. Modular — each feature lives under includes/modules.
 * Version: 1.0.14
 * Author: Martin Lundstrom
 * Text Domain: thessley-security-hardening
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'THESSLEY_VERSION', '1.0.14' );
define( 'THESSLEY_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'THESSLEY_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'THESSLEY_MU_SOURCE', THESSLEY_PLUGIN_DIR . 'mu-loader/wp-thessley-early.php' );
define( 'THESSLEY_MU_DEST', WPMU_PLUGIN_DIR . '/wp-thessley-early.php' );
define( 'THESSLEY_CHECKS_DIR', WPMU_PLUGIN_DIR . '/wp-thessley-checks' );

require_once THESSLEY_PLUGIN_DIR . 'includes/class-ui.php';
require_once THESSLEY_PLUGIN_DIR . 'includes/class-module-loader.php';
require_once THESSLEY_PLUGIN_DIR . 'includes/class-menu-router.php';

register_activation_hook( __FILE__, array( 'Thessley_Module_Loader', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'Thessley_Module_Loader', 'deactivate' ) );

add_action( 'plugins_loaded', array( 'Thessley_Module_Loader', 'init' ) );
