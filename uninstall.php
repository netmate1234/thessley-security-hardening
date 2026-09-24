<?php
/**
 * Removes the data this plugin keeps outside the database when it is
 * deleted from the Plugins screen: the compiled datasets folder in uploads.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

$thessley_dir = get_option( 'thessley_data_dir', '' );
if ( is_string( $thessley_dir ) && '' !== $thessley_dir && 'thessley-security-hardening' === basename( $thessley_dir ) && is_dir( $thessley_dir ) ) {
	require_once ABSPATH . 'wp-admin/includes/file.php';
	if ( WP_Filesystem() ) {
		global $wp_filesystem;
		$wp_filesystem->delete( $thessley_dir, true );
	}
}

delete_option( 'thessley_data_dir' );
delete_option( 'thessley_plugin_folder' );
delete_option( 'thessley_active_checks' );
delete_option( 'thessley_data_moved' );
