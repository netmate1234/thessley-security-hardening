<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * DB access for Passkey Login: enrolled devices (long-lived) and the
 * short-lived login/enroll handshake rows. Kept separate from module.php
 * so the REST/crypto/UI wiring there isn't tangled up with SQL.
 */
// This class is the plugin's data-access layer for its own two custom tables, so
// every method is a direct query by design, and none of it may be cached:
// handshake rows and device state are security decisions that must always be
// read fresh. What the sniffs below cannot see is that the only thing
// concatenated into a query is a table name built from $wpdb->prefix plus a
// fixed literal (passkeys_table()/requests_table()); every value that varies
// goes through $wpdb->prepare() placeholders or $wpdb->insert()/update()
// format arrays, and nothing here ever interpolates request data.
// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

class Thessley_Passkey_Store {

	const DB_VERSION = 2; // v2: thessley_passkeys.attestation_level

	public static function passkeys_table() {
		global $wpdb;
		return $wpdb->prefix . 'thessley_passkeys';
	}

	public static function requests_table() {
		global $wpdb;
		return $wpdb->prefix . 'thessley_passkey_requests';
	}

	public static function install_tables() {
		global $wpdb;

		$collate = $wpdb->get_charset_collate();

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		dbDelta(
			"CREATE TABLE {$wpdb->prefix}thessley_passkeys (
				id            bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				user_id       bigint(20) unsigned NOT NULL,
				credential_id varchar(64) NOT NULL,
				public_key    varchar(255) NOT NULL,
				algorithm     varchar(16) NOT NULL DEFAULT 'ES256',
				counter       bigint(20) unsigned NOT NULL DEFAULT 0,
				label         varchar(100) NOT NULL DEFAULT '',
				attestation_level varchar(16) NULL,
				created_at    datetime NOT NULL,
				last_used_at  datetime NULL,
				revoked_at    datetime NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY credential_id (credential_id),
				KEY user_id (user_id)
			) {$collate};"
		);

		dbDelta(
			"CREATE TABLE {$wpdb->prefix}thessley_passkey_requests (
				request_id        varchar(43) NOT NULL,
				type               varchar(10) NOT NULL,
				nonce              varchar(43) NOT NULL,
				status             varchar(10) NOT NULL DEFAULT 'pending',
				requester_user_id  bigint(20) unsigned NULL,
				approver_user_id   bigint(20) unsigned NULL,
				credential_id      bigint(20) unsigned NULL,
				ip                 varchar(45) NOT NULL DEFAULT '',
				created_at         datetime NOT NULL,
				expires_at         datetime NOT NULL,
				approved_at        datetime NULL,
				PRIMARY KEY  (request_id),
				KEY status_expires (status, expires_at),
				KEY requester_user_id (requester_user_id)
			) {$collate};"
		);

		update_option( 'thessley_passkey_db_version', self::DB_VERSION, false );
	}

	public static function maybe_upgrade() {
		if ( (int) get_option( 'thessley_passkey_db_version', 0 ) !== self::DB_VERSION ) {
			self::install_tables();
		}
	}

	// --- Requests (login/enroll handshakes) ---------------------------

	public static function create_request( $type, $requester_user_id, $ttl_seconds ) {
		global $wpdb;

		$request_id = self::random_token();
		$nonce      = self::random_token();
		$now        = current_time( 'mysql', true );
		$expires    = gmdate( 'Y-m-d H:i:s', time() + $ttl_seconds );
		$ip         = thessley_client_ip();

		$wpdb->insert(
			self::requests_table(),
			array(
				'request_id'        => $request_id,
				'type'              => $type,
				'nonce'             => $nonce,
				'status'            => 'pending',
				'requester_user_id' => $requester_user_id,
				'ip'                => $ip,
				'created_at'        => $now,
				'expires_at'        => $expires,
			),
			array( '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s' )
		);

		return array(
			'request_id' => $request_id,
			'nonce'      => $nonce,
			'ip'         => $ip,
			'expires_in' => $ttl_seconds,
		);
	}

	public static function get_request( $request_id ) {
		global $wpdb;

		return $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM " . self::requests_table() . " WHERE request_id = %s",
				$request_id
			)
		);
	}

	/** Marks a pending, unexpired request resolved. Returns false if it was already resolved/expired (prevents replay). */
	public static function resolve_request( $request_id, $status, $approver_user_id = null, $credential_id = null ) {
		global $wpdb;

		$now  = current_time( 'mysql', true );
		$data = array(
			'status'      => $status,
			'approved_at' => $now,
		);
		$fmt = array( '%s', '%s' );

		if ( null !== $approver_user_id ) {
			$data['approver_user_id'] = $approver_user_id;
			$fmt[]                    = '%d';
		}
		if ( null !== $credential_id ) {
			$data['credential_id'] = $credential_id;
			$fmt[]                 = '%d';
		}

		$updated = $wpdb->update(
			self::requests_table(),
			$data,
			array(
				'request_id' => $request_id,
				'status'     => 'pending',
			),
			$fmt,
			array( '%s', '%s' )
		);

		return (bool) $updated;
	}

	/** Consumes an approved request so its status can only ever be read once as "approved" (cookie-replay guard). */
	public static function consume_request( $request_id ) {
		global $wpdb;

		$wpdb->update(
			self::requests_table(),
			array( 'status' => 'consumed' ),
			array(
				'request_id' => $request_id,
				'status'     => 'approved',
			),
			array( '%s' ),
			array( '%s', '%s' )
		);
	}

	public static function prune_expired_requests() {
		global $wpdb;

		$wpdb->query(
			'DELETE FROM ' . self::requests_table() . ' WHERE expires_at < UTC_TIMESTAMP() OR (status != "pending" AND created_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 DAY))'
		);
	}

	// --- Passkeys (enrolled devices) -----------------------------------

	public static function add_passkey( $user_id, $public_key, $algorithm, $label ) {
		global $wpdb;

		$credential_id = self::random_token();

		$wpdb->insert(
			self::passkeys_table(),
			array(
				'user_id'       => $user_id,
				'credential_id' => $credential_id,
				'public_key'    => $public_key,
				'algorithm'     => $algorithm ? $algorithm : 'ES256',
				'counter'       => 0,
				'label'         => substr( (string) $label, 0, 100 ),
				'created_at'    => current_time( 'mysql', true ),
			),
			array( '%s', '%s', '%s', '%s', '%d', '%s', '%s' )
		);

		return $credential_id;
	}

	/** $level is one of 'software'|'tee'|'strongbox'|null (null = device submitted no attestation chain, or verification itself failed to even parse it — distinct from a confirmed 'software' result). */
	public static function set_attestation_level( $row_id, $level ) {
		global $wpdb;

		$wpdb->update(
			self::passkeys_table(),
			array( 'attestation_level' => $level ),
			array( 'id' => $row_id ),
			array( '%s' ),
			array( '%d' )
		);
	}

	public static function get_passkey_by_credential( $credential_id ) {
		global $wpdb;

		return $wpdb->get_row(
			$wpdb->prepare(
				'SELECT * FROM ' . self::passkeys_table() . ' WHERE credential_id = %s AND revoked_at IS NULL',
				$credential_id
			)
		);
	}

	/** $request->credential_id stores the passkeys.id row id, not the credential_id string — this resolves one to the other (for display). */
	public static function get_credential_string_for_row( $row_id ) {
		global $wpdb;

		return $wpdb->get_var(
			$wpdb->prepare(
				'SELECT credential_id FROM ' . self::passkeys_table() . ' WHERE id = %d',
				$row_id
			)
		);
	}

	public static function get_passkey_row_id( $credential_id ) {
		global $wpdb;

		return (int) $wpdb->get_var(
			$wpdb->prepare(
				'SELECT id FROM ' . self::passkeys_table() . ' WHERE credential_id = %s',
				$credential_id
			)
		);
	}

	/** A user's devices, most recently used first; devices never used come last, newest first. */
	public static function devices_for_user( $user_id ) {
		global $wpdb;

		return $wpdb->get_results(
			$wpdb->prepare(
				'SELECT id, credential_id, label, attestation_level, created_at, last_used_at, revoked_at FROM ' . self::passkeys_table() . ' WHERE user_id = %d ORDER BY (last_used_at IS NULL), last_used_at DESC, created_at DESC, id DESC',
				$user_id
			)
		);
	}

	public static function bump_counter_and_touch( $id, $new_counter ) {
		global $wpdb;

		$wpdb->update(
			self::passkeys_table(),
			array(
				'counter'      => $new_counter,
				'last_used_at' => current_time( 'mysql', true ),
			),
			array( 'id' => $id ),
			array( '%d', '%s' ),
			array( '%d' )
		);
	}

	public static function revoke( $id, $user_id ) {
		global $wpdb;

		// Scoped to $user_id so one user can never revoke another's device
		// via a guessed/incremented id.
		return (bool) $wpdb->update(
			self::passkeys_table(),
			array( 'revoked_at' => current_time( 'mysql', true ) ),
			array(
				'id'      => $id,
				'user_id' => $user_id,
			),
			array( '%s' ),
			array( '%d', '%d' )
		);
	}

	public static function random_token() {
		// 32 random bytes, base64url, no padding — matches the request_id/
		// nonce/credential_id length budget assumed by the varchar(43)/
		// varchar(64) column widths above.
		return rtrim( strtr( base64_encode( random_bytes( 32 ) ), '+/', '-_' ), '=' );
	}
}

// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
