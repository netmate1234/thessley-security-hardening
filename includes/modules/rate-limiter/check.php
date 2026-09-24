<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Required from this plugin's own folder by wp-thessley-early.php while this
// module is enabled.
//
// Fixed 60-second window per IP, via transient. This only ever sees
// requests that reach PHP at all — the same fact that limits sensitive-path
// probe detection elsewhere works in this module's favour: Apache serves a
// page's actual static assets (CSS/JS/images) directly without invoking
// PHP, so a normal page load's burst of sub-resource fetches never counts
// against this limiter. Only genuine WordPress-processed hits do.

thessley_register_check(
	function () {
		if ( ! get_option( 'thessley_ratelimit_enabled', true ) ) {
			return null;
		}

		$ip = thessley_client_ip();
		if ( '' === $ip || thessley_ip_is_exempt( $ip ) ) {
			return null;
		}

		$limit  = max( 10, (int) get_option( 'thessley_ratelimit_per_minute', 300 ) );
		$window = (int) floor( time() / 60 );
		$key    = 'thessley_rl_' . md5( $ip ) . '_' . $window;

		$count = get_transient( $key );
		$count = ( false === $count ) ? 1 : $count + 1;
		set_transient( $key, $count, 90 );

		if ( $count <= $limit ) {
			return null;
		}

		$enforce = get_option( 'thessley_ratelimit_mode', 'log' );

		// Log only the request that first crosses the threshold in this
		// window, not every one after it — a real flood can be thousands of
		// requests, and the event log recording "still over the limit" that
		// many times would drown out everything else in it.
		if ( $limit + 1 === $count ) {
			$action = ( 'block' === $enforce ) ? 'blocked' : 'logged';
			thessley_log_event( 'rate-limiter', 'over_limit', $action, "{$count} requests this minute, limit {$limit}", 10 );

			if ( get_option( 'thessley_ratelimit_escalate', true ) ) {
				$viol_key = 'thessley_rl_viol_' . md5( $ip );
				$viol     = (int) get_transient( $viol_key );
				$viol++;
				set_transient( $viol_key, $viol, 150 ); // spans ~2 windows: lapses if the next minute is clean

				$after = max( 1, (int) get_option( 'thessley_ratelimit_escalate_after', 3 ) );
				if ( $viol >= $after ) {
					$minutes = max( 1, (int) get_option( 'thessley_ratelimit_escalate_minutes', 30 ) );
					thessley_local_blocklist_add( $ip, 'rate-limiter: sustained flood', $minutes * MINUTE_IN_SECONDS );
					delete_transient( $viol_key );
				}
			}
		}

		if ( 'block' !== $enforce ) {
			return null;
		}

		return array( 'reason' => 'Too many requests.' );
	}
);
