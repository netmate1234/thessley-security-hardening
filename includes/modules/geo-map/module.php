<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Read-only visualization, not a gate: no check.php, nothing runs on the
 * request path. Aggregates the shared events table by country and tints
 * an embedded world map accordingly.
 *
 * Country resolution reuses geo-blocker's compiled binary index and
 * names map (thessley_geo_lookup() / thessley_geo_country_label(), both
 * defined by geo-blocker's check.php once that module has been active at
 * least once) rather than adding a third geo dataset. If geo-blocker has
 * never run, this page just has nothing to color — it degrades to an
 * empty map, not an error.
 */
class Thessley_Module_Geo_Map {

	/** 5-step red intensity scale — light for a handful of hits, deep red for the worst offenders. */
	const BUCKET_COLORS = array( '#ffe3e0', '#ffab9e', '#f96f5c', '#dc2f2f', '#7a0c14' );

	public static function activate() {}
	public static function deactivate() {}

	public static function register() {
		return __CLASS__;
	}


	/**
	 * @return array<string,int> ISO 3166-1 alpha-2 code (uppercase) => event count
	 */
	public static function counts_by_country( $days ) {
		global $wpdb;

		$table = thessley_events_table();

		// Aggregate by IP first — far fewer unique IPs than raw events, so
		// country resolution (a binary search per IP) stays cheap even on a
		// busy site. The 2000-IP cap is a safety valve, not a real-world
		// ceiling: that many distinct attacking IPs in one window is already
		// an extreme outlier worth its own investigation, not a map.
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table name only, built from $wpdb->prefix, no user input; the actual value ($days) is bound via the %d placeholder below.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ip, COUNT(*) c FROM {$table}
				 WHERE action IN ('blocked','logged') AND created_at > DATE_SUB(NOW(), INTERVAL %d DAY)
				 GROUP BY ip ORDER BY c DESC LIMIT 2000",
				$days
			),
			ARRAY_A
		) ?: array();
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$by_country = array();
		$geo_ready  = function_exists( 'thessley_geo_lookup' ) && function_exists( 'thessley_geo_country_label' );
		$file       = function_exists( 'thessley_data_file' ) ? thessley_data_file( 'geo-country-index.bin' ) : '';

		foreach ( $rows as $row ) {
			if ( ! $geo_ready || thessley_ip_is_reserved( $row['ip'] ) ) {
				continue;
			}
			$long = ip2long( $row['ip'] );
			if ( false === $long ) {
				continue;
			}
			$idx = thessley_geo_lookup( $file, $long );
			if ( null === $idx ) {
				continue;
			}
			$label = thessley_geo_country_label( $idx );
			if ( ! preg_match( '/\(([A-Z]{2})\)$/', $label, $m ) ) {
				continue; // "index N" fallback — dataset missing, nothing to plot
			}
			$code                = $m[1];
			$by_country[ $code ] = ( $by_country[ $code ] ?? 0 ) + (int) $row['c'];
		}

		return $by_country;
	}

	/** Injects a class + data attributes into every <path id="xx" .../> that has data. */
	private static function tint_svg( $svg, array $by_country ) {
		if ( empty( $by_country ) ) {
			return $svg;
		}

		$max     = max( $by_country );
		$log_max = log( $max + 1 );
		$codes   = Thessley_Geo_Country_Codes::all();

		foreach ( $by_country as $code => $count ) {
			$name   = $codes[ $code ] ?? $code;
			$bucket = $log_max > 0 ? min( 4, (int) floor( ( log( $count + 1 ) / $log_max ) * 5 ) ) : 0;
			$id     = strtolower( $code );

			$replacement = sprintf(
				'id="%s" class="thessley-geo-hit thessley-geo-b%d" data-country="%s" data-count="%d"',
				esc_attr( $id ),
				$bucket,
				esc_attr( $name ),
				$count
			);
			$svg = preg_replace_callback(
				'/id="' . preg_quote( $id, '/' ) . '"/',
				function () use ( $replacement ) {
					return $replacement;
				},
				$svg
			);
		}

		return $svg;
	}

	public static function render_page() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only day-range selector for this map view, not a state-changing action.
		$days       = isset( $_GET['days'] ) ? max( 1, (int) $_GET['days'] ) : 7;
		$by_country = self::counts_by_country( $days );
		$svg_path   = __DIR__ . '/assets/world-map.svg';
		$svg        = is_readable( $svg_path ) ? file_get_contents( $svg_path ) : '';
		$svg        = self::tint_svg( $svg, $by_country );

		arsort( $by_country );
		$codes = Thessley_Geo_Country_Codes::all();

		Thessley_UI::open( 'geo-map' );

		Thessley_UI::tiles(
			array(
				array( 'icon' => 'admin-site-alt3', 'tone' => 'quiet', 'value' => number_format_i18n( count( $by_country ) ), 'label' => 'countries seen' ),
				array( 'icon' => 'clock', 'tone' => 'quiet', 'value' => sprintf( 'last %d day(s)', $days ), 'label' => 'window' ),
			)
		);

		?>
		<form method="get" style="margin-bottom:14px">
			<?php wp_parse_str( Thessley_Menu_Router::query( 'geo-map' ), $route ); ?>
			<?php foreach ( $route as $k => $v ) : ?>
				<input type="hidden" name="<?php echo esc_attr( $k ); ?>" value="<?php echo esc_attr( $v ); ?>">
			<?php endforeach; ?>
			<label>Window:
				<select name="days" onchange="this.form.submit()">
					<?php foreach ( array( 1 => '24 hours', 7 => '7 days', 30 => '30 days', 90 => '90 days' ) as $val => $label ) : ?>
						<option value="<?php echo esc_attr( $val ); ?>" <?php selected( $days, $val ); ?>><?php echo esc_html( $label ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
		</form>

		<?php Thessley_UI::section( 'Activity by country', 'admin-site-alt3' ); ?>
			<?php if ( empty( $by_country ) ) : ?>
				<div class="thessley-empty"><span class="dashicons dashicons-info-outline"></span><p>No blocked or logged events with a resolvable country in this window.</p></div>
			<?php else : ?>
				<div class="thessley-geo-map-wrap"><?php
				// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $svg is this plugin's own bundled, static asset file (assets/world-map.svg); the only dynamic pieces spliced in (tint_svg() above) are esc_attr()'d, and the country codes/counts driving them come from the compiled GeoIP dataset, never from request input.
				echo $svg;
				?></div>
				<div id="thessley-geo-tip" class="thessley-geo-tip"></div>
			<?php endif; ?>
		<?php Thessley_UI::section_end(); ?>

		<?php if ( ! empty( $by_country ) ) : ?>
			<?php Thessley_UI::section( 'Top countries', 'list-view' ); ?>
				<div class="thessley-table-scroll">
				<table class="thessley-table">
					<thead><tr><th>Country</th><th style="width:120px">Events</th><th>Share</th></tr></thead>
					<tbody>
					<?php $top = array_slice( $by_country, 0, 15, true ); ?>
					<?php $max = max( $by_country ); ?>
					<?php foreach ( $top as $code => $count ) : ?>
						<tr>
							<td><?php echo esc_html( ( $codes[ $code ] ?? $code ) . " ({$code})" ); ?></td>
							<td><?php echo esc_html( number_format_i18n( $count ) ); ?></td>
							<td style="width:200px">
								<div style="background:#f0f0f1;border-radius:3px;overflow:hidden;height:8px">
									<div style="background:#3d84d6;height:8px;width:<?php echo esc_attr( max( 4, (int) round( ( $count / $max ) * 100 ) ) ); ?>%"></div>
								</div>
							</td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
				</div>
			<?php Thessley_UI::section_end(); ?>
		<?php endif; ?>

		<p class="thessley-help">Country resolution reuses the Geo Blocker module's dataset (DB-IP Country Lite, CC BY 4.0) — enable that module at least once for this map to have data. Map graphic: <a href="https://github.com/flekschas/simple-world-map" target="_blank" rel="noopener">flekschas/simple-world-map</a>, CC BY-SA 3.0.</p>

		<?php
		// Styling (assets/geo-map.css, enqueued by Thessley_Module_Loader::
		// enqueue_assets()) hardcodes BUCKET_COLORS' 5 values directly —
		// keep the two in sync if BUCKET_COLORS above is ever changed.
		wp_register_script( 'thessley-geo-map', false, array(), THESSLEY_VERSION, true );
		wp_enqueue_script( 'thessley-geo-map' );
		wp_add_inline_script(
			'thessley-geo-map',
			"(function () {
				var wrap = document.querySelector( '.thessley-geo-map-wrap' );
				var tip  = document.getElementById( 'thessley-geo-tip' );
				if ( ! wrap || ! tip ) { return; }
				wrap.addEventListener( 'mousemove', function ( e ) {
					var el = e.target.closest ? e.target.closest( '.thessley-geo-hit' ) : null;
					if ( ! el ) { tip.style.display = 'none'; return; }
					tip.textContent = el.getAttribute( 'data-country' ) + ': ' + el.getAttribute( 'data-count' ) + ' event(s)';
					tip.style.left = ( e.clientX + 14 ) + 'px';
					tip.style.top  = ( e.clientY + 14 ) + 'px';
					tip.style.display = 'block';
				} );
				wrap.addEventListener( 'mouseleave', function () { tip.style.display = 'none'; } );
			})();"
		);
		Thessley_UI::close();
	}
}
