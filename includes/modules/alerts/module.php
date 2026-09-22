<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Real-time notification (Telegram and/or email) for high-severity events.
 *
 * The actual send calls (thessley_maybe_telegram_alert(),
 * thessley_maybe_email_alert()) live in the mu-loader, not here — they have
 * to run inline inside thessley_log_event() itself, because a real block
 * calls wp_die() immediately afterwards at mu-plugin time, before regular
 * plugins (this module included) have even loaded. This module is just the
 * admin UI and settings around that.
 */
class Thessley_Module_Alerts {

	const API = 'https://api.telegram.org/bot';

	public static function activate() {}
	public static function deactivate() {}

	public static function register() {
		add_action( 'admin_post_thessley_alerts_save_settings', array( __CLASS__, 'handle_save_settings' ) );
		add_action( 'admin_post_thessley_tg_test', array( __CLASS__, 'handle_tg_test' ) );
		add_action( 'admin_post_thessley_tg_detect_chat', array( __CLASS__, 'handle_detect_chat' ) );
		add_action( 'admin_post_thessley_email_test', array( __CLASS__, 'handle_email_test' ) );

		return __CLASS__;
	}

	private static function api_call( $token, $method, $args = array() ) {
		$response = wp_remote_post(
			self::API . rawurlencode( $token ) . '/' . $method,
			array( 'timeout' => 10, 'body' => $args )
		);

		if ( is_wp_error( $response ) ) {
			return array( 'ok' => false, 'error' => $response->get_error_message() );
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( empty( $body['ok'] ) ) {
			return array( 'ok' => false, 'error' => $body['description'] ?? 'Unknown Telegram API error' );
		}

		return array( 'ok' => true, 'result' => $body['result'] );
	}

	public static function handle_save_settings() {
		check_admin_referer( 'thessley_alerts_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		update_option( 'thessley_telegram_enabled', isset( $_POST['tg_enabled'] ) );

		$token = isset( $_POST['bot_token'] ) ? sanitize_text_field( wp_unslash( $_POST['bot_token'] ) ) : '';
		update_option( 'thessley_telegram_bot_token', $token );

		$chat_id = isset( $_POST['chat_id'] ) ? sanitize_text_field( wp_unslash( $_POST['chat_id'] ) ) : '';
		update_option( 'thessley_telegram_chat_id', $chat_id );

		$tg_threshold = isset( $_POST['tg_threshold'] ) ? max( 1, min( 20, (int) $_POST['tg_threshold'] ) ) : 15;
		update_option( 'thessley_telegram_threshold', $tg_threshold );

		update_option( 'thessley_email_enabled', isset( $_POST['email_enabled'] ) );

		$address = isset( $_POST['email_address'] ) ? sanitize_email( wp_unslash( $_POST['email_address'] ) ) : '';
		update_option( 'thessley_email_address', ( '' !== $address && is_email( $address ) ) ? $address : '' );

		$email_threshold = isset( $_POST['email_threshold'] ) ? max( 1, min( 20, (int) $_POST['email_threshold'] ) ) : 15;
		update_option( 'thessley_email_threshold', $email_threshold );

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function handle_tg_test() {
		check_admin_referer( 'thessley_tg_test' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		$token   = trim( (string) get_option( 'thessley_telegram_bot_token', '' ) );
		$chat_id = trim( (string) get_option( 'thessley_telegram_chat_id', '' ) );

		if ( '' === $token || '' === $chat_id ) {
			wp_safe_redirect( add_query_arg( 'tg_test', 'missing', wp_get_referer() ) );
			exit;
		}

		$site   = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );
		$host   = wp_parse_url( get_option( 'siteurl' ), PHP_URL_HOST ) ?: '';
		$result = self::api_call(
			$token,
			'sendMessage',
			array(
				'chat_id'    => $chat_id,
				'parse_mode' => 'HTML',
				'text'       => sprintf(
					"<b>%s</b>%s\nThessley Security Hardening test message — if you can read this, Telegram alerts are wired up correctly.",
					esc_html( $site ),
					$host ? ' (' . esc_html( $host ) . ')' : ''
				),
			)
		);

		wp_safe_redirect( add_query_arg( 'tg_test', $result['ok'] ? 'ok' : rawurlencode( 'fail:' . $result['error'] ), wp_get_referer() ) );
		exit;
	}

	/**
	 * Reads the bot's recent updates and pulls the chat id from whoever
	 * most recently messaged it — saves the admin from finding their
	 * numeric Telegram chat id by hand.
	 */
	public static function handle_detect_chat() {
		check_admin_referer( 'thessley_tg_detect_chat' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		$token = trim( (string) get_option( 'thessley_telegram_bot_token', '' ) );
		if ( '' === $token ) {
			wp_safe_redirect( add_query_arg( 'detect', 'missing', wp_get_referer() ) );
			exit;
		}

		$result = self::api_call( $token, 'getUpdates' );
		if ( ! $result['ok'] || empty( $result['result'] ) ) {
			wp_safe_redirect( add_query_arg( 'detect', 'none', wp_get_referer() ) );
			exit;
		}

		$latest = end( $result['result'] );
		$chat   = $latest['message']['chat'] ?? $latest['message_reaction']['chat'] ?? null;

		if ( empty( $chat['id'] ) ) {
			wp_safe_redirect( add_query_arg( 'detect', 'none', wp_get_referer() ) );
			exit;
		}

		update_option( 'thessley_telegram_chat_id', (string) $chat['id'] );
		update_option( 'thessley_telegram_chat_name', $chat['username'] ?? $chat['first_name'] ?? '', false );

		wp_safe_redirect( add_query_arg( 'detect', 'ok', wp_get_referer() ) );
		exit;
	}

	public static function handle_email_test() {
		check_admin_referer( 'thessley_email_test' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		$address = trim( (string) get_option( 'thessley_email_address', '' ) ) ?: get_option( 'admin_email' );
		if ( '' === $address ) {
			wp_safe_redirect( add_query_arg( 'email_test', 'missing', wp_get_referer() ) );
			exit;
		}

		$site = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );
		$host = wp_parse_url( get_option( 'siteurl' ), PHP_URL_HOST ) ?: '';
		$sent = wp_mail(
			$address,
			sprintf( '[%s] Thessley Security Hardening test alert', $site ),
			sprintf( "%s%s\n\nThessley Security Hardening test message — if you can read this, email alerts are wired up correctly.", $site, $host ? " ({$host})" : '' )
		);

		wp_safe_redirect( add_query_arg( 'email_test', $sent ? 'ok' : 'fail', wp_get_referer() ) );
		exit;
	}

	public static function render_page() {
		$tg_enabled = get_option( 'thessley_telegram_enabled', false );
		$tg_token   = (string) get_option( 'thessley_telegram_bot_token', '' );
		$chat_id    = (string) get_option( 'thessley_telegram_chat_id', '' );
		$chat_name  = (string) get_option( 'thessley_telegram_chat_name', '' );
		$tg_thresh  = (int) get_option( 'thessley_telegram_threshold', 15 );

		$em_enabled = get_option( 'thessley_email_enabled', false );
		$em_address = (string) get_option( 'thessley_email_address', '' );
		$em_thresh  = (int) get_option( 'thessley_email_threshold', 15 );

		Thessley_UI::open( 'alerts' );

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only result flags set only by this module's own admin-post redirects (handle_save_settings/handle_tg_test/handle_detect_chat/handle_email_test), which already check_admin_referer() before redirecting; there is no state change here to protect.
		$saved      = isset( $_GET['saved'] );
		$tg_test    = isset( $_GET['tg_test'] ) ? sanitize_text_field( wp_unslash( $_GET['tg_test'] ) ) : '';
		$detect     = isset( $_GET['detect'] ) ? sanitize_text_field( wp_unslash( $_GET['detect'] ) ) : '';
		$email_test = isset( $_GET['email_test'] ) ? sanitize_text_field( wp_unslash( $_GET['email_test'] ) ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		if ( $saved ) {
			Thessley_UI::notice( 'success', 'Settings saved.' );
		}
		if ( '' !== $tg_test ) {
			if ( 'ok' === $tg_test ) {
				Thessley_UI::notice( 'success', 'Test message sent — check Telegram.' );
			} elseif ( 'missing' === $tg_test ) {
				Thessley_UI::notice( 'warning', 'Set a bot token and chat ID first.' );
			} else {
				Thessley_UI::notice( 'error', 'Telegram rejected the test message: ' . esc_html( str_replace( 'fail:', '', $tg_test ) ) );
			}
		}
		if ( '' !== $detect ) {
			if ( 'ok' === $detect ) {
				Thessley_UI::notice( 'success', 'Chat ID detected and saved.' );
			} elseif ( 'missing' === $detect ) {
				Thessley_UI::notice( 'warning', 'Set a bot token first.' );
			} else {
				Thessley_UI::notice( 'warning', 'No messages found. Send anything to your bot on Telegram, then try again.' );
			}
		}
		if ( '' !== $email_test ) {
			if ( 'ok' === $email_test ) {
				Thessley_UI::notice( 'success', 'Test email sent — check your inbox.' );
			} elseif ( 'missing' === $email_test ) {
				Thessley_UI::notice( 'warning', 'Set a recipient address first (or set a WordPress admin email).' );
			} else {
				Thessley_UI::notice( 'error', 'WordPress could not send the test email — check the site\'s mail configuration.' );
			}
		}

		Thessley_UI::tiles(
			array(
				array(
					'icon'  => $tg_enabled ? 'yes-alt' : 'warning',
					'tone'  => $tg_enabled ? 'good' : 'warn',
					'value' => $tg_enabled ? 'Enabled' : 'Disabled',
					'label' => 'Telegram',
				),
				array(
					'icon'  => $em_enabled ? 'yes-alt' : 'warning',
					'tone'  => $em_enabled ? 'good' : 'warn',
					'value' => $em_enabled ? 'Enabled' : 'Disabled',
					'label' => 'Email',
				),
				array(
					'icon'  => $chat_id ? 'yes-alt' : 'warning',
					'tone'  => $chat_id ? 'good' : 'warn',
					'value' => $chat_id ? 'Set' : 'Not set',
					'label' => $chat_name ? 'chat: ' . $chat_name : 'Telegram chat ID',
				),
			)
		);

		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'thessley_alerts_save_settings' ); ?>
			<input type="hidden" name="action" value="thessley_alerts_save_settings">

			<?php Thessley_UI::section( 'Telegram', 'testimonial' ); ?>
				<?php
				Thessley_UI::row(
					'Enabled',
					function () use ( $tg_enabled ) {
						?>
						<label><input type="checkbox" name="tg_enabled" <?php checked( $tg_enabled ); ?>> Send a Telegram message when an event exceeds the threshold below</label>
						<?php
					}
				);

				Thessley_UI::row(
					'Bot token',
					function () use ( $tg_token ) {
						?>
						<input type="text" name="bot_token" value="<?php echo esc_attr( $tg_token ); ?>" style="width:100%;max-width:420px" autocomplete="off">
						<?php
					},
					'From <a href="https://t.me/BotFather" target="_blank" rel="noopener">@BotFather</a> on Telegram — message it <code>/newbot</code> to create one.'
				);

				Thessley_UI::row(
					'Chat ID',
					function () use ( $chat_id ) {
						?>
						<input type="text" name="chat_id" value="<?php echo esc_attr( $chat_id ); ?>" style="width:16em">
						<?php
					},
					'Send any message to your bot on Telegram first, then use "Detect chat ID" below rather than finding this number by hand.'
				);

				Thessley_UI::row(
					'Threshold',
					function () use ( $tg_thresh ) {
						?>
						Alert on events with severity greater than <input type="number" name="tg_threshold" value="<?php echo esc_attr( $tg_thresh ); ?>" min="1" max="20" style="width:5em">
						<?php
					},
					'18+ means something already happened (a core file changed, a rogue admin account); 14&ndash;17 is a serious exploitation attempt that was stopped. The Event Log records everything regardless of this setting — this only controls what interrupts you in real time.'
				);
				?>
			<?php Thessley_UI::section_end(); ?>

			<?php Thessley_UI::section( 'Email', 'email-alt' ); ?>
				<?php
				Thessley_UI::row(
					'Enabled',
					function () use ( $em_enabled ) {
						?>
						<label><input type="checkbox" name="email_enabled" <?php checked( $em_enabled ); ?>> Send an email when an event exceeds the threshold below</label>
						<?php
					}
				);

				Thessley_UI::row(
					'Recipient',
					function () use ( $em_address ) {
						?>
						<input type="email" name="email_address" value="<?php echo esc_attr( $em_address ); ?>" style="width:100%;max-width:420px" placeholder="<?php echo esc_attr( get_option( 'admin_email' ) ); ?>">
						<?php
					},
					'Leave blank to use this site\'s WordPress admin email. Sent via WordPress\'s own mail function — deliverability depends on the site\'s mail setup, same as any other WordPress notification.'
				);

				Thessley_UI::row(
					'Threshold',
					function () use ( $em_thresh ) {
						?>
						Alert on events with severity greater than <input type="number" name="email_threshold" value="<?php echo esc_attr( $em_thresh ); ?>" min="1" max="20" style="width:5em">
						<?php
					},
					'Independent from the Telegram threshold above — email is often the noisier channel to have around, so many sites set this higher and keep Telegram for everything.'
				);
				?>
			<?php Thessley_UI::section_end(); ?>

			<?php submit_button( 'Save settings' ); ?>
		</form>

		<div class="thessley-actions" style="margin-top:14px">
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'thessley_tg_detect_chat' ); ?>
				<input type="hidden" name="action" value="thessley_tg_detect_chat">
				<?php submit_button( 'Detect chat ID', 'secondary', 'submit', false ); ?>
			</form>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'thessley_tg_test' ); ?>
				<input type="hidden" name="action" value="thessley_tg_test">
				<?php submit_button( 'Send test message', 'secondary', 'submit', false ); ?>
			</form>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'thessley_email_test' ); ?>
				<input type="hidden" name="action" value="thessley_email_test">
				<?php submit_button( 'Send test email', 'secondary', 'submit', false ); ?>
			</form>
		</div>
		<?php
		Thessley_UI::close();
	}
}
