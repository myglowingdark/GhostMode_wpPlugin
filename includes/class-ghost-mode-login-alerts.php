<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Email alerts when a user logs in from a new / unknown IP.
 */
class Ghost_Mode_Login_Alerts {

	const KNOWN_IPS_META = 'ghost_mode_known_ips';

	public function __construct() {
		add_action( 'wp_login', array( $this, 'maybe_alert' ), 30, 2 );
	}

	/**
	 * Whether new-IP alerts are enabled.
	 */
	public static function is_enabled() {
		$settings = ghost_mode_get_settings();
		return ( $settings['login_alert_enabled'] ?? 'yes' ) === 'yes';
	}

	/**
	 * @param string  $user_login Username.
	 * @param WP_User $user       User.
	 */
	public function maybe_alert( $user_login, $user ) {
		if ( ! self::is_enabled() || ! ( $user instanceof WP_User ) ) {
			return;
		}

		$ip = Ghost_Mode_Lockout::get_client_ip();
		if ( $ip === '' || $ip === '0.0.0.0' ) {
			return;
		}

		$known = self::get_known_ips( (int) $user->ID );

		// First time we see this user: seed known IPs (no alert).
		if ( empty( $known ) ) {
			$known = self::seed_from_session_log( (int) $user->ID );
			$known[] = $ip;
			$known   = array_values( array_unique( array_filter( $known ) ) );
			self::save_known_ips( (int) $user->ID, $known );
			return;
		}

		if ( in_array( $ip, $known, true ) ) {
			return;
		}

		// New IP — notify, then remember it.
		self::send_alert( $user, $user_login, $ip );
		$known[] = $ip;
		self::save_known_ips( (int) $user->ID, $known );
	}

	/**
	 * @param int $user_id User ID.
	 * @return string[]
	 */
	public static function get_known_ips( $user_id ) {
		$ips = get_user_meta( $user_id, self::KNOWN_IPS_META, true );
		if ( ! is_array( $ips ) ) {
			return array();
		}
		$clean = array();
		foreach ( $ips as $ip ) {
			$ip = trim( (string) $ip );
			if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				$clean[] = $ip;
			}
		}
		return array_values( array_unique( $clean ) );
	}

	/**
	 * @param int      $user_id User ID.
	 * @param string[] $ips     IPs.
	 */
	public static function save_known_ips( $user_id, array $ips ) {
		$clean = array();
		foreach ( $ips as $ip ) {
			$ip = trim( (string) $ip );
			if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				$clean[] = $ip;
			}
		}
		// Cap stored IPs per user.
		$clean = array_slice( array_values( array_unique( $clean ) ), 0, 50 );
		update_user_meta( $user_id, self::KNOWN_IPS_META, $clean );
	}

	/**
	 * Prefill known IPs from existing session log so enabling alerts is not noisy.
	 *
	 * @param int $user_id User ID.
	 * @return string[]
	 */
	public static function seed_from_session_log( $user_id ) {
		if ( ! class_exists( 'Ghost_Mode_Sessions' ) ) {
			return array();
		}
		$ips = array();
		foreach ( Ghost_Mode_Sessions::get_log() as $row ) {
			if ( (int) ( $row['user_id'] ?? 0 ) !== (int) $user_id ) {
				continue;
			}
			$ip = trim( (string) ( $row['ip'] ?? '' ) );
			if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				$ips[] = $ip;
			}
		}
		return array_values( array_unique( $ips ) );
	}

	/**
	 * @param WP_User $user       User.
	 * @param string  $user_login Login name.
	 * @param string  $ip         New IP.
	 */
	public static function send_alert( WP_User $user, $user_login, $ip ) {
		$settings     = ghost_mode_get_settings();
		$notify_user  = ( $settings['login_alert_notify_user'] ?? 'yes' ) === 'yes';
		$notify_admin = ( $settings['login_alert_notify_admin'] ?? 'yes' ) === 'yes';

		$recipients = array();
		if ( $notify_user && is_email( $user->user_email ) ) {
			$recipients[] = $user->user_email;
		}
		if ( $notify_admin ) {
			$admin_email = get_option( 'admin_email' );
			if ( is_email( $admin_email ) ) {
				$recipients[] = $admin_email;
			}
		}

		$extra = isset( $settings['login_alert_extra_emails'] ) ? (string) $settings['login_alert_extra_emails'] : '';
		if ( $extra !== '' ) {
			foreach ( preg_split( '/[\s,;]+/', $extra ) as $email ) {
				$email = sanitize_email( $email );
				if ( is_email( $email ) ) {
					$recipients[] = $email;
				}
			}
		}

		$recipients = array_values( array_unique( array_filter( $recipients ) ) );
		if ( empty( $recipients ) ) {
			return false;
		}

		$site_name = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$time      = wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ) );
		$ua        = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$mac       = Ghost_Mode_Lockout::get_client_mac();
		$sessions  = ghost_mode_get_settings_url();

		$subject = sprintf(
			/* translators: 1: site name, 2: username */
			__( '[%1$s] New login from unknown IP — %2$s', 'ghost-mode' ),
			$site_name,
			$user_login
		);

		$lines = array(
			sprintf( __( 'A login was detected from a new IP address on %s.', 'ghost-mode' ), $site_name ),
			'',
			sprintf( __( 'User: %s', 'ghost-mode' ), $user_login ),
			sprintf( __( 'Email: %s', 'ghost-mode' ), $user->user_email ),
			sprintf( __( 'IP address: %s', 'ghost-mode' ), $ip ),
			sprintf( __( 'Time: %s', 'ghost-mode' ), $time ),
		);

		if ( $mac !== '' ) {
			$lines[] = sprintf( __( 'MAC: %s', 'ghost-mode' ), $mac );
		}
		if ( $ua !== '' ) {
			$lines[] = sprintf( __( 'Browser: %s', 'ghost-mode' ), $ua );
		}

		$lines[] = '';
		$lines[] = __( 'If this was you, no action is needed — this IP is now trusted for that account.', 'ghost-mode' );
		$lines[] = __( 'If this was not you, change the password immediately and review active sessions in Ghost Mode settings.', 'ghost-mode' );
		$lines[] = '';
		$lines[] = sprintf( __( 'Session log: %s', 'ghost-mode' ), $sessions );

		$body    = implode( "\n", $lines );
		$headers = array( 'Content-Type: text/plain; charset=UTF-8' );
		$sent    = false;

		foreach ( $recipients as $to ) {
			$result = wp_mail( $to, $subject, $body, $headers );
			if ( $result ) {
				$sent = true;
			}
		}

		/**
		 * Fires after a new-IP login alert is attempted.
		 *
		 * @param WP_User $user       User.
		 * @param string  $ip         IP address.
		 * @param string[] $recipients Emails.
		 * @param bool    $sent       Whether at least one mail succeeded.
		 */
		do_action( 'ghost_mode_new_login_alert', $user, $ip, $recipients, $sent );

		return $sent;
	}
}
