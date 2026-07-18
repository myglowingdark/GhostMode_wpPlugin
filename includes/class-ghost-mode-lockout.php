<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Failed-login lockouts by IP and device/MAC identifier.
 *
 * Note: Real MAC addresses are not available from browsers over HTTP.
 * When a reverse proxy/captive portal sends a MAC header we use it;
 * otherwise we use a stable device fingerprint from the User-Agent.
 */
class Ghost_Mode_Lockout {

	const ATTEMPTS_OPTION = 'ghost_mode_login_attempts';
	const BLOCKS_OPTION   = 'ghost_mode_login_blocks';
	const MAX_ATTEMPTS    = 5;

	public function __construct() {
		add_action( 'wp_login_failed', array( $this, 'on_wp_login_failed' ), 10, 2 );
		add_action( 'wp_login', array( $this, 'on_wp_login_success' ), 10, 2 );
		add_filter( 'authenticate', array( $this, 'block_authenticate' ), 30, 3 );

		add_action( 'admin_post_ghost_mode_unblock', array( $this, 'handle_unblock' ) );
		add_action( 'admin_post_ghost_mode_unblock_all', array( $this, 'handle_unblock_all' ) );
		add_action( 'admin_post_ghost_mode_clear_attempts', array( $this, 'handle_clear_attempts' ) );
	}

	/**
	 * Max failed attempts before lockout.
	 */
	public static function max_attempts() {
		$settings = ghost_mode_get_settings();
		$max      = isset( $settings['max_login_attempts'] ) ? absint( $settings['max_login_attempts'] ) : self::MAX_ATTEMPTS;
		return max( 1, min( 50, $max ? $max : self::MAX_ATTEMPTS ) );
	}

	/**
	 * Whether lockout protection is enabled.
	 */
	public static function is_enabled() {
		$settings = ghost_mode_get_settings();
		return ( $settings['lockout_enabled'] ?? 'yes' ) === 'yes';
	}

	/**
	 * Client IP (honours common proxy headers when trusted by the host).
	 */
	public static function get_client_ip() {
		$candidates = array();

		if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
			$candidates[] = wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		}
		if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$xff = (string) wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			$parts = array_map( 'trim', explode( ',', $xff ) );
			if ( ! empty( $parts[0] ) ) {
				$candidates[] = $parts[0];
			}
		}
		if ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
			$candidates[] = wp_unslash( $_SERVER['REMOTE_ADDR'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		}

		foreach ( $candidates as $ip ) {
			$ip = trim( (string) $ip );
			if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				return $ip;
			}
		}

		return '0.0.0.0';
	}

	/**
	 * MAC from proxy headers when present; otherwise empty.
	 */
	public static function get_client_mac() {
		$header_keys = array(
			'HTTP_X_CLIENT_MAC',
			'HTTP_X_MAC_ADDRESS',
			'HTTP_X_PHYSICAL_ADDRESS',
			'HTTP_MAC',
		);

		foreach ( $header_keys as $key ) {
			if ( empty( $_SERVER[ $key ] ) ) {
				continue;
			}
			$raw = strtoupper( trim( (string) wp_unslash( $_SERVER[ $key ] ) ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			$mac = self::normalize_mac( $raw );
			if ( $mac !== '' ) {
				return $mac;
			}
		}

		return '';
	}

	/**
	 * @param string $mac Raw MAC.
	 */
	public static function normalize_mac( $mac ) {
		$mac = strtoupper( preg_replace( '/[^0-9A-F]/', '', (string) $mac ) );
		if ( strlen( $mac ) !== 12 ) {
			return '';
		}
		return implode( ':', str_split( $mac, 2 ) );
	}

	/**
	 * Device fingerprint used when MAC is unavailable.
	 */
	public static function get_device_fingerprint() {
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$al = isset( $_SERVER['HTTP_ACCEPT_LANGUAGE'] ) ? (string) wp_unslash( $_SERVER['HTTP_ACCEPT_LANGUAGE'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		return substr( hash( 'sha256', $ua . '|' . $al . '|' . self::get_client_ip() ), 0, 16 );
	}

	/**
	 * Identifiers to track for the current request.
	 *
	 * @return array<int, array{type:string,value:string,label:string}>
	 */
	public static function get_request_identifiers() {
		$ids = array(
			array(
				'type'  => 'ip',
				'value' => self::get_client_ip(),
				'label' => self::get_client_ip(),
			),
		);

		$mac = self::get_client_mac();
		if ( $mac !== '' ) {
			$ids[] = array(
				'type'  => 'mac',
				'value' => $mac,
				'label' => $mac,
			);
		} else {
			$fp = self::get_device_fingerprint();
			$ids[] = array(
				'type'  => 'device',
				'value' => $fp,
				'label' => $fp,
			);
		}

		return $ids;
	}

	/**
	 * Storage key for an identifier.
	 *
	 * @param string $type  ip|mac|device
	 * @param string $value Value.
	 */
	public static function key( $type, $value ) {
		return sanitize_key( $type ) . ':' . md5( (string) $value );
	}

	/**
	 * @return array<string, array>
	 */
	public static function get_attempts() {
		$data = get_option( self::ATTEMPTS_OPTION, array() );
		return is_array( $data ) ? $data : array();
	}

	/**
	 * @return array<string, array>
	 */
	public static function get_blocks() {
		$data = get_option( self::BLOCKS_OPTION, array() );
		return is_array( $data ) ? $data : array();
	}

	/**
	 * Whether the current request is locked out.
	 */
	public static function is_request_blocked() {
		if ( ! self::is_enabled() ) {
			return false;
		}

		$blocks = self::get_blocks();
		foreach ( self::get_request_identifiers() as $id ) {
			$key = self::key( $id['type'], $id['value'] );
			if ( isset( $blocks[ $key ] ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Human message when blocked.
	 */
	public static function blocked_message() {
		return __( 'Too many failed login attempts. This IP/device has been blocked. Contact a site administrator to unblock access.', 'ghost-mode' );
	}

	/**
	 * Record a failed login for the current request identifiers.
	 *
	 * @param string $username Attempted username.
	 * @return bool True if a new block was created.
	 */
	public static function record_failure( $username = '' ) {
		if ( ! self::is_enabled() ) {
			return false;
		}

		$attempts = self::get_attempts();
		$blocks   = self::get_blocks();
		$now      = time();
		$max      = self::max_attempts();
		$blocked  = false;

		foreach ( self::get_request_identifiers() as $id ) {
			$key = self::key( $id['type'], $id['value'] );

			if ( isset( $blocks[ $key ] ) ) {
				$blocked = true;
				continue;
			}

			$prev = isset( $attempts[ $key ] ) && is_array( $attempts[ $key ] ) ? $attempts[ $key ] : array();
			$count = isset( $prev['count'] ) ? absint( $prev['count'] ) + 1 : 1;

			$attempts[ $key ] = array(
				'type'     => $id['type'],
				'value'    => $id['value'],
				'label'    => $id['label'],
				'count'    => $count,
				'first'    => isset( $prev['first'] ) ? absint( $prev['first'] ) : $now,
				'last'     => $now,
				'username' => sanitize_text_field( (string) $username ),
			);

			if ( $count >= $max ) {
				$blocks[ $key ] = array(
					'type'       => $id['type'],
					'value'      => $id['value'],
					'label'      => $id['label'],
					'blocked_at' => $now,
					'attempts'   => $count,
					'username'   => sanitize_text_field( (string) $username ),
					'ip'         => self::get_client_ip(),
					'mac'        => self::get_client_mac(),
				);
				unset( $attempts[ $key ] );
				$blocked = true;
			}
		}

		update_option( self::ATTEMPTS_OPTION, $attempts, false );
		update_option( self::BLOCKS_OPTION, $blocks, false );

		// Attempt review tracking is handled by Ghost_Mode_Attempt_Review::on_login_failed.

		return $blocked;
	}

	/**
	 * Manually block an IP / MAC / device value (e.g. from post-login review).
	 *
	 * @param string $type     ip|mac|device.
	 * @param string $value    Value to block.
	 * @param string $username Related username.
	 * @param string $reason   Reason key.
	 * @return bool True if a new or refreshed block was saved.
	 */
	public static function block_value( $type, $value, $username = '', $reason = 'manual' ) {
		$type  = sanitize_key( $type );
		$value = trim( (string) $value );
		if ( $type === '' || $value === '' ) {
			return false;
		}
		if ( $type === 'ip' && ! filter_var( $value, FILTER_VALIDATE_IP ) ) {
			return false;
		}
		if ( $type === 'mac' ) {
			$value = self::normalize_mac( $value );
			if ( $value === '' ) {
				return false;
			}
		}

		$key    = self::key( $type, $value );
		$blocks = self::get_blocks();
		$blocks[ $key ] = array(
			'type'       => $type,
			'value'      => $value,
			'label'      => $value,
			'blocked_at' => time(),
			'attempts'   => isset( $blocks[ $key ]['attempts'] ) ? absint( $blocks[ $key ]['attempts'] ) : self::max_attempts(),
			'username'   => sanitize_text_field( (string) $username ),
			'ip'         => ( $type === 'ip' ) ? $value : self::get_client_ip(),
			'mac'        => ( $type === 'mac' ) ? $value : self::get_client_mac(),
			'reason'     => sanitize_key( $reason ),
		);
		update_option( self::BLOCKS_OPTION, $blocks, false );

		// Clear in-progress attempts for this key.
		$attempts = self::get_attempts();
		if ( isset( $attempts[ $key ] ) ) {
			unset( $attempts[ $key ] );
			update_option( self::ATTEMPTS_OPTION, $attempts, false );
		}

		return true;
	}

	/**
	 * Clear attempt counters for the current request (on successful login).
	 */
	public static function clear_request_attempts() {
		$attempts = self::get_attempts();
		$changed  = false;

		foreach ( self::get_request_identifiers() as $id ) {
			$key = self::key( $id['type'], $id['value'] );
			if ( isset( $attempts[ $key ] ) ) {
				unset( $attempts[ $key ] );
				$changed = true;
			}
		}

		if ( $changed ) {
			update_option( self::ATTEMPTS_OPTION, $attempts, false );
		}
	}

	/**
	 * Remaining attempts before lockout for current request (min across identifiers).
	 */
	public static function remaining_attempts() {
		if ( ! self::is_enabled() || self::is_request_blocked() ) {
			return 0;
		}

		$max      = self::max_attempts();
		$attempts = self::get_attempts();
		$used     = 0;

		foreach ( self::get_request_identifiers() as $id ) {
			$key = self::key( $id['type'], $id['value'] );
			if ( isset( $attempts[ $key ]['count'] ) ) {
				$used = max( $used, absint( $attempts[ $key ]['count'] ) );
			}
		}

		return max( 0, $max - $used );
	}

	/**
	 * Unblock by storage key.
	 *
	 * @param string $key Block key.
	 */
	public static function unblock( $key ) {
		$key    = (string) $key;
		$blocks = self::get_blocks();
		if ( ! isset( $blocks[ $key ] ) ) {
			return false;
		}
		unset( $blocks[ $key ] );
		update_option( self::BLOCKS_OPTION, $blocks, false );

		$attempts = self::get_attempts();
		if ( isset( $attempts[ $key ] ) ) {
			unset( $attempts[ $key ] );
			update_option( self::ATTEMPTS_OPTION, $attempts, false );
		}

		return true;
	}

	public static function unblock_all() {
		update_option( self::BLOCKS_OPTION, array(), false );
		return true;
	}

	public static function clear_all_attempts() {
		update_option( self::ATTEMPTS_OPTION, array(), false );
		return true;
	}

	/**
	 * Block authentication early when locked out.
	 *
	 * @param WP_User|WP_Error|null $user     User.
	 * @param string                $username Username.
	 * @param string                $password Password.
	 * @return WP_User|WP_Error|null
	 */
	public function block_authenticate( $user, $username, $password ) {
		unset( $username, $password );
		if ( ! self::is_enabled() || ! self::is_request_blocked() ) {
			return $user;
		}
		return new WP_Error( 'ghost_mode_locked', self::blocked_message() );
	}

	/**
	 * @param string        $username Username.
	 * @param WP_Error|null $error    Error object (WP 5.1+).
	 */
	public function on_wp_login_failed( $username, $error = null ) {
		if ( $error instanceof WP_Error && $error->get_error_code() === 'ghost_mode_locked' ) {
			return;
		}
		self::record_failure( $username );
	}

	/**
	 * @param string  $user_login Username.
	 * @param WP_User $user       User.
	 */
	public function on_wp_login_success( $user_login, $user ) {
		unset( $user_login, $user );
		self::clear_request_attempts();
	}

	public function handle_unblock() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized', 'ghost-mode' ) );
		}
		check_admin_referer( 'ghost_mode_unblock' );

		$key = isset( $_POST['block_key'] ) ? sanitize_text_field( wp_unslash( $_POST['block_key'] ) ) : '';
		if ( $key !== '' ) {
			self::unblock( $key );
		}

		wp_safe_redirect( ghost_mode_get_settings_url( array( 'unblocked' => '1' ) ) );
		exit;
	}

	public function handle_unblock_all() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized', 'ghost-mode' ) );
		}
		check_admin_referer( 'ghost_mode_unblock_all' );
		self::unblock_all();
		wp_safe_redirect( ghost_mode_get_settings_url( array( 'unblocked_all' => '1' ) ) );
		exit;
	}

	public function handle_clear_attempts() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized', 'ghost-mode' ) );
		}
		check_admin_referer( 'ghost_mode_clear_attempts' );
		self::clear_all_attempts();
		wp_safe_redirect( ghost_mode_get_settings_url( array( 'attempts_cleared' => '1' ) ) );
		exit;
	}

	/**
	 * Type label for admin UI.
	 *
	 * @param string $type Type key.
	 */
	public static function type_label( $type ) {
		switch ( $type ) {
			case 'ip':
				return __( 'IP', 'ghost-mode' );
			case 'mac':
				return __( 'MAC', 'ghost-mode' );
			case 'device':
				return __( 'Device', 'ghost-mode' );
			default:
				return ucfirst( (string) $type );
		}
	}
}
