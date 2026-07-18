<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Login session log + admin-configurable session lifetime.
 */
class Ghost_Mode_Sessions {

	const LOG_OPTION      = 'ghost_mode_session_log';
	const MAX_LOG_ROWS    = 200;
	const PER_PAGE_DEFAULT = 10;

	/** @var string|null Token captured during set_logged_in_cookie (same request as login). */
	private static $pending_token = null;

	public function __construct() {
		// Token is available on this hook; $_COOKIE is not updated yet during wp_login.
		add_action( 'set_logged_in_cookie', array( $this, 'capture_login_token' ), 10, 6 );
		add_action( 'wp_login', array( $this, 'on_login' ), 20, 2 );
		add_action( 'wp_logout', array( $this, 'on_logout' ), 5 );
		add_action( 'init', array( $this, 'maybe_enforce_timeout' ), 20 );
		add_filter( 'auth_cookie_expiration', array( $this, 'filter_auth_cookie_expiration' ), 20, 3 );

		add_action( 'admin_post_ghost_mode_end_session', array( $this, 'handle_end_session' ) );
		add_action( 'admin_post_ghost_mode_clear_session_log', array( $this, 'handle_clear_log' ) );
		add_action( 'admin_post_ghost_mode_export_sessions', array( $this, 'handle_export' ) );
	}

	/**
	 * @param string $logged_in_cookie Cookie value.
	 * @param int    $expire           Expire timestamp.
	 * @param int    $expiration       Duration.
	 * @param int    $user_id          User ID.
	 * @param string $scheme           Scheme.
	 * @param string $token            Session token.
	 */
	public function capture_login_token( $logged_in_cookie, $expire, $expiration, $user_id, $scheme, $token ) {
		unset( $logged_in_cookie, $expire, $expiration, $user_id, $scheme );
		self::$pending_token = is_string( $token ) ? $token : '';
	}

	/**
	 * Whether session logging / timeout is enabled.
	 */
	public static function is_enabled() {
		$settings = ghost_mode_get_settings();
		return ( $settings['session_logging'] ?? 'yes' ) === 'yes';
	}

	/**
	 * Max session lifetime in minutes (0 = no forced timeout).
	 */
	public static function timeout_minutes() {
		$settings = ghost_mode_get_settings();
		return max( 0, absint( $settings['session_timeout_minutes'] ?? 60 ) );
	}

	/**
	 * @return array<int, array<string, mixed>>
	 */
	public static function get_log() {
		$log = get_option( self::LOG_OPTION, array() );
		return is_array( $log ) ? $log : array();
	}

	/**
	 * @param array<int, array<string, mixed>> $log Log rows.
	 */
	public static function save_log( array $log ) {
		if ( count( $log ) > self::MAX_LOG_ROWS ) {
			$log = array_slice( $log, 0, self::MAX_LOG_ROWS );
		}
		update_option( self::LOG_OPTION, array_values( $log ), false );
	}

	/**
	 * Human duration string.
	 *
	 * @param int $seconds Seconds.
	 */
	public static function format_duration( $seconds ) {
		$seconds = max( 0, (int) $seconds );
		$h       = (int) floor( $seconds / HOUR_IN_SECONDS );
		$m       = (int) floor( ( $seconds % HOUR_IN_SECONDS ) / MINUTE_IN_SECONDS );
		$s       = (int) ( $seconds % MINUTE_IN_SECONDS );

		$parts = array();
		if ( $h > 0 ) {
			$parts[] = sprintf( '%dh', $h );
		}
		if ( $m > 0 || $h > 0 ) {
			$parts[] = sprintf( '%dm', $m );
		}
		$parts[] = sprintf( '%ds', $s );
		return implode( ' ', $parts );
	}

	/**
	 * @param string  $user_login Username.
	 * @param WP_User $user       User.
	 */
	public function on_login( $user_login, $user ) {
		if ( ! self::is_enabled() || ! ( $user instanceof WP_User ) ) {
			return;
		}

		$token = is_string( self::$pending_token ) ? self::$pending_token : '';
		if ( $token === '' && function_exists( 'wp_get_session_token' ) ) {
			$token = (string) wp_get_session_token();
		}
		self::$pending_token = null;

		$now = time();
		$row = array(
			'id'         => function_exists( 'wp_generate_uuid4' ) ? wp_generate_uuid4() : uniqid( 'gm_', true ),
			'user_id'    => (int) $user->ID,
			'user_login' => sanitize_user( $user_login ),
			'ip'         => Ghost_Mode_Lockout::get_client_ip(),
			'mac'        => Ghost_Mode_Lockout::get_client_mac(),
			'ua'         => self::truncate_ua(),
			'login_at'   => $now,
			'last_seen'  => $now,
			'ended_at'   => null,
			'duration'   => 0,
			'status'     => 'active',
			'token_hash' => $token !== '' ? hash( 'sha256', $token ) : '',
		);

		$log = self::get_log();
		array_unshift( $log, $row );
		self::save_log( $log );
	}

	public function on_logout() {
		if ( ! self::is_enabled() ) {
			return;
		}

		$user_id = get_current_user_id();
		$token   = function_exists( 'wp_get_session_token' ) ? (string) wp_get_session_token() : '';
		self::close_session( $user_id, $token, 'logout' );
	}

	/**
	 * Enforce max session duration and refresh last_seen.
	 */
	public function maybe_enforce_timeout() {
		if ( ! self::is_enabled() || ! is_user_logged_in() ) {
			return;
		}

		// Avoid breaking cron / CLI.
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() ) {
			return;
		}

		$user_id = get_current_user_id();
		$token   = function_exists( 'wp_get_session_token' ) ? (string) wp_get_session_token() : '';
		$now     = time();
		$timeout = self::timeout_minutes();

		$log     = self::get_log();
		$changed = false;
		$expired = false;

		foreach ( $log as $i => $row ) {
			if ( ( $row['status'] ?? '' ) !== 'active' ) {
				continue;
			}
			if ( (int) ( $row['user_id'] ?? 0 ) !== $user_id ) {
				continue;
			}

			$token_hash = (string) ( $row['token_hash'] ?? '' );
			if ( $token_hash !== '' && $token !== '' && ! hash_equals( $token_hash, hash( 'sha256', $token ) ) ) {
				continue;
			}

			$login_at = absint( $row['login_at'] ?? 0 );
			$log[ $i ]['last_seen'] = $now;
			$log[ $i ]['duration']  = max( 0, $now - $login_at );
			$changed                = true;

			if ( $timeout > 0 && $login_at > 0 && ( $now - $login_at ) >= ( $timeout * MINUTE_IN_SECONDS ) ) {
				$log[ $i ]['status']   = 'expired';
				$log[ $i ]['ended_at'] = $now;
				$log[ $i ]['duration'] = $now - $login_at;
				$expired               = true;
			}
			break;
		}

		if ( $changed ) {
			self::save_log( $log );
		}

		if ( $expired ) {
			// Destroy WP session for this token, then redirect to login.
			$manager = WP_Session_Tokens::get_instance( $user_id );
			if ( $token !== '' ) {
				$manager->destroy( $token );
			} else {
				$manager->destroy_all();
			}

			wp_clear_auth_cookie();
			nocache_headers();

			$login_url = ghost_mode_get_login_url(
				'login',
				array(
					'redirect_to' => ( is_admin() ? admin_url() : home_url( '/' ) ),
					'session'     => 'expired',
				)
			);
			wp_safe_redirect( $login_url );
			exit;
		}
	}

	/**
	 * Cap auth cookie lifetime to the admin session timeout.
	 *
	 * @param int  $expiration Duration in seconds.
	 * @param int  $user_id    User ID.
	 * @param bool $remember   Remember me.
	 */
	public function filter_auth_cookie_expiration( $expiration, $user_id, $remember ) {
		unset( $user_id, $remember );
		if ( ! self::is_enabled() ) {
			return $expiration;
		}
		$timeout = self::timeout_minutes();
		if ( $timeout <= 0 ) {
			return $expiration;
		}
		return min( (int) $expiration, $timeout * MINUTE_IN_SECONDS );
	}

	/**
	 * Close an active session row.
	 *
	 * @param int    $user_id User ID.
	 * @param string $token   Session token.
	 * @param string $status  ended status.
	 * @param string $id      Optional row id.
	 */
	public static function close_session( $user_id, $token = '', $status = 'logout', $id = '' ) {
		$log     = self::get_log();
		$now     = time();
		$changed = false;
		$hash    = $token !== '' ? hash( 'sha256', $token ) : '';

		foreach ( $log as $i => $row ) {
			if ( ( $row['status'] ?? '' ) !== 'active' ) {
				continue;
			}

			$match = false;
			if ( $id !== '' && ( $row['id'] ?? '' ) === $id ) {
				$match = true;
			} elseif ( $id === '' && (int) ( $row['user_id'] ?? 0 ) === (int) $user_id ) {
				$row_hash = (string) ( $row['token_hash'] ?? '' );
				if ( $hash !== '' && $row_hash !== '' ) {
					$match = hash_equals( $row_hash, $hash );
				} elseif ( $hash === '' || $row_hash === '' ) {
					// Fallback: newest active for this user.
					$match = true;
				}
			}

			if ( ! $match ) {
				continue;
			}

			$login_at              = absint( $row['login_at'] ?? $now );
			$log[ $i ]['status']   = sanitize_key( $status );
			$log[ $i ]['ended_at'] = $now;
			$log[ $i ]['last_seen'] = $now;
			$log[ $i ]['duration'] = max( 0, $now - $login_at );
			$changed               = true;
			break;
		}

		if ( $changed ) {
			self::save_log( $log );
		}
	}

	/**
	 * Force-end a logged session (admin action).
	 *
	 * @param string $id Session row id.
	 */
	public static function force_end( $id ) {
		$log = self::get_log();
		foreach ( $log as $row ) {
			if ( ( $row['id'] ?? '' ) !== $id ) {
				continue;
			}
			$user_id = absint( $row['user_id'] ?? 0 );
			$status  = (string) ( $row['status'] ?? '' );

			if ( $status === 'active' && $user_id > 0 ) {
				WP_Session_Tokens::get_instance( $user_id )->destroy_all();
				self::close_session( $user_id, '', 'forced', $id );
			}
			return true;
		}
		return false;
	}

	/**
	 * Paginate the session log.
	 *
	 * @param int $page     1-based page.
	 * @param int $per_page Rows per page.
	 * @param int $user_id  Optional: limit to one user (0 = all).
	 * @return array{rows:array,total:int,page:int,per_page:int,total_pages:int}
	 */
	public static function get_log_page( $page = 1, $per_page = self::PER_PAGE_DEFAULT, $user_id = 0 ) {
		$log = self::get_log();
		$user_id = absint( $user_id );
		if ( $user_id > 0 ) {
			$log = array_values(
				array_filter(
					$log,
					static function ( $row ) use ( $user_id ) {
						return absint( $row['user_id'] ?? 0 ) === $user_id;
					}
				)
			);
		}
		$total       = count( $log );
		$per_page    = max( 1, min( 100, absint( $per_page ) ) );
		$total_pages = max( 1, (int) ceil( $total / $per_page ) );
		$page        = max( 1, min( $total_pages, absint( $page ) ) );
		$offset      = ( $page - 1 ) * $per_page;
		$rows        = array_slice( $log, $offset, $per_page );

		return array(
			'rows'        => $rows,
			'total'       => $total,
			'page'        => $page,
			'per_page'    => $per_page,
			'total_pages' => $total_pages,
		);
	}

	/**
	 * Flatten a log row for CSV / display helpers.
	 *
	 * @param array $row Raw row.
	 * @return array<string, string>
	 */
	public static function flatten_row_for_export( array $row ) {
		$login_at  = absint( $row['login_at'] ?? 0 );
		$ended_at  = absint( $row['ended_at'] ?? 0 );
		$duration  = absint( $row['duration'] ?? 0 );
		$status    = (string) ( $row['status'] ?? '' );
		if ( $status === 'active' && $login_at > 0 ) {
			$duration = max( $duration, time() - $login_at );
		}

		return array(
			'id'          => (string) ( $row['id'] ?? '' ),
			'user_id'     => (string) ( $row['user_id'] ?? '' ),
			'user_login'  => (string) ( $row['user_login'] ?? '' ),
			'ip'          => (string) ( $row['ip'] ?? '' ),
			'mac'         => (string) ( $row['mac'] ?? '' ),
			'login_at'    => $login_at ? wp_date( 'Y-m-d H:i:s', $login_at ) : '',
			'ended_at'    => $ended_at ? wp_date( 'Y-m-d H:i:s', $ended_at ) : '',
			'duration'    => self::format_duration( $duration ),
			'duration_s'  => (string) $duration,
			'status'      => self::status_label( $status ),
			'status_key'  => $status,
			'user_agent'  => (string) ( $row['ua'] ?? '' ),
		);
	}

	public function handle_end_session() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized', 'ghost-mode' ) );
		}
		check_admin_referer( 'ghost_mode_end_session' );
		$id = isset( $_POST['session_id'] ) ? sanitize_text_field( wp_unslash( $_POST['session_id'] ) ) : '';
		if ( $id !== '' ) {
			self::force_end( $id );
		}
		$page = isset( $_POST['gm_session_page'] ) ? absint( $_POST['gm_session_page'] ) : 1;
		wp_safe_redirect(
			ghost_mode_get_settings_url(
				array(
					'session_ended'   => '1',
					'gm_session_page' => max( 1, $page ),
				)
			)
		);
		exit;
	}

	public function handle_clear_log() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized', 'ghost-mode' ) );
		}
		check_admin_referer( 'ghost_mode_clear_session_log' );
		update_option( self::LOG_OPTION, array(), false );
		wp_safe_redirect( ghost_mode_get_settings_url( array( 'sessions_cleared' => '1' ) ) );
		exit;
	}

	/**
	 * Export full session log as CSV.
	 */
	public function handle_export() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized', 'ghost-mode' ) );
		}
		check_admin_referer( 'ghost_mode_export_sessions' );

		$log      = self::get_log();
		$filename = 'ghost-mode-sessions-' . gmdate( 'Y-m-d-His' ) . '.csv';

		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . $filename . '"' );

		$out = fopen( 'php://output', 'w' );
		if ( false === $out ) {
			wp_die( esc_html__( 'Unable to export.', 'ghost-mode' ) );
		}

		// UTF-8 BOM for Excel.
		fwrite( $out, "\xEF\xBB\xBF" );

		fputcsv(
			$out,
			array(
				'ID',
				'User ID',
				'Username',
				'IP',
				'MAC',
				'Login time',
				'Ended at',
				'Duration',
				'Duration (seconds)',
				'Status',
				'User agent',
			)
		);

		foreach ( $log as $row ) {
			$flat = self::flatten_row_for_export( is_array( $row ) ? $row : array() );
			fputcsv(
				$out,
				array(
					$flat['id'],
					$flat['user_id'],
					$flat['user_login'],
					$flat['ip'],
					$flat['mac'],
					$flat['login_at'],
					$flat['ended_at'],
					$flat['duration'],
					$flat['duration_s'],
					$flat['status'],
					$flat['user_agent'],
				)
			);
		}

		fclose( $out );
		exit;
	}

	/**
	 * Truncate user agent for storage.
	 */
	private static function truncate_ua() {
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$ua = sanitize_text_field( $ua );
		if ( strlen( $ua ) > 180 ) {
			$ua = substr( $ua, 0, 177 ) . '...';
		}
		return $ua;
	}

	/**
	 * Status label for admin UI.
	 *
	 * @param string $status Status key.
	 */
	public static function status_label( $status ) {
		switch ( $status ) {
			case 'active':
				return __( 'Active', 'ghost-mode' );
			case 'expired':
				return __( 'Expired', 'ghost-mode' );
			case 'logout':
				return __( 'Logged out', 'ghost-mode' );
			case 'forced':
				return __( 'Ended by admin', 'ghost-mode' );
			default:
				return ucfirst( (string) $status );
		}
	}
}
