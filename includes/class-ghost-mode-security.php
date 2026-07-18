<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Ghost_Mode_Security {

	public function __construct() {
		add_action( 'init', array( __CLASS__, 'register_rewrite_rules' ) );
		add_filter( 'query_vars', array( $this, 'register_query_vars' ) );

		add_action( 'init', array( $this, 'maybe_handle_unlock' ), 1 );
		// Run before auth_redirect() in wp-admin/admin.php so /wp-admin does not leak the secret login URL.
		add_action( 'init', array( $this, 'block_wp_admin' ), 2 );
		add_action( 'login_init', array( $this, 'block_stock_login' ), 1 );

		add_filter( 'login_url', array( $this, 'filter_login_url' ), 10, 3 );
		add_filter( 'lostpassword_url', array( $this, 'filter_lostpassword_url' ), 10, 2 );
		add_filter( 'register_url', array( $this, 'filter_register_url' ), 10, 1 );
		add_filter( 'logout_url', array( $this, 'filter_logout_url' ), 10, 2 );
		add_filter( 'site_url', array( $this, 'filter_site_url' ), 10, 4 );
		add_filter( 'network_site_url', array( $this, 'filter_site_url' ), 10, 3 );
		add_filter( 'wp_redirect', array( $this, 'filter_wp_redirect' ), 10, 2 );

		add_action( 'admin_notices', array( $this, 'unlock_admin_notice' ) );
		add_action( 'wp_logout', array( $this, 'redirect_after_logout' ) );
	}

	public static function register_rewrite_rules() {
		$settings = ghost_mode_get_settings();
		$slug     = ghost_mode_sanitize_slug( $settings['login_slug'] ?? '' );
		if ( $slug === '' ) {
			return;
		}
		$quoted = preg_quote( $slug, '/' );
		add_rewrite_rule( '^' . $quoted . '/go/([^/]+)/?$', 'index.php?ghost_mode_quick=$matches[1]', 'top' );
		add_rewrite_rule( '^' . $quoted . '/assets/([^/]+)/?$', 'index.php?ghost_mode_asset=$matches[1]', 'top' );
		add_rewrite_rule( '^' . $quoted . '/?$', 'index.php?ghost_mode_login=1', 'top' );
	}

	/**
	 * @param string[] $vars Query vars.
	 * @return string[]
	 */
	public function register_query_vars( $vars ) {
		$vars[] = 'ghost_mode_login';
		$vars[] = 'ghost_mode_asset';
		$vars[] = 'ghost_mode_quick';
		return $vars;
	}

	/**
	 * Whether the current browser has a valid emergency unlock cookie.
	 */
	public static function is_temporarily_unlocked() {
		if ( empty( $_COOKIE[ GHOST_MODE_UNLOCK_COOKIE ] ) ) {
			return false;
		}
		$settings = ghost_mode_get_settings();
		$key      = (string) ( $settings['unlock_key'] ?? '' );
		if ( $key === '' ) {
			return false;
		}
		$cookie = sanitize_text_field( wp_unslash( $_COOKIE[ GHOST_MODE_UNLOCK_COOKIE ] ) );
		return hash_equals( wp_hash( $key ), $cookie );
	}

	/**
	 * Handle ?ghost_mode_unlock=SECRET
	 */
	public function maybe_handle_unlock() {
		if ( empty( $_GET['ghost_mode_unlock'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}

		$provided = sanitize_text_field( wp_unslash( $_GET['ghost_mode_unlock'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$settings = ghost_mode_get_settings();
		$key      = (string) ( $settings['unlock_key'] ?? '' );

		if ( $key === '' || ! hash_equals( $key, $provided ) ) {
			return;
		}

		$cookie_value = wp_hash( $key );
		$expire       = time() + GHOST_MODE_UNLOCK_TTL;

		setcookie(
			GHOST_MODE_UNLOCK_COOKIE,
			$cookie_value,
			array(
				'expires'  => $expire,
				'path'     => COOKIEPATH ? COOKIEPATH : '/',
				'domain'   => COOKIE_DOMAIN,
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);
		$_COOKIE[ GHOST_MODE_UNLOCK_COOKIE ] = $cookie_value;

		set_transient( 'ghost_mode_unlock_notice_' . md5( $cookie_value ), 1, GHOST_MODE_UNLOCK_TTL );

		wp_safe_redirect( ghost_mode_get_settings_url( array( 'ghost_unlocked' => '1' ) ) );
		exit;
	}

	public function unlock_admin_notice() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		if ( ! self::is_temporarily_unlocked() ) {
			return;
		}
		if ( ! ghost_mode_is_active() ) {
			return;
		}

		echo '<div class="notice notice-warning is-dismissible"><p>';
		echo esc_html__( 'Ghost Mode is temporarily unlocked for this browser (1 hour). Stock wp-login.php and wp-admin are accessible. Disable Ghost Mode in settings if you need permanent access, or wait for the unlock to expire.', 'ghost-mode' );
		echo ' <a href="' . esc_url( ghost_mode_get_settings_url() ) . '">' . esc_html__( 'Open Ghost Mode settings', 'ghost-mode' ) . '</a>';
		echo '</p></div>';
	}

	/**
	 * Redirect logged-out visitors away from wp-login.php when Ghost Mode is on.
	 */
	public function block_stock_login() {
		if ( ! ghost_mode_is_active() || self::is_temporarily_unlocked() ) {
			return;
		}

		$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : 'login'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		// Allow password-protected post form and logout confirmation when already ending a session.
		$allowed = array( 'postpass', 'logout', 'confirmaction' );
		if ( in_array( $action, $allowed, true ) ) {
			return;
		}

		wp_safe_redirect( home_url( '/' ) );
		exit;
	}

	/**
	 * Redirect logged-out visitors away from wp-admin (except ajax/post).
	 * Must run on init before auth_redirect() so the Location header does not expose the custom login slug.
	 */
	public function block_wp_admin() {
		if ( ! ghost_mode_is_active() || self::is_temporarily_unlocked() ) {
			return;
		}

		if ( ! is_admin() || is_user_logged_in() ) {
			return;
		}

		// Keep AJAX and admin-post for front-end forms.
		if ( wp_doing_ajax() ) {
			return;
		}

		global $pagenow;
		if ( in_array( (string) $pagenow, array( 'admin-ajax.php', 'admin-post.php' ), true ) ) {
			return;
		}

		$script = isset( $_SERVER['SCRIPT_NAME'] ) ? (string) wp_unslash( $_SERVER['SCRIPT_NAME'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		if ( $script !== '' && ( str_ends_with( $script, '/admin-ajax.php' ) || str_ends_with( $script, '/admin-post.php' ) ) ) {
			return;
		}

		wp_safe_redirect( home_url( '/' ) );
		exit;
	}

	/**
	 * @param string $login_url    Login URL.
	 * @param string $redirect     Redirect destination.
	 * @param bool   $force_reauth Force reauth.
	 */
	public function filter_login_url( $login_url, $redirect, $force_reauth ) {
		if ( ! ghost_mode_is_active() || self::is_temporarily_unlocked() ) {
			return $login_url;
		}

		$args = array();
		if ( ! empty( $redirect ) ) {
			$args['redirect_to'] = $redirect;
		}
		if ( $force_reauth ) {
			$args['reauth'] = '1';
		}
		return ghost_mode_get_login_url( 'login', $args );
	}

	/**
	 * @param string $url      Lost password URL.
	 * @param string $redirect Redirect.
	 */
	public function filter_lostpassword_url( $url, $redirect ) {
		if ( ! ghost_mode_is_active() || self::is_temporarily_unlocked() ) {
			return $url;
		}
		$args = array();
		if ( ! empty( $redirect ) ) {
			$args['redirect_to'] = $redirect;
		}
		return ghost_mode_get_login_url( 'lostpassword', $args );
	}

	/**
	 * @param string $url Register URL.
	 */
	public function filter_register_url( $url ) {
		if ( ! ghost_mode_is_active() || self::is_temporarily_unlocked() ) {
			return $url;
		}
		return ghost_mode_get_login_url( 'register' );
	}

	/**
	 * @param string $logout_url Logout URL.
	 * @param string $redirect   Redirect after logout.
	 */
	public function filter_logout_url( $logout_url, $redirect ) {
		if ( ! ghost_mode_is_active() || self::is_temporarily_unlocked() ) {
			return $logout_url;
		}

		$args = array(
			'action' => 'logout',
		);
		if ( ! empty( $redirect ) ) {
			$args['redirect_to'] = $redirect;
		} else {
			$args['redirect_to'] = ghost_mode_get_login_url();
		}

		// Build nonce against custom URL path.
		$url = ghost_mode_get_login_url( 'logout', $args );
		$url = wp_nonce_url( $url, 'log-out' );
		return $url;
	}

	/**
	 * Rewrite site_url() calls that target wp-login.php.
	 *
	 * @param string      $url     URL.
	 * @param string      $path    Path.
	 * @param string|null $scheme  Scheme.
	 * @param int|null    $blog_id Blog ID (site_url only).
	 */
	public function filter_site_url( $url, $path, $scheme, $blog_id = null ) {
		unset( $scheme, $blog_id );
		if ( ! ghost_mode_is_active() || self::is_temporarily_unlocked() ) {
			return $url;
		}

		if ( ! is_string( $path ) ) {
			return $url;
		}

		$path_only = (string) $path;
		if ( strpos( $path_only, 'wp-login.php' ) === false && strpos( $url, 'wp-login.php' ) === false ) {
			return $url;
		}

		$query = array();
		$parts = wp_parse_url( $url );
		if ( ! empty( $parts['query'] ) ) {
			parse_str( $parts['query'], $query );
		}

		$action = isset( $query['action'] ) ? sanitize_key( $query['action'] ) : 'login';
		unset( $query['action'] );

		if ( in_array( $action, array( 'postpass', 'logout', 'confirmaction' ), true ) && ! empty( $parts['query'] ) ) {
			// Keep native handling for these when coming through site_url — still map logout to custom.
			if ( $action !== 'logout' ) {
				return $url;
			}
		}

		return ghost_mode_get_login_url( $action, $query );
	}

	/**
	 * Catch redirects that still point at wp-login.php.
	 *
	 * @param string $location Location.
	 * @param int    $status   Status.
	 */
	public function filter_wp_redirect( $location, $status ) {
		unset( $status );
		if ( ! ghost_mode_is_active() || self::is_temporarily_unlocked() ) {
			return $location;
		}
		if ( ! is_string( $location ) || strpos( $location, 'wp-login.php' ) === false ) {
			return $location;
		}

		$parts = wp_parse_url( $location );
		$query = array();
		if ( ! empty( $parts['query'] ) ) {
			parse_str( $parts['query'], $query );
		}
		$action = isset( $query['action'] ) ? sanitize_key( $query['action'] ) : 'login';
		unset( $query['action'] );

		if ( in_array( $action, array( 'postpass', 'confirmaction' ), true ) ) {
			return $location;
		}

		return ghost_mode_get_login_url( $action, $query );
	}

	/**
	 * After logout, send users to the custom login page.
	 */
	public function redirect_after_logout() {
		if ( ! ghost_mode_is_active() ) {
			return;
		}

		$redirect = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( $redirect === '' ) {
			$redirect = ghost_mode_get_login_url();
		}

		wp_safe_redirect( $redirect );
		exit;
	}
}
