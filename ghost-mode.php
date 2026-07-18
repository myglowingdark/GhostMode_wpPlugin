<?php
/**
 * Plugin Name: Ghost Mode
 * Description: Hide wp-login and wp-admin behind a secret branded login URL. Works standalone; complements NGOBuddy when that plugin is active.
 * Version: 1.2.4
 * Author: Glowing Dark
 * Text Domain: ghost-mode
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'GHOST_MODE_VERSION', '1.3.0' );
define( 'GHOST_MODE_PATH', plugin_dir_path( __FILE__ ) );
define( 'GHOST_MODE_URL', plugin_dir_url( __FILE__ ) );
define( 'GHOST_MODE_SETTINGS_OPTION', 'ghost_mode_settings' );
define( 'GHOST_MODE_UNLOCK_COOKIE', 'ghost_mode_unlock' );
define( 'GHOST_MODE_UNLOCK_TTL', HOUR_IN_SECONDS );

require_once GHOST_MODE_PATH . 'includes/ghost-mode-plugin-deps.php';
require_once GHOST_MODE_PATH . 'includes/class-ghost-mode-lockout.php';
require_once GHOST_MODE_PATH . 'includes/class-ghost-mode-attempt-review.php';
require_once GHOST_MODE_PATH . 'includes/class-ghost-mode-sessions.php';
require_once GHOST_MODE_PATH . 'includes/class-ghost-mode-login-alerts.php';
require_once GHOST_MODE_PATH . 'includes/class-ghost-mode-settings.php';
require_once GHOST_MODE_PATH . 'includes/class-ghost-mode-security.php';
require_once GHOST_MODE_PATH . 'includes/class-ghost-mode-login.php';
require_once GHOST_MODE_PATH . 'includes/class-ghost-mode-quick-login.php';
require_once GHOST_MODE_PATH . 'includes/class-ghost-mode-password-age.php';

/**
 * Default + merged settings.
 *
 * @return array{
 *   enabled:string,
 *   login_slug:string,
 *   unlock_key:string,
 *   remember_me_default:string,
 *   lockout_enabled:string,
 *   max_login_attempts:int,
 *   session_logging:string,
 *   session_timeout_minutes:int,
 *   login_alert_enabled:string,
 *   login_alert_notify_user:string,
 *   login_alert_notify_admin:string,
 *   login_alert_extra_emails:string
 * }
 */
function ghost_mode_get_settings() {
	$defaults = array(
		'enabled'                   => 'no',
		'login_slug'                => 'secure-gate',
		'unlock_key'                => '',
		'remember_me_default'       => 'no',
		'lockout_enabled'           => 'yes',
		'max_login_attempts'        => 5,
		'session_logging'           => 'yes',
		'session_timeout_minutes'   => 60,
		'login_alert_enabled'       => 'yes',
		'login_alert_notify_user'   => 'yes',
		'login_alert_notify_admin'  => 'yes',
		'login_alert_extra_emails'  => '',
		'attempt_review_enabled'    => 'yes',
		'quick_login_enabled'       => 'yes',
		'password_age_enabled'      => 'yes',
		'password_age_days'         => 45,
	);
	$saved = get_option( GHOST_MODE_SETTINGS_OPTION, array() );
	if ( ! is_array( $saved ) ) {
		$saved = array();
	}
	return wp_parse_args( $saved, $defaults );
}

/**
 * Whether Ghost Mode hiding is active (enabled + valid slug).
 */
function ghost_mode_is_active() {
	$settings = ghost_mode_get_settings();
	if ( ( $settings['enabled'] ?? 'no' ) !== 'yes' ) {
		return false;
	}
	$slug = ghost_mode_sanitize_slug( $settings['login_slug'] ?? '' );
	return $slug !== '';
}

/**
 * Sanitize login slug (lowercase alphanumeric + hyphens).
 *
 * @param string $slug Raw slug.
 */
function ghost_mode_sanitize_slug( $slug ) {
	$slug = strtolower( trim( (string) $slug ) );
	$slug = preg_replace( '/[^a-z0-9\-]/', '', $slug );
	$slug = trim( (string) $slug, '-' );
	$reserved = array(
		'wp-admin',
		'wp-login',
		'wp-content',
		'wp-includes',
		'admin',
		'login',
		'feed',
		'robots.txt',
		'favicon.ico',
	);
	if ( $slug === '' || in_array( $slug, $reserved, true ) ) {
		return '';
	}
	return $slug;
}

/**
 * Public custom login URL.
 *
 * @param string $action Optional action (lostpassword, register, resetpass, logout).
 * @param array  $args   Extra query args.
 */
function ghost_mode_get_login_url( $action = '', $args = array() ) {
	$settings = ghost_mode_get_settings();
	$slug     = ghost_mode_sanitize_slug( $settings['login_slug'] ?? '' );
	if ( $slug === '' ) {
		$url = wp_login_url();
	} else {
		$url = home_url( user_trailingslashit( $slug ) );
	}

	$query = array();
	if ( $action !== '' && $action !== 'login' ) {
		$query['action'] = $action;
	}
	if ( ! empty( $args ) && is_array( $args ) ) {
		$query = array_merge( $query, $args );
	}
	if ( ! empty( $query ) ) {
		$url = add_query_arg( $query, $url );
	}
	return $url;
}

/**
 * Clean public URL for login-page assets (hides /wp-content/ in the Network tab).
 *
 * Allowed: login.css, login.js, logo, icon
 *
 * @param string $asset Asset key.
 */
function ghost_mode_get_login_asset_url( $asset ) {
	$asset    = sanitize_file_name( (string) $asset );
	$settings = ghost_mode_get_settings();
	$slug     = ghost_mode_sanitize_slug( $settings['login_slug'] ?? '' );
	if ( $slug === '' || $asset === '' ) {
		return '';
	}
	return add_query_arg(
		'v',
		rawurlencode( GHOST_MODE_VERSION ),
		home_url( user_trailingslashit( $slug . '/assets/' . $asset ) )
	);
}

/**
 * Emergency unlock URL.
 */
function ghost_mode_get_unlock_url() {
	$settings = ghost_mode_get_settings();
	$key      = (string) ( $settings['unlock_key'] ?? '' );
	if ( $key === '' ) {
		return '';
	}
	return add_query_arg( 'ghost_mode_unlock', rawurlencode( $key ), home_url( '/' ) );
}

/**
 * Generate a strong unlock key.
 */
function ghost_mode_generate_unlock_key() {
	return wp_generate_password( 32, false, false );
}

/**
 * Ensure settings exist with an unlock key.
 */
function ghost_mode_ensure_defaults() {
	$settings = ghost_mode_get_settings();
	$changed  = false;

	if ( empty( $settings['unlock_key'] ) ) {
		$settings['unlock_key'] = ghost_mode_generate_unlock_key();
		$changed                = true;
	}
	if ( ghost_mode_sanitize_slug( $settings['login_slug'] ) === '' ) {
		$settings['login_slug'] = 'secure-gate';
		$changed                = true;
	}

	if ( $changed ) {
		update_option( GHOST_MODE_SETTINGS_OPTION, $settings, false );
	}
}

/**
 * Admin settings screen URL.
 */
function ghost_mode_get_settings_url( $args = array() ) {
	$url = admin_url( 'admin.php?page=ghost-mode' );
	if ( ! empty( $args ) && is_array( $args ) ) {
		$url = add_query_arg( $args, $url );
	}
	return $url;
}

/**
 * Lock icon URL used as the plugin mark.
 */
function ghost_mode_get_icon_url() {
	return GHOST_MODE_URL . 'assets/icon.svg';
}

/**
 * Whether the current user has a Ghost Mode alert (stale password or failed-attempt review).
 *
 * @param int $user_id User ID.
 */
function ghost_mode_user_has_alert( $user_id = 0 ) {
	$user_id = $user_id ? (int) $user_id : get_current_user_id();
	if ( $user_id <= 0 ) {
		return false;
	}
	if ( class_exists( 'Ghost_Mode_Password_Age' ) && Ghost_Mode_Password_Age::is_enabled() && Ghost_Mode_Password_Age::is_stale( $user_id ) ) {
		return true;
	}
	if ( class_exists( 'Ghost_Mode_Attempt_Review' ) && Ghost_Mode_Attempt_Review::get_review( $user_id ) ) {
		return true;
	}
	return false;
}

/**
 * Menu / admin-bar title with optional red alert mark.
 *
 * @param string $label Base label.
 * @param bool   $with_dot Whether to append the alert dot.
 */
function ghost_mode_menu_title( $label, $with_dot = null ) {
	if ( null === $with_dot ) {
		$with_dot = ghost_mode_user_has_alert();
	}
	$title = (string) $label;
	if ( $with_dot ) {
		$title .= ' <span class="ghost-mode-menu-dot" aria-hidden="true"></span>';
	}
	return $title;
}

function ghost_mode_activate() {
	ghost_mode_ensure_defaults();
	Ghost_Mode_Security::register_rewrite_rules();
	flush_rewrite_rules();
}

function ghost_mode_deactivate() {
	flush_rewrite_rules();
}

register_activation_hook( __FILE__, 'ghost_mode_activate' );
register_deactivation_hook( __FILE__, 'ghost_mode_deactivate' );

add_action( 'plugins_loaded', 'ghost_mode_bootstrap' );

function ghost_mode_bootstrap() {
	ghost_mode_ensure_defaults();

	// Flush must wait for init — $wp_rewrite is not ready on plugins_loaded.
	add_action( 'init', 'ghost_mode_maybe_flush_rewrites', 99 );

	new Ghost_Mode_Lockout();
	new Ghost_Mode_Attempt_Review();
	new Ghost_Mode_Sessions();
	new Ghost_Mode_Login_Alerts();
	new Ghost_Mode_Settings();
	new Ghost_Mode_Security();
	$login = new Ghost_Mode_Login();
	new Ghost_Mode_Quick_Login( $login );
	new Ghost_Mode_Password_Age();
}

/**
 * One-time rewrite flush after plugin updates that add new rules.
 */
function ghost_mode_maybe_flush_rewrites() {
	if ( get_option( 'ghost_mode_rewrite_ver' ) === '3' ) {
		return;
	}
	Ghost_Mode_Security::register_rewrite_rules();
	flush_rewrite_rules( false );
	update_option( 'ghost_mode_rewrite_ver', '3', false );
}
