<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Device-bound bookmark URLs with 4-digit PIN login.
 *
 * URL: /{login_slug}/go/{token}
 * Bound to an HttpOnly device cookie set when the link is created.
 * Wrong device / expired / unknown token → homepage (no hint).
 */
class Ghost_Mode_Quick_Login {

	const USER_META       = 'ghost_mode_quick_links';
	const INDEX_OPTION    = 'ghost_mode_quick_index';
	const OFFER_META      = 'ghost_mode_quick_offer';
	const MAX_LINKS       = 3;
	const TTL_DAYS        = 60;
	const COOKIE_PREFIX   = 'gm_qd_';
	const TOKEN_BYTES     = 32;

	/** @var Ghost_Mode_Login|null */
	private $login;

	public function __construct( ?Ghost_Mode_Login $login = null ) {
		$this->login = $login;

		add_action( 'parse_request', array( $this, 'maybe_flag_request' ), 1 );
		add_action( 'template_redirect', array( $this, 'maybe_handle_quick' ), 0 );

		add_action( 'wp_login', array( $this, 'on_password_login_flag' ), 5, 2 );

		add_action( 'admin_footer', array( $this, 'render_modal' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );

		add_action( 'wp_ajax_ghost_mode_quick_create', array( $this, 'ajax_create' ) );
		add_action( 'wp_ajax_ghost_mode_quick_dismiss', array( $this, 'ajax_dismiss' ) );
		add_action( 'admin_post_ghost_mode_quick_revoke', array( $this, 'handle_revoke' ) );
	}

	/**
	 * Whether feature is enabled in settings.
	 */
	public static function is_enabled() {
		$settings = ghost_mode_get_settings();
		return ( $settings['quick_login_enabled'] ?? 'yes' ) === 'yes';
	}

	/**
	 * Public bookmark URL for a raw token.
	 *
	 * @param string $raw_token Raw token.
	 */
	public static function get_url( $raw_token ) {
		$settings = ghost_mode_get_settings();
		$slug     = ghost_mode_sanitize_slug( $settings['login_slug'] ?? '' );
		$token    = preg_replace( '/[^a-zA-Z0-9]/', '', (string) $raw_token );
		if ( $slug === '' || $token === '' ) {
			return '';
		}
		return home_url( user_trailingslashit( $slug . '/go/' . $token ) );
	}

	/**
	 * @param WP $wp WP request.
	 */
	public function maybe_flag_request( $wp ) {
		if ( ! empty( $wp->query_vars['ghost_mode_quick'] ) ) {
			return;
		}

		$settings = ghost_mode_get_settings();
		$slug     = ghost_mode_sanitize_slug( $settings['login_slug'] ?? '' );
		if ( $slug === '' ) {
			return;
		}

		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$path = trim( (string) parse_url( $uri, PHP_URL_PATH ), '/' );
		$home = trim( (string) parse_url( home_url( '/' ), PHP_URL_PATH ), '/' );
		if ( $home !== '' && strpos( $path, $home . '/' ) === 0 ) {
			$path = substr( $path, strlen( $home ) + 1 );
		} elseif ( $home !== '' && $path === $home ) {
			$path = '';
		}

		$prefix = $slug . '/go/';
		if ( strpos( $path, $prefix ) === 0 ) {
			$token = preg_replace( '/[^a-zA-Z0-9]/', '', substr( $path, strlen( $prefix ) ) );
			if ( $token !== '' ) {
				$wp->query_vars['ghost_mode_quick'] = $token;
			}
		}
	}

	/**
	 * Handle /{slug}/go/{token} — homepage on any failure, PIN form on success.
	 */
	public function maybe_handle_quick() {
		$token = (string) get_query_var( 'ghost_mode_quick' );
		if ( $token === '' ) {
			return;
		}

		nocache_headers();

		if ( ! self::is_enabled() ) {
			$this->go_home();
		}

		$token = preg_replace( '/[^a-zA-Z0-9]/', '', $token );
		$found = self::lookup_token( $token );
		if ( ! $found ) {
			$this->go_home();
		}

		$user_id = (int) $found['user_id'];
		$link    = $found['link'];
		$link_id = (string) ( $link['id'] ?? '' );

		if ( $link_id === '' || ! self::device_cookie_matches( $link_id, (string) ( $link['device_hash'] ?? '' ) ) ) {
			$this->go_home();
		}

		$user = get_userdata( $user_id );
		if ( ! ( $user instanceof WP_User ) ) {
			$this->go_home();
		}

		if ( is_user_logged_in() ) {
			wp_safe_redirect( admin_url() );
			exit;
		}

		$errors   = array();
		$messages = array();

		if ( Ghost_Mode_Lockout::is_request_blocked() ) {
			$errors[] = Ghost_Mode_Lockout::blocked_message();
			$this->render_pin( $token, $errors, $messages );
			return;
		}

		if ( 'POST' === ( $_SERVER['REQUEST_METHOD'] ?? '' ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			check_admin_referer( 'ghost_mode_quick_pin', 'ghost_mode_quick_pin_nonce' );

			if ( Ghost_Mode_Lockout::is_request_blocked() ) {
				$errors[] = Ghost_Mode_Lockout::blocked_message();
				$this->render_pin( $token, $errors, $messages );
				return;
			}

			$pin = isset( $_POST['pin'] ) ? preg_replace( '/\D/', '', (string) wp_unslash( $_POST['pin'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			if ( strlen( $pin ) !== 4 || ! self::verify_pin( $pin, (string) ( $link['pin_hash'] ?? '' ) ) ) {
				Ghost_Mode_Lockout::record_failure( $user->user_login );
				if ( Ghost_Mode_Lockout::is_request_blocked() ) {
					$errors[] = Ghost_Mode_Lockout::blocked_message();
				} else {
					$errors[] = __( 'Invalid PIN.', 'ghost-mode' );
					$remaining = Ghost_Mode_Lockout::remaining_attempts();
					if ( Ghost_Mode_Lockout::is_enabled() && $remaining > 0 ) {
						$errors[] = sprintf(
							/* translators: %d: remaining attempts */
							_n( '%d attempt remaining.', '%d attempts remaining.', $remaining, 'ghost-mode' ),
							$remaining
						);
					}
				}
				$this->render_pin( $token, $errors, $messages );
				return;
			}

			Ghost_Mode_Lockout::clear_request_attempts();
			self::touch_link( $user_id, $link_id );

			$GLOBALS['ghost_mode_quick_pin_login'] = true;
			wp_set_current_user( $user_id );
			wp_set_auth_cookie( $user_id, true, is_ssl() );
			do_action( 'wp_login', $user->user_login, $user );

			wp_safe_redirect( admin_url() );
			exit;
		}

		$this->render_pin( $token, $errors, $messages );
	}

	/**
	 * @param string   $token    Raw token.
	 * @param string[] $errors   Errors.
	 * @param string[] $messages Messages.
	 */
	private function render_pin( $token, array $errors, array $messages ) {
		if ( $this->login instanceof Ghost_Mode_Login ) {
			$this->login->render_pin_view( $token, $errors, $messages );
		}
		exit;
	}

	private function go_home() {
		wp_safe_redirect( home_url( '/' ) );
		exit;
	}

	/**
	 * Flag offer after password sign-on (not PIN — PIN already has a device cookie).
	 *
	 * @param string  $user_login Login.
	 * @param WP_User $user       User.
	 */
	public function on_password_login_flag( $user_login, $user ) {
		unset( $user_login );
		if ( ! self::is_enabled() || ! ( $user instanceof WP_User ) ) {
			return;
		}
		// Skip if this request is a quick PIN login (cookie already matched).
		if ( ! empty( $GLOBALS['ghost_mode_quick_pin_login'] ) ) {
			return;
		}
		// Only offer when under the link cap and this device has no binding yet.
		$links = self::get_active_links( (int) $user->ID );
		if ( count( $links ) >= self::MAX_LINKS ) {
			return;
		}
		if ( self::current_device_has_link( (int) $user->ID ) ) {
			return;
		}
		update_user_meta( (int) $user->ID, self::OFFER_META, time() );
	}

	/**
	 * Whether the modal should show for the current admin user.
	 */
	public static function should_show_offer( $user_id = 0 ) {
		$user_id = $user_id ? (int) $user_id : get_current_user_id();
		if ( ! self::is_enabled() || $user_id <= 0 ) {
			return false;
		}
		// Password-age prompt takes priority so two modals do not stack.
		if ( class_exists( 'Ghost_Mode_Password_Age' ) && Ghost_Mode_Password_Age::should_show_prompt( $user_id ) ) {
			return false;
		}
		$offered = absint( get_user_meta( $user_id, self::OFFER_META, true ) );
		if ( $offered <= 0 ) {
			return false;
		}
		// Offer window: 12 hours after password login.
		if ( $offered < ( time() - ( 12 * HOUR_IN_SECONDS ) ) ) {
			delete_user_meta( $user_id, self::OFFER_META );
			return false;
		}
		$links = self::get_active_links( $user_id );
		if ( count( $links ) >= self::MAX_LINKS ) {
			return false;
		}
		if ( self::current_device_has_link( $user_id ) ) {
			return false;
		}
		return true;
	}

	public function enqueue_admin_assets( $hook ) {
		unset( $hook );
		if ( ! is_user_logged_in() || ! self::should_show_offer() ) {
			return;
		}
		wp_enqueue_style(
			'ghost-mode-admin',
			GHOST_MODE_URL . 'assets/ghost-mode-admin.css',
			array(),
			GHOST_MODE_VERSION
		);
		wp_enqueue_script(
			'ghost-mode-admin',
			GHOST_MODE_URL . 'assets/ghost-mode-admin.js',
			array(),
			GHOST_MODE_VERSION,
			true
		);
		wp_localize_script(
			'ghost-mode-admin',
			'ghostModeQuick',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( 'ghost_mode_quick' ),
				'i18n'    => array(
					'copied'     => __( 'Copied!', 'ghost-mode' ),
					'copy'       => __( 'Copy link', 'ghost-mode' ),
					'pinMismatch'=> __( 'PINs do not match.', 'ghost-mode' ),
					'pinInvalid' => __( 'Enter a 4-digit PIN.', 'ghost-mode' ),
					'error'      => __( 'Something went wrong. Please try again.', 'ghost-mode' ),
				),
			)
		);
	}

	public function render_modal() {
		if ( ! self::should_show_offer() ) {
			return;
		}
		?>
		<div id="ghost-mode-quick-modal" class="ghost-mode-quick-modal" role="dialog" aria-modal="true" aria-labelledby="ghost-mode-quick-title">
			<div class="ghost-mode-quick-modal__backdrop"></div>
			<div class="ghost-mode-quick-modal__card">
				<div class="ghost-mode-quick-modal__badge" aria-hidden="true">PIN</div>
				<div data-step="setup">
					<h2 id="ghost-mode-quick-title"><?php esc_html_e( 'Skip the password next time!', 'ghost-mode' ); ?></h2>
					<p class="ghost-mode-quick-modal__lead">
						<?php esc_html_e( 'Bookmark a private link for this device. Next visit: just your 4-digit PIN. No typing your password again.', 'ghost-mode' ); ?>
					</p>
					<p class="ghost-mode-quick-modal__hint">
						<?php esc_html_e( 'Works only on this browser for 60 days. Up to 3 devices.', 'ghost-mode' ); ?>
					</p>
					<label class="ghost-mode-quick-modal__label" for="ghost_mode_quick_pin"><?php esc_html_e( 'Create a 4-digit PIN', 'ghost-mode' ); ?></label>
					<input class="ghost-mode-quick-modal__pin" type="password" inputmode="numeric" pattern="[0-9]*" maxlength="4" id="ghost_mode_quick_pin" autocomplete="off" placeholder="••••">
					<label class="ghost-mode-quick-modal__label" for="ghost_mode_quick_pin2"><?php esc_html_e( 'Confirm PIN', 'ghost-mode' ); ?></label>
					<input class="ghost-mode-quick-modal__pin" type="password" inputmode="numeric" pattern="[0-9]*" maxlength="4" id="ghost_mode_quick_pin2" autocomplete="off" placeholder="••••">
					<p class="ghost-mode-quick-modal__error" id="ghost_mode_quick_error" hidden></p>
					<div class="ghost-mode-quick-modal__actions">
						<button type="button" class="button button-primary button-hero" id="ghost_mode_quick_create"><?php esc_html_e( 'Create my shortcut', 'ghost-mode' ); ?></button>
						<button type="button" class="button button-secondary button-hero" id="ghost_mode_quick_dismiss"><?php esc_html_e( 'Not now', 'ghost-mode' ); ?></button>
					</div>
				</div>
				<div data-step="done" hidden>
					<h2><?php esc_html_e( 'Nice — save this link!', 'ghost-mode' ); ?></h2>
					<p class="ghost-mode-quick-modal__lead">
						<?php esc_html_e( 'Bookmark it now (or copy it). On this device you can open it and sign in with your PIN only.', 'ghost-mode' ); ?>
					</p>
					<div class="ghost-mode-quick-modal__url-row">
						<input type="text" class="large-text" id="ghost_mode_quick_url" readonly value="">
						<button type="button" class="button" id="ghost_mode_quick_copy"><?php esc_html_e( 'Copy link', 'ghost-mode' ); ?></button>
					</div>
					<div class="ghost-mode-quick-modal__actions">
						<button type="button" class="button button-primary button-hero" id="ghost_mode_quick_saved"><?php esc_html_e( 'I’ve saved it', 'ghost-mode' ); ?></button>
					</div>
				</div>
				<div class="ghost-mode-modal__brand" aria-hidden="true">GLOWINGDARK CARBON DOME</div>
			</div>
		</div>
		<?php
	}

	public function ajax_create() {
		check_ajax_referer( 'ghost_mode_quick', 'nonce' );
		if ( ! is_user_logged_in() || ! self::is_enabled() ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized.', 'ghost-mode' ) ), 403 );
		}

		$user_id = get_current_user_id();
		$pin     = isset( $_POST['pin'] ) ? preg_replace( '/\D/', '', (string) wp_unslash( $_POST['pin'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$pin2    = isset( $_POST['pin2'] ) ? preg_replace( '/\D/', '', (string) wp_unslash( $_POST['pin2'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput

		if ( strlen( $pin ) !== 4 || $pin !== $pin2 ) {
			wp_send_json_error( array( 'message' => __( 'Enter a matching 4-digit PIN.', 'ghost-mode' ) ) );
		}

		$result = self::create_link( $user_id, $pin );
		if ( is_wp_error( $result ) ) {
			wp_send_json_error( array( 'message' => $result->get_error_message() ) );
		}

		delete_user_meta( $user_id, self::OFFER_META );

		wp_send_json_success(
			array(
				'url'     => $result['url'],
				'link_id' => $result['link_id'],
			)
		);
	}

	public function ajax_dismiss() {
		check_ajax_referer( 'ghost_mode_quick', 'nonce' );
		if ( ! is_user_logged_in() ) {
			wp_send_json_error( null, 403 );
		}
		delete_user_meta( get_current_user_id(), self::OFFER_META );
		wp_send_json_success();
	}

	public function handle_revoke() {
		if ( ! is_user_logged_in() ) {
			wp_die( esc_html__( 'Unauthorized', 'ghost-mode' ) );
		}
		check_admin_referer( 'ghost_mode_quick_revoke' );

		$link_id = isset( $_POST['link_id'] ) ? sanitize_text_field( wp_unslash( $_POST['link_id'] ) ) : '';
		$user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : get_current_user_id();

		if ( $user_id !== get_current_user_id() && ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized', 'ghost-mode' ) );
		}

		self::revoke_link( $user_id, $link_id );

		wp_safe_redirect( ghost_mode_get_settings_url( array( 'quick_revoked' => '1' ) ) );
		exit;
	}

	/**
	 * Create a new quick-login link for a user on this device.
	 *
	 * @param int    $user_id User ID.
	 * @param string $pin     4-digit PIN.
	 * @return array{url:string,link_id:string}|WP_Error
	 */
	public static function create_link( $user_id, $pin ) {
		$user_id = (int) $user_id;
		$pin     = preg_replace( '/\D/', '', (string) $pin );
		if ( $user_id <= 0 || strlen( $pin ) !== 4 ) {
			return new WP_Error( 'invalid', __( 'Invalid PIN.', 'ghost-mode' ) );
		}

		$links = self::get_links( $user_id );
		$links = self::prune_expired( $links, $user_id );

		// Replace existing link for this device if present.
		foreach ( $links as $i => $row ) {
			$lid = (string) ( $row['id'] ?? '' );
			if ( $lid !== '' && self::device_cookie_matches( $lid, (string) ( $row['device_hash'] ?? '' ) ) ) {
				self::remove_from_index( (string) ( $row['token_hash'] ?? '' ) );
				self::clear_device_cookie( $lid );
				unset( $links[ $i ] );
			}
		}
		$links = array_values( $links );

		if ( count( $links ) >= self::MAX_LINKS ) {
			return new WP_Error(
				'limit',
				__( 'You already have 3 device shortcuts. Revoke one in Ghost Mode settings first.', 'ghost-mode' )
			);
		}

		$raw_token    = self::generate_token();
		$token_hash   = self::hash_token( $raw_token );
		$device_secret = self::generate_token();
		$device_hash   = self::hash_token( $device_secret );
		$link_id      = function_exists( 'wp_generate_uuid4' ) ? wp_generate_uuid4() : uniqid( 'gmq_', true );
		$now          = time();
		$expires      = $now + ( self::TTL_DAYS * DAY_IN_SECONDS );

		$row = array(
			'id'           => $link_id,
			'token_hash'   => $token_hash,
			'device_hash'  => $device_hash,
			'pin_hash'     => wp_hash_password( $pin ),
			'created_at'   => $now,
			'expires_at'   => $expires,
			'last_used_at' => 0,
			'ua'           => self::truncate_ua(),
			'label'        => self::device_label(),
		);

		$links[] = $row;
		update_user_meta( $user_id, self::USER_META, $links );
		self::add_to_index( $token_hash, $user_id, $link_id );
		self::set_device_cookie( $link_id, $device_secret, $expires );

		return array(
			'url'     => self::get_url( $raw_token ),
			'link_id' => $link_id,
		);
	}

	/**
	 * @param int    $user_id User ID.
	 * @param string $link_id Link ID.
	 */
	public static function revoke_link( $user_id, $link_id ) {
		$user_id = (int) $user_id;
		$link_id = (string) $link_id;
		$links   = self::get_links( $user_id );
		$kept    = array();
		foreach ( $links as $row ) {
			if ( (string) ( $row['id'] ?? '' ) === $link_id ) {
				self::remove_from_index( (string) ( $row['token_hash'] ?? '' ) );
				self::clear_device_cookie( $link_id );
				continue;
			}
			$kept[] = $row;
		}
		update_user_meta( $user_id, self::USER_META, $kept );
	}

	/**
	 * @param int $user_id User ID.
	 * @return array<int, array<string, mixed>>
	 */
	public static function get_links( $user_id ) {
		$links = get_user_meta( (int) $user_id, self::USER_META, true );
		return is_array( $links ) ? $links : array();
	}

	/**
	 * Active (non-expired) links.
	 *
	 * @param int $user_id User ID.
	 * @return array<int, array<string, mixed>>
	 */
	public static function get_active_links( $user_id ) {
		$links = self::get_links( $user_id );
		$now   = time();
		$out   = array();
		foreach ( $links as $row ) {
			if ( absint( $row['expires_at'] ?? 0 ) > $now ) {
				$out[] = $row;
			}
		}
		return $out;
	}

	/**
	 * @param array<int, array<string, mixed>> $links   Links.
	 * @param int                              $user_id User ID.
	 * @return array<int, array<string, mixed>>
	 */
	public static function prune_expired( array $links, $user_id ) {
		$now  = time();
		$kept = array();
		foreach ( $links as $row ) {
			if ( absint( $row['expires_at'] ?? 0 ) <= $now ) {
				self::remove_from_index( (string) ( $row['token_hash'] ?? '' ) );
				continue;
			}
			$kept[] = $row;
		}
		if ( count( $kept ) !== count( $links ) ) {
			update_user_meta( (int) $user_id, self::USER_META, $kept );
		}
		return $kept;
	}

	/**
	 * @param string $raw_token Raw token.
	 * @return array{user_id:int,link:array<string,mixed>}|null
	 */
	public static function lookup_token( $raw_token ) {
		$token_hash = self::hash_token( $raw_token );
		$index      = self::get_index();
		if ( empty( $index[ $token_hash ] ) || ! is_array( $index[ $token_hash ] ) ) {
			return null;
		}
		$user_id = absint( $index[ $token_hash ]['user_id'] ?? 0 );
		$link_id = (string) ( $index[ $token_hash ]['link_id'] ?? '' );
		if ( $user_id <= 0 || $link_id === '' ) {
			return null;
		}

		$links = self::prune_expired( self::get_links( $user_id ), $user_id );
		foreach ( $links as $row ) {
			if ( (string) ( $row['id'] ?? '' ) === $link_id && (string) ( $row['token_hash'] ?? '' ) === $token_hash ) {
				if ( absint( $row['expires_at'] ?? 0 ) <= time() ) {
					return null;
				}
				return array(
					'user_id' => $user_id,
					'link'    => $row,
				);
			}
		}
		self::remove_from_index( $token_hash );
		return null;
	}

	/**
	 * @param int    $user_id User ID.
	 * @param string $link_id Link ID.
	 */
	public static function touch_link( $user_id, $link_id ) {
		$links = self::get_links( $user_id );
		foreach ( $links as $i => $row ) {
			if ( (string) ( $row['id'] ?? '' ) === (string) $link_id ) {
				$links[ $i ]['last_used_at'] = time();
				break;
			}
		}
		update_user_meta( (int) $user_id, self::USER_META, $links );
	}

	/**
	 * @param int $user_id User ID.
	 */
	public static function current_device_has_link( $user_id ) {
		foreach ( self::get_active_links( $user_id ) as $row ) {
			$lid = (string) ( $row['id'] ?? '' );
			if ( $lid !== '' && self::device_cookie_matches( $lid, (string) ( $row['device_hash'] ?? '' ) ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @param string $link_id     Link ID.
	 * @param string $device_hash Stored hash.
	 */
	public static function device_cookie_matches( $link_id, $device_hash ) {
		$cookie = self::COOKIE_PREFIX . preg_replace( '/[^a-zA-Z0-9_\-]/', '', (string) $link_id );
		if ( empty( $_COOKIE[ $cookie ] ) || $device_hash === '' ) {
			return false;
		}
		$secret = sanitize_text_field( wp_unslash( $_COOKIE[ $cookie ] ) );
		return hash_equals( $device_hash, self::hash_token( $secret ) );
	}

	/**
	 * @param string $link_id Link ID.
	 * @param string $secret  Device secret.
	 * @param int    $expires Expiry timestamp.
	 */
	public static function set_device_cookie( $link_id, $secret, $expires ) {
		$name = self::COOKIE_PREFIX . preg_replace( '/[^a-zA-Z0-9_\-]/', '', (string) $link_id );
		setcookie(
			$name,
			$secret,
			array(
				'expires'  => (int) $expires,
				'path'     => COOKIEPATH ? COOKIEPATH : '/',
				'domain'   => COOKIE_DOMAIN,
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);
		$_COOKIE[ $name ] = $secret;
	}

	/**
	 * @param string $link_id Link ID.
	 */
	public static function clear_device_cookie( $link_id ) {
		$name = self::COOKIE_PREFIX . preg_replace( '/[^a-zA-Z0-9_\-]/', '', (string) $link_id );
		setcookie(
			$name,
			'',
			array(
				'expires'  => time() - YEAR_IN_SECONDS,
				'path'     => COOKIEPATH ? COOKIEPATH : '/',
				'domain'   => COOKIE_DOMAIN,
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);
		unset( $_COOKIE[ $name ] );
	}

	/**
	 * @param string $pin      PIN.
	 * @param string $pin_hash Hash.
	 */
	public static function verify_pin( $pin, $pin_hash ) {
		if ( $pin_hash === '' || strlen( $pin ) !== 4 ) {
			return false;
		}
		return wp_check_password( $pin, $pin_hash );
	}

	public static function generate_token() {
		try {
			return bin2hex( random_bytes( self::TOKEN_BYTES ) );
		} catch ( Exception $e ) {
			return wp_generate_password( 64, false, false );
		}
	}

	/**
	 * @param string $raw Raw token/secret.
	 */
	public static function hash_token( $raw ) {
		return hash( 'sha256', (string) $raw );
	}

	/**
	 * @return array<string, array{user_id:int,link_id:string}>
	 */
	public static function get_index() {
		$index = get_option( self::INDEX_OPTION, array() );
		return is_array( $index ) ? $index : array();
	}

	/**
	 * @param string $token_hash Token hash.
	 * @param int    $user_id    User ID.
	 * @param string $link_id    Link ID.
	 */
	public static function add_to_index( $token_hash, $user_id, $link_id ) {
		$index = self::get_index();
		$index[ $token_hash ] = array(
			'user_id' => (int) $user_id,
			'link_id' => (string) $link_id,
		);
		update_option( self::INDEX_OPTION, $index, false );
	}

	/**
	 * @param string $token_hash Token hash.
	 */
	public static function remove_from_index( $token_hash ) {
		if ( $token_hash === '' ) {
			return;
		}
		$index = self::get_index();
		if ( isset( $index[ $token_hash ] ) ) {
			unset( $index[ $token_hash ] );
			update_option( self::INDEX_OPTION, $index, false );
		}
	}

	public static function truncate_ua() {
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		return substr( sanitize_text_field( $ua ), 0, 180 );
	}

	public static function device_label() {
		$ua = self::truncate_ua();
		$browser = __( 'Browser', 'ghost-mode' );
		$os      = '';
		if ( preg_match( '/Edg\//', $ua ) ) {
			$browser = 'Edge';
		} elseif ( preg_match( '/Chrome\//', $ua ) && ! preg_match( '/Edg\//', $ua ) ) {
			$browser = 'Chrome';
		} elseif ( preg_match( '/Firefox\//', $ua ) ) {
			$browser = 'Firefox';
		} elseif ( preg_match( '/Safari\//', $ua ) && ! preg_match( '/Chrome\//', $ua ) ) {
			$browser = 'Safari';
		}
		if ( preg_match( '/Windows/i', $ua ) ) {
			$os = 'Windows';
		} elseif ( preg_match( '/Mac OS X|Macintosh/i', $ua ) ) {
			$os = 'Mac';
		} elseif ( preg_match( '/Android/i', $ua ) ) {
			$os = 'Android';
		} elseif ( preg_match( '/iPhone|iPad/i', $ua ) ) {
			$os = 'iOS';
		} elseif ( preg_match( '/Linux/i', $ua ) ) {
			$os = 'Linux';
		}
		if ( $os !== '' ) {
			return sprintf( '%s on %s', $browser, $os );
		}
		return $browser;
	}
}
