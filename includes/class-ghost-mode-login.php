<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Ghost_Mode_Login {

	/** @var string[] */
	private $errors = array();

	/** @var string[] */
	private $messages = array();

	public function __construct() {
		add_action( 'parse_request', array( $this, 'maybe_flag_request' ), 1 );
		add_action( 'template_redirect', array( $this, 'maybe_serve_asset' ), 0 );
		add_action( 'template_redirect', array( $this, 'maybe_render_login' ), 0 );
	}

	/**
	 * Fallback when rewrite rules are stale or permalinks are plain.
	 *
	 * @param WP $wp WP request object.
	 */
	public function maybe_flag_request( $wp ) {
		if ( ! empty( $wp->query_vars['ghost_mode_login'] ) || ! empty( $wp->query_vars['ghost_mode_asset'] ) ) {
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

		$prefix = $slug . '/assets/';
		if ( strpos( $path, $prefix ) === 0 ) {
			$asset = sanitize_file_name( substr( $path, strlen( $prefix ) ) );
			if ( $asset !== '' ) {
				$wp->query_vars['ghost_mode_asset'] = $asset;
			}
			return;
		}

		if ( $path === $slug ) {
			$wp->query_vars['ghost_mode_login'] = 1;
		}
	}

	/**
	 * Serve CSS/JS/logo via /{slug}/assets/* so Network tab does not show /wp-content/.
	 */
	public function maybe_serve_asset() {
		$asset = (string) get_query_var( 'ghost_mode_asset' );
		if ( $asset === '' ) {
			return;
		}

		$asset = sanitize_file_name( $asset );
		$map   = array(
			'login.css' => array(
				'path' => GHOST_MODE_PATH . 'assets/ghost-mode-login.css',
				'type' => 'text/css; charset=UTF-8',
			),
			'login.js'  => array(
				'path' => GHOST_MODE_PATH . 'assets/ghost-mode-login.js',
				'type' => 'application/javascript; charset=UTF-8',
			),
		);

		if ( isset( $map[ $asset ] ) ) {
			$this->stream_local_file( $map[ $asset ]['path'], $map[ $asset ]['type'] );
		}

		if ( $asset === 'logo' || $asset === 'icon' ) {
			$this->stream_brand_image( $asset === 'icon' ? 'icon' : 'logo' );
		}

		status_header( 404 );
		exit;
	}

	/**
	 * @param string $path Absolute filesystem path.
	 * @param string $type Content-Type header.
	 */
	private function stream_local_file( $path, $type ) {
		if ( ! is_string( $path ) || $path === '' || ! is_readable( $path ) ) {
			status_header( 404 );
			exit;
		}

		nocache_headers();
		header( 'Content-Type: ' . $type );
		header( 'Content-Length: ' . (string) filesize( $path ) );
		header( 'X-Content-Type-Options: nosniff' );
		header( 'Cache-Control: public, max-age=86400' );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_readfile
		readfile( $path );
		exit;
	}

	/**
	 * Stream site logo or favicon without exposing the uploads path in HTML.
	 *
	 * @param string $kind logo|icon
	 */
	private function stream_brand_image( $kind ) {
		$file = $this->resolve_brand_file( $kind );
		if ( ! $file ) {
			status_header( 404 );
			exit;
		}

		$mime = wp_check_filetype( $file );
		$type = ! empty( $mime['type'] ) ? $mime['type'] : 'application/octet-stream';
		$this->stream_local_file( $file, $type );
	}

	/**
	 * @param string $kind logo|icon
	 * @return string Absolute path or empty.
	 */
	private function resolve_brand_file( $kind ) {
		$attachment_id = 0;
		if ( $kind === 'icon' ) {
			$attachment_id = (int) get_option( 'site_icon' );
		} else {
			$attachment_id = (int) get_theme_mod( 'custom_logo' );
			if ( ! $attachment_id ) {
				$attachment_id = (int) get_option( 'site_icon' );
			}
		}

		if ( $attachment_id > 0 ) {
			$path = get_attached_file( $attachment_id );
			if ( is_string( $path ) && $path !== '' && is_readable( $path ) ) {
				return $path;
			}
		}

		// Fallback: map a known local media URL to a filesystem path.
		$url = $kind === 'icon' ? get_site_icon_url( 192 ) : $this->get_logo_source_url();
		if ( ! is_string( $url ) || $url === '' ) {
			return '';
		}

		$uploads = wp_get_upload_dir();
		if ( empty( $uploads['baseurl'] ) || empty( $uploads['basedir'] ) ) {
			return '';
		}
		$baseurl = (string) $uploads['baseurl'];
		if ( strpos( $url, $baseurl ) !== 0 ) {
			return '';
		}
		$rel  = substr( $url, strlen( $baseurl ) );
		$path = $uploads['basedir'] . $rel;
		$path = wp_normalize_path( $path );
		$root = wp_normalize_path( (string) $uploads['basedir'] );
		if ( strpos( $path, $root ) !== 0 || ! is_readable( $path ) ) {
			return '';
		}
		return $path;
	}

	/**
	 * Serve the branded login page when the rewrite query var is set.
	 */
	public function maybe_render_login() {
		if ( (int) get_query_var( 'ghost_mode_login' ) !== 1 ) {
			return;
		}

		// Custom slug should work even when Ghost Mode is disabled (preview / testing).
		nocache_headers();

		$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : 'login'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		if ( $action === 'logout' ) {
			$this->handle_logout();
			return;
		}

		if ( is_user_logged_in() && ! in_array( $action, array( 'logout' ), true ) ) {
			$redirect = $this->get_redirect_to( admin_url() );
			wp_safe_redirect( $redirect );
			exit;
		}

		switch ( $action ) {
			case 'lostpassword':
				$this->handle_lostpassword();
				break;
			case 'rp':
			case 'resetpass':
				$this->handle_resetpass();
				break;
			case 'register':
				$this->handle_register();
				break;
			case 'login':
			default:
				$this->handle_login();
				break;
		}
	}

	private function handle_logout() {
		check_admin_referer( 'log-out' );
		wp_logout();
		$redirect = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : ghost_mode_get_login_url(); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		wp_safe_redirect( $redirect ? $redirect : ghost_mode_get_login_url() );
		exit;
	}

	private function handle_login() {
		if ( isset( $_GET['session'] ) && sanitize_key( wp_unslash( $_GET['session'] ) ) === 'expired' ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$this->messages[] = __( 'Your session expired. Please log in again.', 'ghost-mode' );
		}

		if ( Ghost_Mode_Lockout::is_request_blocked() ) {
			$this->errors[] = Ghost_Mode_Lockout::blocked_message();
			$this->render_page( 'login' );
			return;
		}

		if ( 'POST' === $_SERVER['REQUEST_METHOD'] ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			check_admin_referer( 'ghost_mode_login', 'ghost_mode_login_nonce' );

			if ( Ghost_Mode_Lockout::is_request_blocked() ) {
				$this->errors[] = Ghost_Mode_Lockout::blocked_message();
				$this->render_page( 'login' );
				return;
			}

			$creds = array(
				'user_login'    => isset( $_POST['log'] ) ? sanitize_text_field( wp_unslash( $_POST['log'] ) ) : '',
				'user_password' => isset( $_POST['pwd'] ) ? (string) wp_unslash( $_POST['pwd'] ) : '', // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
				'remember'      => ! empty( $_POST['rememberme'] ),
			);

			$user = wp_signon( $creds, is_ssl() );
			if ( is_wp_error( $user ) ) {
				// wp_login_failed already records via Ghost_Mode_Lockout; add remaining hint if not locked yet.
				if ( Ghost_Mode_Lockout::is_request_blocked() ) {
					$this->errors[] = Ghost_Mode_Lockout::blocked_message();
				} else {
					// Generic message so attackers cannot tell username vs password failures apart.
					$this->errors[] = $this->get_login_error_message( $user );
					$remaining      = Ghost_Mode_Lockout::remaining_attempts();
					if ( Ghost_Mode_Lockout::is_enabled() && $remaining > 0 ) {
						$this->errors[] = sprintf(
							/* translators: %d: remaining attempts */
							_n(
								'%d attempt remaining.',
								'%d attempts remaining.',
								$remaining,
								'ghost-mode'
							),
							$remaining
						);
					}
				}
			} else {
				Ghost_Mode_Lockout::clear_request_attempts();
				$redirect = $this->get_redirect_to( admin_url() );
				wp_safe_redirect( $redirect );
				exit;
			}
		}

		$this->render_page( 'login' );
	}

	private function handle_lostpassword() {
		if ( 'POST' === $_SERVER['REQUEST_METHOD'] ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			check_admin_referer( 'ghost_mode_lostpassword', 'ghost_mode_lostpassword_nonce' );

			$user_login = isset( $_POST['user_login'] ) ? sanitize_text_field( wp_unslash( $_POST['user_login'] ) ) : '';
			$result     = retrieve_password( $user_login );

			if ( true === $result ) {
				$this->messages[] = __( 'Check your email for the confirmation link.', 'ghost-mode' );
			} elseif ( is_wp_error( $result ) ) {
				foreach ( $result->get_error_messages() as $msg ) {
					$this->errors[] = $msg;
				}
			} else {
				$this->errors[] = __( 'Unable to send password reset email.', 'ghost-mode' );
			}
		}

		$this->render_page( 'lostpassword' );
	}

	private function handle_resetpass() {
		$rp_key   = isset( $_REQUEST['key'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['key'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$rp_login = isset( $_REQUEST['login'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['login'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		$user = check_password_reset_key( $rp_key, $rp_login );
		if ( is_wp_error( $user ) ) {
			$this->errors[] = __( 'This password reset link is invalid or has expired.', 'ghost-mode' );
			$this->render_page( 'lostpassword' );
			return;
		}

		if ( 'POST' === $_SERVER['REQUEST_METHOD'] ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			check_admin_referer( 'ghost_mode_resetpass', 'ghost_mode_resetpass_nonce' );

			$pass1 = isset( $_POST['pass1'] ) ? (string) wp_unslash( $_POST['pass1'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			$pass2 = isset( $_POST['pass2'] ) ? (string) wp_unslash( $_POST['pass2'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized

			$errors = new WP_Error();
			if ( $pass1 === '' || $pass2 === '' ) {
				$errors->add( 'password_reset_empty', __( 'Please enter a password.', 'ghost-mode' ) );
			} elseif ( $pass1 !== $pass2 ) {
				$errors->add( 'password_reset_mismatch', __( 'The passwords do not match.', 'ghost-mode' ) );
			}

			do_action( 'validate_password_reset', $errors, $user );

			if ( $errors->has_errors() ) {
				foreach ( $errors->get_error_messages() as $msg ) {
					$this->errors[] = $msg;
				}
			} else {
				reset_password( $user, $pass1 );
				$this->messages[] = __( 'Your password has been reset. You can log in now.', 'ghost-mode' );
				$this->render_page( 'login' );
				return;
			}
		}

		$this->render_page(
			'resetpass',
			array(
				'rp_key'   => $rp_key,
				'rp_login' => $rp_login,
			)
		);
	}

	private function handle_register() {
		if ( ! get_option( 'users_can_register' ) ) {
			$this->errors[] = __( 'Registration is currently closed.', 'ghost-mode' );
			$this->render_page( 'login' );
			return;
		}

		if ( 'POST' === $_SERVER['REQUEST_METHOD'] ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			check_admin_referer( 'ghost_mode_register', 'ghost_mode_register_nonce' );

			$user_login = isset( $_POST['user_login'] ) ? sanitize_user( wp_unslash( $_POST['user_login'] ) ) : '';
			$user_email = isset( $_POST['user_email'] ) ? sanitize_email( wp_unslash( $_POST['user_email'] ) ) : '';

			$result = register_new_user( $user_login, $user_email );
			if ( is_wp_error( $result ) ) {
				foreach ( $result->get_error_messages() as $msg ) {
					$this->errors[] = $msg;
				}
			} else {
				$this->messages[] = __( 'Registration complete. Check your email for your login details.', 'ghost-mode' );
				$this->render_page( 'login' );
				return;
			}
		}

		$this->render_page( 'register' );
	}

	/**
	 * Map WordPress auth errors to a single generic credentials message.
	 *
	 * @param WP_Error $error Sign-on error.
	 * @return string
	 */
	private function get_login_error_message( WP_Error $error ) {
		$credential_codes = array(
			'invalid_username',
			'invalid_email',
			'incorrect_password',
			'authentication_failed',
			'invalidcombo',
		);

		foreach ( $error->get_error_codes() as $code ) {
			if ( in_array( $code, $credential_codes, true ) ) {
				return __( 'Invalid credentials. Please check your username/email and password and try again.', 'ghost-mode' );
			}
		}

		// Empty fields and other non-enumerating messages can stay as WordPress provides them.
		$message = $error->get_error_message();
		return $message !== ''
			? $message
			: __( 'Invalid credentials. Please check your username/email and password and try again.', 'ghost-mode' );
	}

	/**
	 * @param string $default Default redirect.
	 */
	private function get_redirect_to( $default ) {
		$redirect = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( $redirect === '' ) {
			return $default;
		}
		// Avoid redirecting back to login.
		if ( strpos( $redirect, 'wp-login.php' ) !== false ) {
			return $default;
		}
		$slug = ghost_mode_sanitize_slug( ghost_mode_get_settings()['login_slug'] ?? '' );
		if ( $slug && strpos( $redirect, '/' . $slug ) !== false ) {
			return $default;
		}
		return $redirect;
	}

	/**
	 * Public entry for device-bound PIN login view.
	 *
	 * @param string   $token    Raw quick-login token.
	 * @param string[] $errors   Error messages.
	 * @param string[] $messages Info messages.
	 */
	public function render_pin_view( $token, array $errors = array(), array $messages = array() ) {
		$this->errors   = $errors;
		$this->messages = $messages;
		$this->render_page(
			'pin',
			array(
				'quick_token' => preg_replace( '/[^a-zA-Z0-9]/', '', (string) $token ),
			)
		);
	}

	/**
	 * @param string               $view View key.
	 * @param array<string,string> $extra Extra template vars.
	 */
	private function render_page( $view, $extra = array() ) {
		$settings = ghost_mode_get_settings();
		$site     = get_bloginfo( 'name' );
		$logo_url = $this->get_logo_source_url() ? ghost_mode_get_login_asset_url( 'logo' ) : '';
		$can_reg  = (bool) get_option( 'users_can_register' );

		$status = array();
		foreach ( $this->errors as $err ) {
			$status[] = array(
				'type' => 'error',
				'text' => $err,
			);
		}
		foreach ( $this->messages as $msg ) {
			$status[] = array(
				'type' => 'success',
				'text' => $msg,
			);
		}

		$titles = array(
			'login'        => __( 'Login', 'ghost-mode' ),
			'lostpassword' => __( 'Forgot Password', 'ghost-mode' ),
			'resetpass'    => __( 'Reset Password', 'ghost-mode' ),
			'register'     => __( 'Create Account', 'ghost-mode' ),
			'pin'          => __( 'Welcome back', 'ghost-mode' ),
		);
		$page_title = $titles[ $view ] ?? $titles['login'];

		header( 'Content-Type: text/html; charset=' . get_bloginfo( 'charset' ) );
		?>
<!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
	<meta charset="<?php bloginfo( 'charset' ); ?>">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<meta name="robots" content="noindex, nofollow">
	<title><?php echo esc_html( $page_title . ' — ' . $site ); ?></title>
	<?php $this->print_theme_color_vars(); ?>
	<link rel="stylesheet" href="<?php echo esc_url( ghost_mode_get_login_asset_url( 'login.css' ) ); ?>">
	<?php if ( (int) get_option( 'site_icon' ) > 0 || get_site_icon_url( 32 ) ) : ?>
		<link rel="icon" href="<?php echo esc_url( ghost_mode_get_login_asset_url( 'icon' ) ); ?>">
	<?php endif; ?>
</head>
<body class="ghost-mode-body ghost-mode-view-<?php echo esc_attr( $view ); ?>">
	<header class="ghost-mode-brand">
		<a class="ghost-mode-brand-link" href="<?php echo esc_url( home_url( '/' ) ); ?>">
			<?php if ( $logo_url ) : ?>
				<img class="ghost-mode-brand-logo" src="<?php echo esc_url( $logo_url ); ?>" alt="<?php echo esc_attr( $site ); ?>">
			<?php endif; ?>
			<span class="ghost-mode-brand-name"><?php echo esc_html( $site ); ?></span>
		</a>
	</header>

	<main class="ghost-mode-main">
		<div class="ghost-mode-card">
			<?php if ( $view === 'login' ) : ?>
				<h1 class="ghost-mode-title"><?php esc_html_e( 'Login', 'ghost-mode' ); ?></h1>
				<p class="ghost-mode-subtitle"><?php esc_html_e( 'Hi, Welcome back', 'ghost-mode' ); ?></p>
			<?php elseif ( $view === 'pin' ) : ?>
				<h1 class="ghost-mode-title"><?php esc_html_e( 'Welcome back', 'ghost-mode' ); ?></h1>
				<p class="ghost-mode-subtitle"><?php esc_html_e( 'Enter your 4-digit PIN to continue.', 'ghost-mode' ); ?></p>
			<?php elseif ( $view === 'lostpassword' ) : ?>
				<h1 class="ghost-mode-title"><?php esc_html_e( 'Forgot Password', 'ghost-mode' ); ?></h1>
				<p class="ghost-mode-subtitle"><?php esc_html_e( 'Enter your email or username and we will send a reset link.', 'ghost-mode' ); ?></p>
			<?php elseif ( $view === 'resetpass' ) : ?>
				<h1 class="ghost-mode-title"><?php esc_html_e( 'Reset Password', 'ghost-mode' ); ?></h1>
				<p class="ghost-mode-subtitle"><?php esc_html_e( 'Choose a new password for your account.', 'ghost-mode' ); ?></p>
			<?php else : ?>
				<h1 class="ghost-mode-title"><?php esc_html_e( 'Create Account', 'ghost-mode' ); ?></h1>
				<p class="ghost-mode-subtitle"><?php esc_html_e( 'Register a new account to get started.', 'ghost-mode' ); ?></p>
			<?php endif; ?>

			<?php foreach ( $status as $item ) : ?>
				<div class="ghost-mode-alert ghost-mode-alert--<?php echo esc_attr( $item['type'] ); ?>">
					<?php echo wp_kses_post( $item['text'] ); ?>
				</div>
			<?php endforeach; ?>

			<?php
			if ( $view === 'login' ) {
				$this->render_login_form( $settings );
			} elseif ( $view === 'pin' ) {
				$this->render_pin_form( $extra );
			} elseif ( $view === 'lostpassword' ) {
				$this->render_lostpassword_form();
			} elseif ( $view === 'resetpass' ) {
				$this->render_resetpass_form( $extra );
			} elseif ( $view === 'register' ) {
				$this->render_register_form();
			}
			?>

			<?php if ( $view === 'login' && $can_reg ) : ?>
				<p class="ghost-mode-footer">
					<?php esc_html_e( 'Not registered yet?', 'ghost-mode' ); ?>
					<a href="<?php echo esc_url( ghost_mode_get_login_url( 'register' ) ); ?>">
						<?php esc_html_e( 'Create an account', 'ghost-mode' ); ?>
						<span class="ghost-mode-footer-arrow" aria-hidden="true">↗</span>
					</a>
				</p>
			<?php elseif ( $view === 'pin' ) : ?>
				<p class="ghost-mode-footer">
					<a href="<?php echo esc_url( ghost_mode_get_login_url() ); ?>">
						<?php esc_html_e( 'Use password instead', 'ghost-mode' ); ?>
						<span class="ghost-mode-footer-arrow" aria-hidden="true">↗</span>
					</a>
				</p>
			<?php elseif ( $view === 'register' ) : ?>
				<p class="ghost-mode-footer">
					<?php esc_html_e( 'Already have an account?', 'ghost-mode' ); ?>
					<a href="<?php echo esc_url( ghost_mode_get_login_url() ); ?>">
						<?php esc_html_e( 'Login', 'ghost-mode' ); ?>
						<span class="ghost-mode-footer-arrow" aria-hidden="true">↗</span>
					</a>
				</p>
			<?php elseif ( in_array( $view, array( 'lostpassword', 'resetpass' ), true ) ) : ?>
				<p class="ghost-mode-footer">
					<a href="<?php echo esc_url( ghost_mode_get_login_url() ); ?>">
						<?php esc_html_e( 'Back to Login', 'ghost-mode' ); ?>
						<span class="ghost-mode-footer-arrow" aria-hidden="true">↗</span>
					</a>
				</p>
			<?php endif; ?>
		</div>
	</main>

	<script src="<?php echo esc_url( ghost_mode_get_login_asset_url( 'login.js' ) ); ?>"></script>
</body>
</html>
		<?php
		exit;
	}

	/**
	 * @param array<string,string> $extra Extra vars (quick_token).
	 */
	private function render_pin_form( $extra ) {
		$token  = (string) ( $extra['quick_token'] ?? '' );
		$action = Ghost_Mode_Quick_Login::get_url( $token );
		?>
		<form class="ghost-mode-form ghost-mode-form--pin" method="post" action="<?php echo esc_url( $action ); ?>" novalidate>
			<?php wp_nonce_field( 'ghost_mode_quick_pin', 'ghost_mode_quick_pin_nonce' ); ?>
			<label class="ghost-mode-label" for="ghost_mode_pin"><?php esc_html_e( 'PIN', 'ghost-mode' ); ?></label>
			<input
				class="ghost-mode-input ghost-mode-input--pin"
				type="password"
				name="pin"
				id="ghost_mode_pin"
				inputmode="numeric"
				pattern="[0-9]*"
				maxlength="4"
				autocomplete="one-time-code"
				placeholder="••••"
				required
			>
			<button type="submit" class="ghost-mode-btn"><?php esc_html_e( 'Continue', 'ghost-mode' ); ?></button>
		</form>
		<?php
	}

	/**
	 * @param array $settings Settings.
	 */
	private function render_login_form( $settings ) {
		$redirect = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : admin_url(); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$remember = ( $settings['remember_me_default'] ?? 'no' ) === 'yes';
		?>
		<form class="ghost-mode-form" method="post" action="<?php echo esc_url( ghost_mode_get_login_url() ); ?>" novalidate>
			<?php wp_nonce_field( 'ghost_mode_login', 'ghost_mode_login_nonce' ); ?>
			<input type="hidden" name="redirect_to" value="<?php echo esc_attr( $redirect ); ?>">

			<label class="ghost-mode-label" for="ghost_mode_log"><?php esc_html_e( 'Email', 'ghost-mode' ); ?></label>
			<input
				class="ghost-mode-input"
				type="text"
				name="log"
				id="ghost_mode_log"
				autocomplete="username"
				placeholder="<?php esc_attr_e( 'E.g. johndoe@email.com', 'ghost-mode' ); ?>"
				required
			>

			<label class="ghost-mode-label" for="ghost_mode_pwd"><?php esc_html_e( 'Password', 'ghost-mode' ); ?></label>
			<div class="ghost-mode-password-wrap">
				<input
					class="ghost-mode-input"
					type="password"
					name="pwd"
					id="ghost_mode_pwd"
					autocomplete="current-password"
					placeholder="<?php esc_attr_e( 'Enter your password', 'ghost-mode' ); ?>"
					required
				>
				<button type="button" class="ghost-mode-toggle-password" data-target="ghost_mode_pwd" aria-label="<?php esc_attr_e( 'Show password', 'ghost-mode' ); ?>" aria-pressed="false">
					<svg class="ghost-mode-eye-open" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z"/><circle cx="12" cy="12" r="3"/></svg>
					<svg class="ghost-mode-eye-closed" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 19c-7 0-11-7-11-7a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 7 11 7a18.5 18.5 0 0 1-2.16 3.19M1 1l22 22"/><path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"/></svg>
				</button>
			</div>

			<div class="ghost-mode-row">
				<label class="ghost-mode-remember">
					<input type="checkbox" name="rememberme" value="forever" <?php checked( $remember ); ?>>
					<span><?php esc_html_e( 'Remember Me', 'ghost-mode' ); ?></span>
				</label>
				<a class="ghost-mode-link" href="<?php echo esc_url( ghost_mode_get_login_url( 'lostpassword' ) ); ?>">
					<?php esc_html_e( 'Forgot Password?', 'ghost-mode' ); ?>
				</a>
			</div>

			<button type="submit" class="ghost-mode-btn"><?php esc_html_e( 'Login', 'ghost-mode' ); ?></button>
		</form>
		<?php
	}

	private function render_lostpassword_form() {
		?>
		<form class="ghost-mode-form" method="post" action="<?php echo esc_url( ghost_mode_get_login_url( 'lostpassword' ) ); ?>">
			<?php wp_nonce_field( 'ghost_mode_lostpassword', 'ghost_mode_lostpassword_nonce' ); ?>
			<label class="ghost-mode-label" for="ghost_mode_user_login"><?php esc_html_e( 'Email or Username', 'ghost-mode' ); ?></label>
			<input
				class="ghost-mode-input"
				type="text"
				name="user_login"
				id="ghost_mode_user_login"
				autocomplete="username"
				placeholder="<?php esc_attr_e( 'E.g. johndoe@email.com', 'ghost-mode' ); ?>"
				required
			>
			<button type="submit" class="ghost-mode-btn"><?php esc_html_e( 'Send Reset Link', 'ghost-mode' ); ?></button>
		</form>
		<?php
	}

	/**
	 * @param array<string,string> $extra Extra vars.
	 */
	private function render_resetpass_form( $extra ) {
		$action = ghost_mode_get_login_url(
			'resetpass',
			array(
				'key'   => $extra['rp_key'] ?? '',
				'login' => $extra['rp_login'] ?? '',
			)
		);
		?>
		<form class="ghost-mode-form" method="post" action="<?php echo esc_url( $action ); ?>">
			<?php wp_nonce_field( 'ghost_mode_resetpass', 'ghost_mode_resetpass_nonce' ); ?>
			<input type="hidden" name="rp_key" value="<?php echo esc_attr( $extra['rp_key'] ?? '' ); ?>">
			<input type="hidden" name="rp_login" value="<?php echo esc_attr( $extra['rp_login'] ?? '' ); ?>">

			<label class="ghost-mode-label" for="ghost_mode_pass1"><?php esc_html_e( 'New Password', 'ghost-mode' ); ?></label>
			<div class="ghost-mode-password-wrap">
				<input class="ghost-mode-input" type="password" name="pass1" id="ghost_mode_pass1" autocomplete="new-password" required>
				<button type="button" class="ghost-mode-toggle-password" data-target="ghost_mode_pass1" aria-label="<?php esc_attr_e( 'Show password', 'ghost-mode' ); ?>" aria-pressed="false">
					<svg class="ghost-mode-eye-open" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z"/><circle cx="12" cy="12" r="3"/></svg>
					<svg class="ghost-mode-eye-closed" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 19c-7 0-11-7-11-7a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 7 11 7a18.5 18.5 0 0 1-2.16 3.19M1 1l22 22"/><path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"/></svg>
				</button>
			</div>

			<label class="ghost-mode-label" for="ghost_mode_pass2"><?php esc_html_e( 'Confirm Password', 'ghost-mode' ); ?></label>
			<input class="ghost-mode-input" type="password" name="pass2" id="ghost_mode_pass2" autocomplete="new-password" required>

			<button type="submit" class="ghost-mode-btn"><?php esc_html_e( 'Save Password', 'ghost-mode' ); ?></button>
		</form>
		<?php
	}

	private function render_register_form() {
		?>
		<form class="ghost-mode-form" method="post" action="<?php echo esc_url( ghost_mode_get_login_url( 'register' ) ); ?>">
			<?php wp_nonce_field( 'ghost_mode_register', 'ghost_mode_register_nonce' ); ?>

			<label class="ghost-mode-label" for="ghost_mode_user_login_reg"><?php esc_html_e( 'Username', 'ghost-mode' ); ?></label>
			<input class="ghost-mode-input" type="text" name="user_login" id="ghost_mode_user_login_reg" autocomplete="username" required>

			<label class="ghost-mode-label" for="ghost_mode_user_email"><?php esc_html_e( 'Email', 'ghost-mode' ); ?></label>
			<input class="ghost-mode-input" type="email" name="user_email" id="ghost_mode_user_email" autocomplete="email" placeholder="<?php esc_attr_e( 'E.g. johndoe@email.com', 'ghost-mode' ); ?>" required>

			<button type="submit" class="ghost-mode-btn"><?php esc_html_e( 'Create Account', 'ghost-mode' ); ?></button>
		</form>
		<?php
	}

	/**
	 * Real media URL used only to resolve a local file for the asset proxy.
	 */
	private function get_logo_source_url() {
		$custom_logo_id = (int) get_theme_mod( 'custom_logo' );
		if ( $custom_logo_id ) {
			$url = wp_get_attachment_image_url( $custom_logo_id, 'full' );
			if ( $url ) {
				return $url;
			}
		}
		if ( function_exists( 'gdnb_get_logo_fallback_url' ) ) {
			$fallback = gdnb_get_logo_fallback_url();
			if ( is_string( $fallback ) && $fallback !== '' ) {
				return $fallback;
			}
		}
		$icon = get_site_icon_url( 192 );
		return $icon ? $icon : '';
	}

	/**
	 * Inject HSF / Theme Settings color variables for the standalone page.
	 */
	private function print_theme_color_vars() {
		$brand       = '#1f9d6a';
		$brand_dark  = '#16714c';
		$brand_blue  = '#195b9b';
		$brand_blue_d = '#123f71';
		$ink         = '#132238';
		$body        = '#526277';
		$muted       = '#8091a7';

		$theme_settings = get_option( 'gdnb_theme_settings', array() );
		if ( is_array( $theme_settings ) ) {
			if ( ! empty( $theme_settings['color_brand'] ) ) {
				$brand = sanitize_hex_color( $theme_settings['color_brand'] ) ?: $brand;
			}
			if ( ! empty( $theme_settings['color_brand_dark'] ) ) {
				$brand_dark = sanitize_hex_color( $theme_settings['color_brand_dark'] ) ?: $brand_dark;
			}
			if ( ! empty( $theme_settings['color_brand_blue'] ) ) {
				$brand_blue = sanitize_hex_color( $theme_settings['color_brand_blue'] ) ?: $brand_blue;
			}
		}

		echo '<style id="ghost-mode-theme-vars">:root{';
		echo '--rpf-brand:' . esc_html( $brand ) . ';';
		echo '--rpf-brand-dark:' . esc_html( $brand_dark ) . ';';
		echo '--rpf-brand-blue:' . esc_html( $brand_blue ) . ';';
		echo '--rpf-brand-blue-dark:' . esc_html( $brand_blue_d ) . ';';
		echo '--rpf-ink:' . esc_html( $ink ) . ';';
		echo '--rpf-body:' . esc_html( $body ) . ';';
		echo '--rpf-muted:' . esc_html( $muted ) . ';';
		echo '}</style>';
	}
}
