<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Ghost_Mode_Settings {

	public function __construct() {
		add_action( 'admin_menu', array( $this, 'register_menu' ), 26 );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_action( 'admin_head', array( $this, 'print_menu_styles' ) );
		add_action( 'admin_print_styles-plugins.php', array( $this, 'print_plugins_list_icon' ) );
		add_action( 'admin_post_ghost_mode_regenerate_unlock', array( $this, 'handle_regenerate_unlock' ) );
		add_action( 'update_option_' . GHOST_MODE_SETTINGS_OPTION, array( $this, 'maybe_flush_rewrites' ), 10, 2 );
	}

	public function register_menu() {
		$menu_title = ghost_mode_menu_title( __( 'Ghost Mode', 'ghost-mode' ) );

		// Soft complement: nest under NGOBuddy when present; otherwise top-level with lock icon.
		if ( ghost_mode_is_ngobuddy_active() ) {
			add_submenu_page(
				'ngobuddy',
				__( 'Ghost Mode', 'ghost-mode' ),
				$menu_title,
				'manage_options',
				'ghost-mode',
				array( $this, 'render_page' )
			);
			return;
		}

		add_menu_page(
			__( 'Ghost Mode', 'ghost-mode' ),
			$menu_title,
			'manage_options',
			'ghost-mode',
			array( $this, 'render_page' ),
			'dashicons-lock',
			58
		);
	}

	/**
	 * Red alert dot next to Ghost Mode menu labels.
	 */
	public function print_menu_styles() {
		?>
		<style id="ghost-mode-menu-css">
			#adminmenu .ghost-mode-menu-dot,
			#adminmenu .wp-submenu .ghost-mode-menu-dot {
				display: inline-block;
				width: 8px;
				height: 8px;
				margin-left: 6px;
				border-radius: 50%;
				background: #d63638;
				vertical-align: middle;
				box-shadow: 0 0 0 1px rgba(0,0,0,.15);
			}
			#adminmenu #toplevel_page_ghost-mode .wp-menu-image:before {
				content: "\f160";
			}
		</style>
		<?php
	}

	/**
	 * Show the lock mark on the Plugins list row.
	 */
	public function print_plugins_list_icon() {
		$icon = esc_url( ghost_mode_get_icon_url() );
		?>
		<style id="ghost-mode-plugins-icon-css">
			.plugins tr[data-plugin="ghost-mode/ghost-mode.php"] .plugin-title .ghost-mode-plugin-icon,
			.plugins tr[data-slug="ghost-mode"] .plugin-title .ghost-mode-plugin-icon {
				display: inline-block;
				width: 28px;
				height: 28px;
				margin: 0 8px 0 0;
				vertical-align: middle;
				background: url("<?php echo $icon; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>") no-repeat center / contain;
				border-radius: 6px;
			}
		</style>
		<script>
		(function () {
			document.querySelectorAll('.plugins tr[data-plugin="ghost-mode/ghost-mode.php"] .plugin-title strong, .plugins tr[data-plugin*="ghost-mode.php"] .plugin-title strong').forEach(function (el) {
				if (el.querySelector('.ghost-mode-plugin-icon')) { return; }
				var mark = document.createElement('span');
				mark.className = 'ghost-mode-plugin-icon';
				mark.setAttribute('aria-hidden', 'true');
				el.insertBefore(mark, el.firstChild);
			});
		})();
		</script>
		<?php
	}

	public function register_settings() {
		register_setting(
			'ghost_mode_settings_group',
			GHOST_MODE_SETTINGS_OPTION,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_settings' ),
				'default'           => array(),
			)
		);
	}

	/**
	 * @param array $input Raw input.
	 * @return array
	 */
	public function sanitize_settings( $input ) {
		$prev = ghost_mode_get_settings();
		if ( ! is_array( $input ) ) {
			$input = array();
		}

		$output = $prev;

		$output['enabled'] = ( isset( $input['enabled'] ) && $input['enabled'] === 'yes' ) ? 'yes' : 'no';

		$slug = ghost_mode_sanitize_slug( $input['login_slug'] ?? '' );
		if ( $slug === '' ) {
			$slug = ghost_mode_sanitize_slug( $prev['login_slug'] );
			if ( $slug === '' ) {
				$slug = 'secure-gate';
			}
			add_settings_error(
				'ghost_mode_settings',
				'invalid_slug',
				__( 'Login slug was invalid. Kept the previous valid slug.', 'ghost-mode' ),
				'error'
			);
			$output['enabled'] = 'no';
		} else {
			$conflict = $this->slug_conflicts( $slug );
			if ( $conflict ) {
				add_settings_error(
					'ghost_mode_settings',
					'slug_conflict',
					sprintf(
						/* translators: %s: conflicting content type */
						__( 'Login slug conflicts with an existing %s. Choose a different slug. Ghost Mode was not enabled.', 'ghost-mode' ),
						$conflict
					),
					'error'
				);
				if ( isset( $input['enabled'] ) && $input['enabled'] === 'yes' ) {
					$output['enabled'] = 'no';
				}
			}
		}
		$output['login_slug'] = $slug;

		// Preserve unlock key unless empty (then regenerate).
		$key = isset( $input['unlock_key'] ) ? sanitize_text_field( (string) $input['unlock_key'] ) : (string) ( $prev['unlock_key'] ?? '' );
		if ( $key === '' ) {
			$key = ghost_mode_generate_unlock_key();
		}
		$output['unlock_key'] = $key;

		$output['remember_me_default'] = ( isset( $input['remember_me_default'] ) && $input['remember_me_default'] === 'yes' ) ? 'yes' : 'no';
		$output['lockout_enabled']     = ( isset( $input['lockout_enabled'] ) && $input['lockout_enabled'] === 'yes' ) ? 'yes' : 'no';

		$max = isset( $input['max_login_attempts'] ) ? absint( $input['max_login_attempts'] ) : Ghost_Mode_Lockout::MAX_ATTEMPTS;
		$output['max_login_attempts'] = max( 1, min( 50, $max ? $max : Ghost_Mode_Lockout::MAX_ATTEMPTS ) );

		$output['session_logging'] = ( isset( $input['session_logging'] ) && $input['session_logging'] === 'yes' ) ? 'yes' : 'no';
		$timeout                   = isset( $input['session_timeout_minutes'] ) ? absint( $input['session_timeout_minutes'] ) : 60;
		$output['session_timeout_minutes'] = min( 10080, $timeout ); // max 7 days; 0 = no forced timeout

		$output['login_alert_enabled']      = ( isset( $input['login_alert_enabled'] ) && $input['login_alert_enabled'] === 'yes' ) ? 'yes' : 'no';
		$output['login_alert_notify_user']  = ( isset( $input['login_alert_notify_user'] ) && $input['login_alert_notify_user'] === 'yes' ) ? 'yes' : 'no';
		$output['login_alert_notify_admin'] = ( isset( $input['login_alert_notify_admin'] ) && $input['login_alert_notify_admin'] === 'yes' ) ? 'yes' : 'no';

		$extra = isset( $input['login_alert_extra_emails'] ) ? (string) $input['login_alert_extra_emails'] : '';
		$extra_clean = array();
		foreach ( preg_split( '/[\s,;]+/', $extra ) as $email ) {
			$email = sanitize_email( $email );
			if ( is_email( $email ) ) {
				$extra_clean[] = $email;
			}
		}
		$output['login_alert_extra_emails'] = implode( ', ', array_unique( $extra_clean ) );
		$output['attempt_review_enabled']   = ( isset( $input['attempt_review_enabled'] ) && $input['attempt_review_enabled'] === 'yes' ) ? 'yes' : 'no';
		$output['quick_login_enabled']      = ( isset( $input['quick_login_enabled'] ) && $input['quick_login_enabled'] === 'yes' ) ? 'yes' : 'no';
		$output['password_age_enabled']     = ( isset( $input['password_age_enabled'] ) && $input['password_age_enabled'] === 'yes' ) ? 'yes' : 'no';
		$age_days = isset( $input['password_age_days'] ) ? absint( $input['password_age_days'] ) : Ghost_Mode_Password_Age::DEFAULT_DAYS;
		$output['password_age_days'] = max( 1, min( 3650, $age_days ? $age_days : Ghost_Mode_Password_Age::DEFAULT_DAYS ) );

		if ( $output['enabled'] === 'yes' ) {
			add_settings_error(
				'ghost_mode_settings',
				'ghost_enabled',
				__( 'Ghost Mode is enabled. Bookmark your custom login URL and unlock URL before leaving this page.', 'ghost-mode' ),
				'success'
			);
		}

		return $output;
	}

	/**
	 * @param string $slug Login slug.
	 * @return string Empty or conflict label.
	 */
	private function slug_conflicts( $slug ) {
		$page = get_page_by_path( $slug );
		if ( $page instanceof WP_Post ) {
			return __( 'page', 'ghost-mode' );
		}

		$post = get_posts(
			array(
				'name'        => $slug,
				'post_type'   => 'post',
				'post_status' => 'publish',
				'numberposts' => 1,
			)
		);
		if ( ! empty( $post ) ) {
			return __( 'post', 'ghost-mode' );
		}

		return '';
	}

	/**
	 * Flush rewrite rules when slug or enabled state changes.
	 *
	 * @param mixed $old Previous value.
	 * @param mixed $new New value.
	 */
	public function maybe_flush_rewrites( $old, $new ) {
		$old_slug = is_array( $old ) ? ghost_mode_sanitize_slug( $old['login_slug'] ?? '' ) : '';
		$new_slug = is_array( $new ) ? ghost_mode_sanitize_slug( $new['login_slug'] ?? '' ) : '';
		$old_on   = is_array( $old ) && ( $old['enabled'] ?? 'no' ) === 'yes';
		$new_on   = is_array( $new ) && ( $new['enabled'] ?? 'no' ) === 'yes';

		if ( $old_slug !== $new_slug || $old_on !== $new_on ) {
			Ghost_Mode_Security::register_rewrite_rules();
			flush_rewrite_rules( false );
		}
	}

	public function handle_regenerate_unlock() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized', 'ghost-mode' ) );
		}
		check_admin_referer( 'ghost_mode_regenerate_unlock' );

		$settings               = ghost_mode_get_settings();
		$settings['unlock_key'] = ghost_mode_generate_unlock_key();
		update_option( GHOST_MODE_SETTINGS_OPTION, $settings, false );

		wp_safe_redirect(
			ghost_mode_get_settings_url(
				array(
					'unlock_regenerated' => '1',
				)
			)
		);
		exit;
	}

	public function enqueue_assets( $hook ) {
		$allowed = array( 'ngobuddy_page_ghost-mode', 'settings_page_ghost-mode', 'toplevel_page_ghost-mode' );
		if ( ! in_array( $hook, $allowed, true ) ) {
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
	}

	public function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized', 'ghost-mode' ) );
		}

		$settings   = ghost_mode_get_settings();
		$login_url  = ghost_mode_get_login_url();
		$unlock_url = ghost_mode_get_unlock_url();
		$is_active  = ghost_mode_is_active();

		if ( isset( $_GET['unlock_regenerated'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Emergency unlock key regenerated. Update your bookmarks.', 'ghost-mode' ) . '</p></div>';
		}
		if ( isset( $_GET['unblocked'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Block removed.', 'ghost-mode' ) . '</p></div>';
		}
		if ( isset( $_GET['unblocked_all'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'All blocks cleared.', 'ghost-mode' ) . '</p></div>';
		}
		if ( isset( $_GET['attempts_cleared'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Failed-attempt counters cleared.', 'ghost-mode' ) . '</p></div>';
		}
		if ( isset( $_GET['quick_revoked'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Quick login shortcut revoked.', 'ghost-mode' ) . '</p></div>';
		}
		if ( isset( $_GET['session_ended'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Session ended.', 'ghost-mode' ) . '</p></div>';
		}
		if ( isset( $_GET['sessions_cleared'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Session log cleared.', 'ghost-mode' ) . '</p></div>';
		}

		settings_errors( 'ghost_mode_settings' );
		?>
		<div class="wrap ghost-mode-admin-wrap">
			<h1><?php esc_html_e( 'Ghost Mode', 'ghost-mode' ); ?></h1>
			<p class="description">
				<?php esc_html_e( 'Hide wp-login.php and wp-admin behind a secret branded login URL. Logged-out visitors hitting the stock URLs are sent to the homepage.', 'ghost-mode' ); ?>
			</p>

			<?php if ( $is_active ) : ?>
				<div class="notice notice-warning inline ghost-mode-status-notice">
					<p>
						<strong><?php esc_html_e( 'Ghost Mode is ON.', 'ghost-mode' ); ?></strong>
						<?php esc_html_e( 'Use only your custom login URL below. Bookmark it and the emergency unlock URL.', 'ghost-mode' ); ?>
					</p>
				</div>
			<?php endif; ?>

			<form method="post" action="options.php" class="ghost-mode-settings-form">
				<?php settings_fields( 'ghost_mode_settings_group' ); ?>
				<input type="hidden" name="<?php echo esc_attr( GHOST_MODE_SETTINGS_OPTION ); ?>[unlock_key]" value="<?php echo esc_attr( $settings['unlock_key'] ); ?>" />

				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><?php esc_html_e( 'Enable Ghost Mode', 'ghost-mode' ); ?></th>
						<td>
							<label>
								<input
									type="checkbox"
									name="<?php echo esc_attr( GHOST_MODE_SETTINGS_OPTION ); ?>[enabled]"
									value="yes"
									<?php checked( $settings['enabled'], 'yes' ); ?>
								/>
								<?php esc_html_e( 'Hide stock login and admin entry points', 'ghost-mode' ); ?>
							</label>
							<p class="description">
								<?php esc_html_e( 'Bookmark the custom login URL before enabling. Without it you will need the emergency unlock URL.', 'ghost-mode' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="ghost_mode_login_slug"><?php esc_html_e( 'Login URL slug', 'ghost-mode' ); ?></label></th>
						<td>
							<code><?php echo esc_html( trailingslashit( home_url( '/' ) ) ); ?></code>
							<input
								type="text"
								id="ghost_mode_login_slug"
								class="regular-text"
								name="<?php echo esc_attr( GHOST_MODE_SETTINGS_OPTION ); ?>[login_slug]"
								value="<?php echo esc_attr( $settings['login_slug'] ); ?>"
								pattern="[a-zA-Z0-9\-]+"
								required
							/>
							<p class="description">
								<?php esc_html_e( 'Letters, numbers, and hyphens only. Avoid common words like “login” or “admin”.', 'ghost-mode' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Remember Me default', 'ghost-mode' ); ?></th>
						<td>
							<label>
								<input
									type="checkbox"
									name="<?php echo esc_attr( GHOST_MODE_SETTINGS_OPTION ); ?>[remember_me_default]"
									value="yes"
									<?php checked( $settings['remember_me_default'], 'yes' ); ?>
								/>
								<?php esc_html_e( 'Check “Remember Me” by default on the login form', 'ghost-mode' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Login lockout', 'ghost-mode' ); ?></th>
						<td>
							<label>
								<input
									type="checkbox"
									name="<?php echo esc_attr( GHOST_MODE_SETTINGS_OPTION ); ?>[lockout_enabled]"
									value="yes"
									<?php checked( $settings['lockout_enabled'] ?? 'yes', 'yes' ); ?>
								/>
								<?php esc_html_e( 'Block IP and device/MAC after too many failed logins', 'ghost-mode' ); ?>
							</label>
							<p class="description" style="margin-top:10px;">
								<label for="ghost_mode_max_attempts">
									<?php esc_html_e( 'Failed attempts before block:', 'ghost-mode' ); ?>
								</label>
								<input
									type="number"
									min="1"
									max="50"
									id="ghost_mode_max_attempts"
									class="small-text"
									name="<?php echo esc_attr( GHOST_MODE_SETTINGS_OPTION ); ?>[max_login_attempts]"
									value="<?php echo esc_attr( (string) ( $settings['max_login_attempts'] ?? 5 ) ); ?>"
								/>
							</p>
							<p class="description">
								<?php esc_html_e( 'Browsers cannot send a real MAC address. When a proxy sends a MAC header it is used; otherwise a device fingerprint is blocked alongside the IP. Blocks stay until an admin unblocks them.', 'ghost-mode' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Session logging', 'ghost-mode' ); ?></th>
						<td>
							<label>
								<input
									type="checkbox"
									name="<?php echo esc_attr( GHOST_MODE_SETTINGS_OPTION ); ?>[session_logging]"
									value="yes"
									<?php checked( $settings['session_logging'] ?? 'yes', 'yes' ); ?>
								/>
								<?php esc_html_e( 'Log each login (user, IP, time, duration) and enforce session timeout', 'ghost-mode' ); ?>
							</label>
							<p class="description" style="margin-top:10px;">
								<label for="ghost_mode_session_timeout">
									<?php esc_html_e( 'Max session duration (minutes):', 'ghost-mode' ); ?>
								</label>
								<input
									type="number"
									min="0"
									max="10080"
									id="ghost_mode_session_timeout"
									class="small-text"
									name="<?php echo esc_attr( GHOST_MODE_SETTINGS_OPTION ); ?>[session_timeout_minutes]"
									value="<?php echo esc_attr( (string) ( $settings['session_timeout_minutes'] ?? 60 ) ); ?>"
								/>
							</p>
							<p class="description">
								<?php esc_html_e( 'After this many minutes from login, the session is cleared and the user must sign in again. Use 0 to disable forced timeout (logging still works). Default: 60.', 'ghost-mode' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'New-login email alerts', 'ghost-mode' ); ?></th>
						<td>
							<label>
								<input
									type="checkbox"
									name="<?php echo esc_attr( GHOST_MODE_SETTINGS_OPTION ); ?>[login_alert_enabled]"
									value="yes"
									<?php checked( $settings['login_alert_enabled'] ?? 'yes', 'yes' ); ?>
								/>
								<?php esc_html_e( 'Email when a user signs in from a new / unknown IP', 'ghost-mode' ); ?>
							</label>
							<p class="description" style="margin-top:10px;">
								<label>
									<input
										type="checkbox"
										name="<?php echo esc_attr( GHOST_MODE_SETTINGS_OPTION ); ?>[login_alert_notify_user]"
										value="yes"
										<?php checked( $settings['login_alert_notify_user'] ?? 'yes', 'yes' ); ?>
									/>
									<?php esc_html_e( 'Notify the user who logged in', 'ghost-mode' ); ?>
								</label>
								<br>
								<label>
									<input
										type="checkbox"
										name="<?php echo esc_attr( GHOST_MODE_SETTINGS_OPTION ); ?>[login_alert_notify_admin]"
										value="yes"
										<?php checked( $settings['login_alert_notify_admin'] ?? 'yes', 'yes' ); ?>
									/>
									<?php
									printf(
										/* translators: %s: admin email */
										esc_html__( 'Notify site admin (%s)', 'ghost-mode' ),
										esc_html( (string) get_option( 'admin_email' ) )
									);
									?>
								</label>
							</p>
							<p class="description">
								<label for="ghost_mode_alert_extra"><?php esc_html_e( 'Extra alert emails (optional, comma-separated):', 'ghost-mode' ); ?></label><br>
								<input
									type="text"
									id="ghost_mode_alert_extra"
									class="regular-text"
									name="<?php echo esc_attr( GHOST_MODE_SETTINGS_OPTION ); ?>[login_alert_extra_emails]"
									value="<?php echo esc_attr( $settings['login_alert_extra_emails'] ?? '' ); ?>"
									placeholder="security@example.com"
								/>
							</p>
							<p class="description">
								<?php esc_html_e( 'The first IP for each account is trusted without an email. Later logins from new IPs trigger an alert, then that IP is remembered.', 'ghost-mode' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Failed-attempt review', 'ghost-mode' ); ?></th>
						<td>
							<label>
								<input
									type="checkbox"
									name="<?php echo esc_attr( GHOST_MODE_SETTINGS_OPTION ); ?>[attempt_review_enabled]"
									value="yes"
									<?php checked( $settings['attempt_review_enabled'] ?? 'yes', 'yes' ); ?>
								/>
								<?php esc_html_e( 'After several failed attempts, ask the user on next successful login if it was them — and offer to block attacker IPs', 'ghost-mode' ); ?>
							</label>
							<p class="description">
								<?php esc_html_e( 'Shown as an admin notice after login when 2+ recent failed attempts targeted that account.', 'ghost-mode' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Quick login shortcuts', 'ghost-mode' ); ?></th>
						<td>
							<label>
								<input
									type="checkbox"
									name="<?php echo esc_attr( GHOST_MODE_SETTINGS_OPTION ); ?>[quick_login_enabled]"
									value="yes"
									<?php checked( $settings['quick_login_enabled'] ?? 'yes', 'yes' ); ?>
								/>
								<?php esc_html_e( 'After password login, offer a device bookmark URL that signs in with a 4-digit PIN', 'ghost-mode' ); ?>
							</label>
							<p class="description">
								<?php esc_html_e( 'Each shortcut works only on the browser where it was created, for 60 days. Max 3 per user. Wrong device silently goes to the homepage. The normal gate login URL always shows the full login form.', 'ghost-mode' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Password age reminder', 'ghost-mode' ); ?></th>
						<td>
							<label>
								<input
									type="checkbox"
									name="<?php echo esc_attr( GHOST_MODE_SETTINGS_OPTION ); ?>[password_age_enabled]"
									value="yes"
									<?php checked( $settings['password_age_enabled'] ?? 'yes', 'yes' ); ?>
								/>
								<?php esc_html_e( 'After login, ask users to change their password if it is older than', 'ghost-mode' ); ?>
							</label>
							<input
								type="number"
								min="1"
								max="3650"
								class="small-text"
								name="<?php echo esc_attr( GHOST_MODE_SETTINGS_OPTION ); ?>[password_age_days]"
								value="<?php echo esc_attr( (string) ( $settings['password_age_days'] ?? 45 ) ); ?>"
							/>
							<?php esc_html_e( 'days', 'ghost-mode' ); ?>
							<p class="description">
								<?php esc_html_e( 'Shows a popup right after login when overdue. If skipped, a softer admin notice appears after 10 days. Default age: 45 days.', 'ghost-mode' ); ?>
							</p>
						</td>
					</tr>
				</table>

				<?php submit_button( __( 'Save Settings', 'ghost-mode' ) ); ?>
			</form>

			<?php $this->render_quick_login_panel(); ?>
			<?php $this->render_sessions_panel(); ?>
			<?php $this->render_lockout_panel(); ?>
			<?php $this->render_security_suggestions(); ?>

			<div class="ghost-mode-urls-card">
				<h2><?php esc_html_e( 'Important URLs', 'ghost-mode' ); ?></h2>

				<div class="ghost-mode-url-row">
					<label><?php esc_html_e( 'Custom login URL', 'ghost-mode' ); ?></label>
					<div class="ghost-mode-url-field">
						<input type="text" class="large-text" id="ghost_mode_login_url" readonly value="<?php echo esc_attr( $login_url ); ?>" />
						<button type="button" class="button ghost-mode-copy" data-copy-target="ghost_mode_login_url"><?php esc_html_e( 'Copy', 'ghost-mode' ); ?></button>
					</div>
				</div>

				<div class="ghost-mode-url-row">
					<label><?php esc_html_e( 'Emergency unlock URL', 'ghost-mode' ); ?></label>
					<div class="ghost-mode-url-field">
						<input type="text" class="large-text" id="ghost_mode_unlock_url" readonly value="<?php echo esc_attr( $unlock_url ); ?>" />
						<button type="button" class="button ghost-mode-copy" data-copy-target="ghost_mode_unlock_url"><?php esc_html_e( 'Copy', 'ghost-mode' ); ?></button>
					</div>
					<p class="description">
						<?php esc_html_e( 'Opens a 1-hour unlock window so stock wp-login.php and wp-admin work again for this browser. Store this somewhere safe.', 'ghost-mode' ); ?>
					</p>
				</div>

				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="ghost-mode-regen-form" onsubmit="return confirm('<?php echo esc_js( __( 'Regenerate unlock key? The old unlock URL will stop working.', 'ghost-mode' ) ); ?>');">
					<input type="hidden" name="action" value="ghost_mode_regenerate_unlock" />
					<?php wp_nonce_field( 'ghost_mode_regenerate_unlock' ); ?>
					<?php submit_button( __( 'Regenerate unlock key', 'ghost-mode' ), 'secondary', 'submit', false ); ?>
				</form>
			</div>
		</div>
		<?php
	}

	/**
	 * Current user's quick-login device shortcuts + revoke.
	 */
	private function render_quick_login_panel() {
		$user_id = get_current_user_id();
		$links   = Ghost_Mode_Quick_Login::prune_expired(
			Ghost_Mode_Quick_Login::get_links( $user_id ),
			$user_id
		);
		?>
		<div class="ghost-mode-urls-card ghost-mode-quick-card">
			<h2><?php esc_html_e( 'Your quick login shortcuts', 'ghost-mode' ); ?></h2>
			<p class="description">
				<?php
				printf(
					/* translators: 1: max links, 2: days */
					esc_html__( 'Up to %1$d device bookmarks. Each lasts %2$d days and only works in the browser where it was created.', 'ghost-mode' ),
					(int) Ghost_Mode_Quick_Login::MAX_LINKS,
					(int) Ghost_Mode_Quick_Login::TTL_DAYS
				);
				?>
			</p>

			<?php if ( empty( $links ) ) : ?>
				<p><em><?php esc_html_e( 'No shortcuts yet. After you sign in with your password, Ghost Mode will offer to create one.', 'ghost-mode' ); ?></em></p>
			<?php else : ?>
				<table class="widefat striped ghost-mode-blocks-table">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Device', 'ghost-mode' ); ?></th>
							<th><?php esc_html_e( 'Created', 'ghost-mode' ); ?></th>
							<th><?php esc_html_e( 'Expires', 'ghost-mode' ); ?></th>
							<th><?php esc_html_e( 'Last used', 'ghost-mode' ); ?></th>
							<th><?php esc_html_e( 'Action', 'ghost-mode' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $links as $row ) : ?>
							<?php
							$created = absint( $row['created_at'] ?? 0 );
							$expires = absint( $row['expires_at'] ?? 0 );
							$used    = absint( $row['last_used_at'] ?? 0 );
							$link_id = (string) ( $row['id'] ?? '' );
							?>
							<tr>
								<td>
									<strong><?php echo esc_html( (string) ( $row['label'] ?? __( 'Device', 'ghost-mode' ) ) ); ?></strong>
									<?php if ( Ghost_Mode_Quick_Login::device_cookie_matches( $link_id, (string) ( $row['device_hash'] ?? '' ) ) ) : ?>
										<br><span class="description"><?php esc_html_e( 'This browser', 'ghost-mode' ); ?></span>
									<?php endif; ?>
								</td>
								<td>
									<?php echo $created ? esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $created ) ) : '—'; ?>
								</td>
								<td>
									<?php echo $expires ? esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $expires ) ) : '—'; ?>
								</td>
								<td>
									<?php echo $used ? esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $used ) ) : '—'; ?>
								</td>
								<td>
									<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="ghost-mode-inline-form" onsubmit="return confirm('<?php echo esc_js( __( 'Revoke this shortcut? The bookmark will stop working.', 'ghost-mode' ) ); ?>');">
										<input type="hidden" name="action" value="ghost_mode_quick_revoke" />
										<input type="hidden" name="link_id" value="<?php echo esc_attr( $link_id ); ?>" />
										<input type="hidden" name="user_id" value="<?php echo esc_attr( (string) $user_id ); ?>" />
										<?php wp_nonce_field( 'ghost_mode_quick_revoke' ); ?>
										<?php submit_button( __( 'Revoke', 'ghost-mode' ), 'small', 'submit', false ); ?>
									</form>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Blocked IPs / MAC / devices + admin unblock controls.
	 */
	private function render_lockout_panel() {
		$blocks   = Ghost_Mode_Lockout::get_blocks();
		$attempts = Ghost_Mode_Lockout::get_attempts();
		?>
		<div class="ghost-mode-urls-card ghost-mode-lockout-card">
			<h2><?php esc_html_e( 'Blocked IPs & devices', 'ghost-mode' ); ?></h2>
			<p class="description">
				<?php esc_html_e( 'Entries appear here after the configured number of failed logins. Unblock to restore access.', 'ghost-mode' ); ?>
			</p>

			<?php if ( empty( $blocks ) ) : ?>
				<p><em><?php esc_html_e( 'No active blocks.', 'ghost-mode' ); ?></em></p>
			<?php else : ?>
				<table class="widefat striped ghost-mode-blocks-table">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Type', 'ghost-mode' ); ?></th>
							<th><?php esc_html_e( 'Value', 'ghost-mode' ); ?></th>
							<th><?php esc_html_e( 'Attempts', 'ghost-mode' ); ?></th>
							<th><?php esc_html_e( 'Last username', 'ghost-mode' ); ?></th>
							<th><?php esc_html_e( 'Blocked at', 'ghost-mode' ); ?></th>
							<th><?php esc_html_e( 'Action', 'ghost-mode' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $blocks as $key => $block ) : ?>
							<tr>
								<td><?php echo esc_html( Ghost_Mode_Lockout::type_label( $block['type'] ?? '' ) ); ?></td>
								<td><code><?php echo esc_html( $block['label'] ?? $block['value'] ?? '' ); ?></code></td>
								<td><?php echo esc_html( (string) ( $block['attempts'] ?? '' ) ); ?></td>
								<td><?php echo esc_html( $block['username'] ?? '—' ); ?></td>
								<td>
									<?php
									$ts = isset( $block['blocked_at'] ) ? absint( $block['blocked_at'] ) : 0;
									echo $ts ? esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $ts ) ) : '—';
									?>
								</td>
								<td>
									<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="ghost-mode-inline-form">
										<input type="hidden" name="action" value="ghost_mode_unblock" />
										<input type="hidden" name="block_key" value="<?php echo esc_attr( $key ); ?>" />
										<?php wp_nonce_field( 'ghost_mode_unblock' ); ?>
										<?php submit_button( __( 'Unblock', 'ghost-mode' ), 'secondary small', 'submit', false ); ?>
									</form>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>

				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="ghost-mode-regen-form" onsubmit="return confirm('<?php echo esc_js( __( 'Unblock all IPs and devices?', 'ghost-mode' ) ); ?>');">
					<input type="hidden" name="action" value="ghost_mode_unblock_all" />
					<?php wp_nonce_field( 'ghost_mode_unblock_all' ); ?>
					<?php submit_button( __( 'Unblock all', 'ghost-mode' ), 'delete', 'submit', false ); ?>
				</form>
			<?php endif; ?>

			<h3><?php esc_html_e( 'In-progress failed attempts', 'ghost-mode' ); ?></h3>
			<?php if ( empty( $attempts ) ) : ?>
				<p><em><?php esc_html_e( 'No tracked failed attempts.', 'ghost-mode' ); ?></em></p>
			<?php else : ?>
				<table class="widefat striped ghost-mode-blocks-table">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Type', 'ghost-mode' ); ?></th>
							<th><?php esc_html_e( 'Value', 'ghost-mode' ); ?></th>
							<th><?php esc_html_e( 'Count', 'ghost-mode' ); ?></th>
							<th><?php esc_html_e( 'Last username', 'ghost-mode' ); ?></th>
							<th><?php esc_html_e( 'Last attempt', 'ghost-mode' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $attempts as $row ) : ?>
							<tr>
								<td><?php echo esc_html( Ghost_Mode_Lockout::type_label( $row['type'] ?? '' ) ); ?></td>
								<td><code><?php echo esc_html( $row['label'] ?? $row['value'] ?? '' ); ?></code></td>
								<td><?php echo esc_html( (string) ( $row['count'] ?? 0 ) ); ?></td>
								<td><?php echo esc_html( $row['username'] ?? '—' ); ?></td>
								<td>
									<?php
									$ts = isset( $row['last'] ) ? absint( $row['last'] ) : 0;
									echo $ts ? esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $ts ) ) : '—';
									?>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>

				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="ghost-mode-regen-form">
					<input type="hidden" name="action" value="ghost_mode_clear_attempts" />
					<?php wp_nonce_field( 'ghost_mode_clear_attempts' ); ?>
					<?php submit_button( __( 'Clear attempt counters', 'ghost-mode' ), 'secondary', 'submit', false ); ?>
				</form>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Session log table with pagination + CSV export.
	 */
	private function render_sessions_panel() {
		$timeout  = Ghost_Mode_Sessions::timeout_minutes();
		$per_page = Ghost_Mode_Sessions::PER_PAGE_DEFAULT;
		$page     = isset( $_GET['gm_session_page'] ) ? absint( $_GET['gm_session_page'] ) : 1; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$paged    = Ghost_Mode_Sessions::get_log_page( $page, $per_page );
		$rows     = $paged['rows'];
		$total    = $paged['total'];
		$page     = $paged['page'];
		$pages    = $paged['total_pages'];
		?>
		<div class="ghost-mode-urls-card ghost-mode-sessions-card" id="ghost-mode-sessions">
			<div class="ghost-mode-sessions-header">
				<div>
					<h2><?php esc_html_e( 'Login session log', 'ghost-mode' ); ?></h2>
					<p class="description">
						<?php
						if ( $timeout > 0 ) {
							printf(
								/* translators: %d: minutes */
								esc_html__( 'Active sessions are cleared automatically after %d minutes from login. Duration updates while the session is active.', 'ghost-mode' ),
								(int) $timeout
							);
						} else {
							esc_html_e( 'Forced session timeout is disabled (0 minutes). Sessions are still logged until logout.', 'ghost-mode' );
						}
						?>
					</p>
				</div>
				<?php if ( $total > 0 ) : ?>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="ghost-mode-export-form">
						<input type="hidden" name="action" value="ghost_mode_export_sessions" />
						<?php wp_nonce_field( 'ghost_mode_export_sessions' ); ?>
						<?php submit_button( __( 'Export CSV', 'ghost-mode' ), 'secondary', 'submit', false ); ?>
					</form>
				<?php endif; ?>
			</div>

			<?php if ( $total === 0 ) : ?>
				<p><em><?php esc_html_e( 'No sessions logged yet.', 'ghost-mode' ); ?></em></p>
			<?php else : ?>
				<p class="ghost-mode-sessions-meta">
					<?php
					printf(
						/* translators: 1: shown from, 2: shown to, 3: total */
						esc_html__( 'Showing %1$d–%2$d of %3$d sessions', 'ghost-mode' ),
						(int) ( ( ( $page - 1 ) * $per_page ) + 1 ),
						(int) min( $page * $per_page, $total ),
						(int) $total
					);
					?>
				</p>

				<table class="widefat striped ghost-mode-blocks-table">
					<thead>
						<tr>
							<th><?php esc_html_e( 'User', 'ghost-mode' ); ?></th>
							<th><?php esc_html_e( 'IP', 'ghost-mode' ); ?></th>
							<th><?php esc_html_e( 'MAC', 'ghost-mode' ); ?></th>
							<th><?php esc_html_e( 'Login time', 'ghost-mode' ); ?></th>
							<th><?php esc_html_e( 'Duration', 'ghost-mode' ); ?></th>
							<th><?php esc_html_e( 'Status', 'ghost-mode' ); ?></th>
							<th><?php esc_html_e( 'Action', 'ghost-mode' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $rows as $row ) : ?>
							<?php
							$login_at  = absint( $row['login_at'] ?? 0 );
							$duration  = absint( $row['duration'] ?? 0 );
							$status    = (string) ( $row['status'] ?? '' );
							$is_active = ( $status === 'active' );
							if ( $is_active && $login_at > 0 ) {
								$duration = max( $duration, time() - $login_at );
							}
							?>
							<tr>
								<td>
									<strong><?php echo esc_html( $row['user_login'] ?? '' ); ?></strong>
									<?php if ( ! empty( $row['user_id'] ) ) : ?>
										<br><span class="description">#<?php echo esc_html( (string) $row['user_id'] ); ?></span>
									<?php endif; ?>
								</td>
								<td><code><?php echo esc_html( $row['ip'] ?? '—' ); ?></code></td>
								<td><code><?php echo esc_html( ! empty( $row['mac'] ) ? $row['mac'] : '—' ); ?></code></td>
								<td>
									<?php echo $login_at ? esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $login_at ) ) : '—'; ?>
								</td>
								<td><?php echo esc_html( Ghost_Mode_Sessions::format_duration( $duration ) ); ?></td>
								<td><?php echo esc_html( Ghost_Mode_Sessions::status_label( $status ) ); ?></td>
								<td>
									<?php if ( $is_active ) : ?>
										<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="ghost-mode-inline-form">
											<input type="hidden" name="action" value="ghost_mode_end_session" />
											<input type="hidden" name="session_id" value="<?php echo esc_attr( $row['id'] ?? '' ); ?>" />
											<input type="hidden" name="gm_session_page" value="<?php echo esc_attr( (string) $page ); ?>" />
											<?php wp_nonce_field( 'ghost_mode_end_session' ); ?>
											<?php submit_button( __( 'End session', 'ghost-mode' ), 'secondary small', 'submit', false ); ?>
										</form>
									<?php else : ?>
										—
									<?php endif; ?>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>

				<?php if ( $pages > 1 ) : ?>
					<div class="tablenav ghost-mode-sessions-pagination">
						<div class="tablenav-pages">
							<span class="displaying-num">
								<?php
								printf(
									/* translators: %s: number of items */
									esc_html( _n( '%s item', '%s items', $total, 'ghost-mode' ) ),
									esc_html( number_format_i18n( $total ) )
								);
								?>
							</span>
							<span class="pagination-links">
								<?php
								$base_args = array( 'gm_session_page' => '%#%' );
								$base_url  = ghost_mode_get_settings_url() . '#ghost-mode-sessions';

								echo wp_kses_post(
									paginate_links(
										array(
											'base'      => esc_url_raw( add_query_arg( 'gm_session_page', '%#%', $base_url ) ),
											'format'    => '',
											'current'   => $page,
											'total'     => $pages,
											'prev_text' => '&laquo;',
											'next_text' => '&raquo;',
											'type'      => 'plain',
										)
									)
								);
								unset( $base_args );
								?>
							</span>
						</div>
					</div>
				<?php endif; ?>

				<div class="ghost-mode-sessions-actions">
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="ghost-mode-export-form">
						<input type="hidden" name="action" value="ghost_mode_export_sessions" />
						<?php wp_nonce_field( 'ghost_mode_export_sessions' ); ?>
						<?php submit_button( __( 'Export CSV', 'ghost-mode' ), 'secondary', 'submit', false ); ?>
					</form>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="ghost-mode-regen-form" onsubmit="return confirm('<?php echo esc_js( __( 'Clear the entire session log?', 'ghost-mode' ) ); ?>');">
						<input type="hidden" name="action" value="ghost_mode_clear_session_log" />
						<?php wp_nonce_field( 'ghost_mode_clear_session_log' ); ?>
						<?php submit_button( __( 'Clear session log', 'ghost-mode' ), 'delete', 'submit', false ); ?>
					</form>
				</div>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Suggested security enhancements (roadmap / guidance).
	 */
	private function render_security_suggestions() {
		?>
		<div class="ghost-mode-urls-card ghost-mode-security-tips">
			<h2><?php esc_html_e( 'Suggested security upgrades', 'ghost-mode' ); ?></h2>
			<p class="description"><?php esc_html_e( 'Already included: hidden login URL, failed-login lockout, session log + timeout, new-IP email alerts, failed-attempt review + block. These would strengthen the site further:', 'ghost-mode' ); ?></p>
			<ul class="ghost-mode-tips-list">
				<li><strong><?php esc_html_e( 'Two-factor authentication (2FA / OTP)', 'ghost-mode' ); ?></strong> — <?php esc_html_e( 'Require a code from email or authenticator app after password.', 'ghost-mode' ); ?></li>
				<li><strong><?php esc_html_e( 'IP allowlist for wp-admin', 'ghost-mode' ); ?></strong> — <?php esc_html_e( 'Only known office/home IPs can reach the dashboard.', 'ghost-mode' ); ?></li>
				<li><strong><?php esc_html_e( 'Limit concurrent sessions', 'ghost-mode' ); ?></strong> — <?php esc_html_e( 'One active session per user; new login ends the old one.', 'ghost-mode' ); ?></li>
				<li><strong><?php esc_html_e( 'Disable XML-RPC / Application Passwords', 'ghost-mode' ); ?></strong> — <?php esc_html_e( 'Close alternate auth entry points if unused.', 'ghost-mode' ); ?></li>
				<li><strong><?php esc_html_e( 'Idle timeout', 'ghost-mode' ); ?></strong> — <?php esc_html_e( 'End the session after N minutes without activity (in addition to max duration).', 'ghost-mode' ); ?></li>
			</ul>
		</div>
		<?php
	}
}
