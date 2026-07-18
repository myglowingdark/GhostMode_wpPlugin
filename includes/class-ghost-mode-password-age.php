<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Prompt users to change password after a configurable number of days.
 *
 * First overdue login → full-screen popup.
 * If skipped → quiet for 10 days, then an admin notice (not a popup).
 */
class Ghost_Mode_Password_Age {

	const CHANGED_META = 'ghost_mode_password_changed_at';
	const NAG_META     = 'ghost_mode_password_nag';
	const DEFAULT_DAYS = 45;
	const SKIP_DAYS    = 10;

	public function __construct() {
		add_action( 'wp_login', array( $this, 'on_login' ), 30, 2 );
		add_action( 'after_password_reset', array( $this, 'on_password_reset' ), 10, 2 );
		add_action( 'profile_update', array( $this, 'on_profile_update' ), 10, 2 );

		add_action( 'admin_footer', array( $this, 'render_modal' ), 5 );
		add_action( 'admin_notices', array( $this, 'render_notice' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );

		add_action( 'wp_ajax_ghost_mode_password_change', array( $this, 'ajax_change' ) );
		add_action( 'wp_ajax_ghost_mode_password_skip', array( $this, 'ajax_skip' ) );
		add_action( 'admin_post_ghost_mode_password_notice_dismiss', array( $this, 'handle_notice_dismiss' ) );
	}

	public static function is_enabled() {
		$settings = ghost_mode_get_settings();
		return ( $settings['password_age_enabled'] ?? 'yes' ) === 'yes';
	}

	/**
	 * Max age in days before a change is suggested.
	 */
	public static function max_days() {
		$settings = ghost_mode_get_settings();
		$days     = isset( $settings['password_age_days'] ) ? absint( $settings['password_age_days'] ) : self::DEFAULT_DAYS;
		return max( 1, min( 3650, $days ? $days : self::DEFAULT_DAYS ) );
	}

	/**
	 * @param int $user_id User ID.
	 * @return array{mode:string,skip_until:int,active:int}
	 */
	public static function get_nag( $user_id ) {
		$nag = get_user_meta( (int) $user_id, self::NAG_META, true );
		if ( ! is_array( $nag ) ) {
			$nag = array();
		}
		return array(
			'mode'       => in_array( ( $nag['mode'] ?? '' ), array( 'modal', 'notice' ), true ) ? $nag['mode'] : '',
			'skip_until' => absint( $nag['skip_until'] ?? 0 ),
			'active'     => ! empty( $nag['active'] ) ? 1 : 0,
		);
	}

	/**
	 * @param int                  $user_id User ID.
	 * @param array<string, mixed> $nag     Nag state.
	 */
	public static function save_nag( $user_id, array $nag ) {
		update_user_meta(
			(int) $user_id,
			self::NAG_META,
			array(
				'mode'       => (string) ( $nag['mode'] ?? '' ),
				'skip_until' => absint( $nag['skip_until'] ?? 0 ),
				'active'     => ! empty( $nag['active'] ) ? 1 : 0,
			)
		);
	}

	/**
	 * @param int $user_id User ID.
	 */
	public static function clear_nag( $user_id ) {
		delete_user_meta( (int) $user_id, self::NAG_META );
		// Legacy cleanup.
		delete_user_meta( (int) $user_id, 'ghost_mode_password_prompt' );
	}

	/**
	 * @param int $user_id User ID.
	 */
	public static function get_changed_at( $user_id ) {
		$user_id = (int) $user_id;
		$stored  = absint( get_user_meta( $user_id, self::CHANGED_META, true ) );
		if ( $stored > 0 ) {
			return $stored;
		}
		$user = get_userdata( $user_id );
		if ( $user && ! empty( $user->user_registered ) ) {
			return (int) strtotime( $user->user_registered );
		}
		return 0;
	}

	/**
	 * @param int $user_id User ID.
	 */
	public static function mark_changed( $user_id ) {
		$user_id = (int) $user_id;
		if ( $user_id <= 0 ) {
			return;
		}
		update_user_meta( $user_id, self::CHANGED_META, time() );
		self::clear_nag( $user_id );
	}

	/**
	 * @param int $user_id User ID.
	 */
	public static function is_stale( $user_id ) {
		if ( ! self::is_enabled() ) {
			return false;
		}
		$changed = self::get_changed_at( $user_id );
		if ( $changed <= 0 ) {
			return true;
		}
		return ( time() - $changed ) >= ( self::max_days() * DAY_IN_SECONDS );
	}

	/**
	 * Migrate legacy prompt meta so current sessions keep working.
	 *
	 * @param int $user_id User ID.
	 */
	private static function maybe_migrate_legacy( $user_id ) {
		$user_id = (int) $user_id;
		$legacy  = get_user_meta( $user_id, 'ghost_mode_password_prompt', true );
		if ( ! $legacy ) {
			return;
		}
		$nag = get_user_meta( $user_id, self::NAG_META, true );
		if ( ! is_array( $nag ) || empty( $nag['mode'] ) ) {
			self::save_nag(
				$user_id,
				array(
					'mode'       => 'modal',
					'skip_until' => 0,
					'active'     => 1,
				)
			);
		}
		delete_user_meta( $user_id, 'ghost_mode_password_prompt' );
	}

	/**
	 * Popup after login (first overdue prompt).
	 *
	 * @param int $user_id User ID.
	 */
	public static function should_show_modal( $user_id = 0 ) {
		$user_id = $user_id ? (int) $user_id : get_current_user_id();
		if ( ! self::is_enabled() || $user_id <= 0 || ! self::is_stale( $user_id ) ) {
			return false;
		}
		self::maybe_migrate_legacy( $user_id );
		$nag = self::get_nag( $user_id );
		return ! empty( $nag['active'] ) && ( $nag['mode'] ?? '' ) === 'modal';
	}

	/**
	 * Soft admin notice after a skip cooldown.
	 *
	 * @param int $user_id User ID.
	 */
	public static function should_show_notice( $user_id = 0 ) {
		$user_id = $user_id ? (int) $user_id : get_current_user_id();
		if ( ! self::is_enabled() || $user_id <= 0 || ! self::is_stale( $user_id ) ) {
			return false;
		}
		$nag = self::get_nag( $user_id );
		return ! empty( $nag['active'] ) && ( $nag['mode'] ?? '' ) === 'notice';
	}

	/** Back-compat for Quick Login priority check. */
	public static function should_show_prompt( $user_id = 0 ) {
		return self::should_show_modal( $user_id );
	}

	/**
	 * @param string  $user_login Login.
	 * @param WP_User $user       User.
	 */
	public function on_login( $user_login, $user ) {
		unset( $user_login );
		if ( ! self::is_enabled() || ! ( $user instanceof WP_User ) ) {
			return;
		}

		$user_id = (int) $user->ID;
		if ( ! self::is_stale( $user_id ) ) {
			self::clear_nag( $user_id );
			return;
		}

		$nag = self::get_nag( $user_id );
		$now = time();

		// Still in skip cooldown — stay quiet.
		if ( (int) $nag['skip_until'] > $now ) {
			$nag['active'] = 0;
			self::save_nag( $user_id, $nag );
			return;
		}

		// Skip period ended → soft notice next.
		if ( (int) $nag['skip_until'] > 0 && ( $nag['mode'] ?? '' ) === 'notice' ) {
			$nag['active']     = 1;
			$nag['mode']       = 'notice';
			$nag['skip_until'] = 0;
			self::save_nag( $user_id, $nag );
			return;
		}

		// First overdue login (or fresh cycle) → popup.
		self::save_nag(
			$user_id,
			array(
				'mode'       => 'modal',
				'skip_until' => 0,
				'active'     => 1,
			)
		);
	}

	/**
	 * @param WP_User $user     User.
	 * @param string  $new_pass New password.
	 */
	public function on_password_reset( $user, $new_pass = '' ) {
		unset( $new_pass );
		if ( $user instanceof WP_User ) {
			self::mark_changed( (int) $user->ID );
		}
	}

	/**
	 * @param int     $user_id       User ID.
	 * @param WP_User $old_user_data Previous user object.
	 */
	public function on_profile_update( $user_id, $old_user_data ) {
		$user = get_userdata( $user_id );
		if ( ! ( $user instanceof WP_User ) || ! ( $old_user_data instanceof WP_User ) ) {
			return;
		}
		if ( $user->user_pass !== $old_user_data->user_pass ) {
			self::mark_changed( (int) $user_id );
		}
	}

	public function enqueue_admin_assets( $hook ) {
		unset( $hook );
		if ( ! is_user_logged_in() || ! self::should_show_modal() ) {
			return;
		}
		wp_enqueue_script(
			'ghost-mode-admin',
			GHOST_MODE_URL . 'assets/ghost-mode-admin.js',
			array(),
			GHOST_MODE_VERSION,
			true
		);
		wp_localize_script(
			'ghost-mode-admin',
			'ghostModePasswordAge',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( 'ghost_mode_password_age' ),
				'days'    => self::max_days(),
				'i18n'    => array(
					'mismatch' => __( 'Passwords do not match.', 'ghost-mode' ),
					'tooShort' => __( 'Use at least 8 characters.', 'ghost-mode' ),
					'error'    => __( 'Something went wrong. Please try again.', 'ghost-mode' ),
					'success'  => __( 'Password updated.', 'ghost-mode' ),
				),
			)
		);
	}

	public function render_modal() {
		if ( ! self::should_show_modal() ) {
			return;
		}
		$days  = self::max_days();
		$nonce = wp_create_nonce( 'ghost_mode_password_age' );
		$ajax  = admin_url( 'admin-ajax.php' );
		?>
		<div id="ghost-mode-password-modal" class="ghost-mode-password-modal" role="dialog" aria-modal="true" aria-labelledby="ghost-mode-password-title">
			<div class="ghost-mode-password-modal__backdrop"></div>
			<div class="ghost-mode-password-modal__card">
				<div class="ghost-mode-password-modal__badge"><?php esc_html_e( 'Security', 'ghost-mode' ); ?></div>
				<h2 id="ghost-mode-password-title"><?php esc_html_e( 'Time for a fresh password?', 'ghost-mode' ); ?></h2>
				<p class="ghost-mode-password-modal__lead">
					<?php
					printf(
						/* translators: %d: number of days */
						esc_html__( 'Your password has not been changed in the last %d days. Updating it keeps this account safer — it only takes a moment.', 'ghost-mode' ),
						(int) $days
					);
					?>
				</p>
				<label class="ghost-mode-password-modal__label" for="ghost_mode_pw_new"><?php esc_html_e( 'New password', 'ghost-mode' ); ?></label>
				<input class="ghost-mode-password-modal__input" type="password" id="ghost_mode_pw_new" autocomplete="new-password">
				<label class="ghost-mode-password-modal__label" for="ghost_mode_pw_confirm"><?php esc_html_e( 'Confirm new password', 'ghost-mode' ); ?></label>
				<input class="ghost-mode-password-modal__input" type="password" id="ghost_mode_pw_confirm" autocomplete="new-password">
				<p class="ghost-mode-password-modal__error" id="ghost_mode_pw_error" hidden></p>
				<p class="ghost-mode-password-modal__ok" id="ghost_mode_pw_ok" hidden></p>
				<div class="ghost-mode-password-modal__actions">
					<button type="button" class="button button-primary button-hero" id="ghost_mode_pw_save"><?php esc_html_e( 'Update password', 'ghost-mode' ); ?></button>
					<button type="button" class="button button-secondary button-hero" id="ghost_mode_pw_skip"><?php esc_html_e( 'Not now', 'ghost-mode' ); ?></button>
				</div>
				<div class="ghost-mode-modal__brand" aria-hidden="true">GGLOWINGDARK CARBON DOME</div>
			</div>
		</div>
		<style>
			.ghost-mode-password-modal{position:fixed!important;inset:0!important;z-index:100010!important;display:flex!important;align-items:center;justify-content:center;padding:24px;box-sizing:border-box}
			.ghost-mode-password-modal__backdrop{position:absolute;inset:0;background:rgba(15,23,42,.55)}
			.ghost-mode-password-modal__card{position:relative;z-index:1;max-width:480px;width:100%;background:#fff;border-radius:14px;padding:28px 28px 24px;box-shadow:0 24px 64px rgba(0,0,0,.25);box-sizing:border-box}
			.ghost-mode-password-modal__badge{display:inline-flex;align-items:center;justify-content:center;height:28px;margin:0 0 12px;padding:0 12px;border:0;border-radius:999px;background:#2271b1;color:#fff;font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase}
			.ghost-mode-password-modal__card h2{margin:0 0 10px;font-size:1.4rem;line-height:1.3;color:#1d2327}
			.ghost-mode-password-modal__lead{margin:0 0 16px;font-size:14px;line-height:1.5;color:#1d2327}
			.ghost-mode-password-modal__label{display:block;margin:0 0 6px;font-weight:600;font-size:13px}
			.ghost-mode-password-modal__input{display:block;width:100%;height:40px;margin:0 0 14px;padding:0 12px;border:1px solid #c3c4c7;border-radius:6px;box-sizing:border-box}
			.ghost-mode-password-modal__error{margin:0 0 12px;color:#b32d2e;font-size:13px}
			.ghost-mode-password-modal__ok{margin:0 0 12px;color:#1f9d6a;font-size:13px}
			.ghost-mode-password-modal__actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:8px}
			.ghost-mode-modal__brand{display:block;width:fit-content;max-width:100%;margin:18px auto 0;padding:0;border:0;background:none;color:#2271b1;font-size:10px;font-weight:600;letter-spacing:.04em;line-height:1.2;text-align:center;white-space:nowrap;pointer-events:none;user-select:none}
		</style>
		<script>
		(function () {
			var cfg = {
				ajaxUrl: <?php echo wp_json_encode( $ajax ); ?>,
				nonce: <?php echo wp_json_encode( $nonce ); ?>,
				i18n: {
					mismatch: <?php echo wp_json_encode( __( 'Passwords do not match.', 'ghost-mode' ) ); ?>,
					tooShort: <?php echo wp_json_encode( __( 'Use at least 8 characters.', 'ghost-mode' ) ); ?>,
					error: <?php echo wp_json_encode( __( 'Something went wrong. Please try again.', 'ghost-mode' ) ); ?>,
					success: <?php echo wp_json_encode( __( 'Password updated.', 'ghost-mode' ) ); ?>
				}
			};
			window.ghostModePasswordAge = cfg;
			window.ghostModePasswordAgeBound = true;

			var modal = document.getElementById('ghost-mode-password-modal');
			if (!modal) { return; }
			var pass1 = document.getElementById('ghost_mode_pw_new');
			var pass2 = document.getElementById('ghost_mode_pw_confirm');
			var errEl = document.getElementById('ghost_mode_pw_error');
			var okEl = document.getElementById('ghost_mode_pw_ok');
			var saveBtn = document.getElementById('ghost_mode_pw_save');
			var skipBtn = document.getElementById('ghost_mode_pw_skip');

			function showError(msg) {
				if (okEl) { okEl.hidden = true; }
				if (!errEl) { return; }
				errEl.hidden = !msg;
				errEl.textContent = msg || '';
			}
			function post(action, data) {
				var body = new FormData();
				body.append('action', action);
				body.append('nonce', cfg.nonce);
				Object.keys(data || {}).forEach(function (k) { body.append(k, data[k]); });
				return fetch(cfg.ajaxUrl, { method: 'POST', credentials: 'same-origin', body: body }).then(function (r) { return r.json(); });
			}
			function done() {
				modal.remove();
				window.location.reload();
			}
			if (saveBtn) {
				saveBtn.addEventListener('click', function () {
					var p1 = pass1 ? pass1.value : '';
					var p2 = pass2 ? pass2.value : '';
					showError('');
					if (p1.length < 8) { showError(cfg.i18n.tooShort); return; }
					if (p1 !== p2) { showError(cfg.i18n.mismatch); return; }
					saveBtn.disabled = true;
					post('ghost_mode_password_change', { password: p1, password2: p2 })
						.then(function (res) {
							saveBtn.disabled = false;
							if (!res || !res.success) {
								showError((res && res.data && res.data.message) || cfg.i18n.error);
								return;
							}
							if (okEl) { okEl.hidden = false; okEl.textContent = (res.data && res.data.message) || cfg.i18n.success; }
							setTimeout(done, 500);
						})
						.catch(function () { saveBtn.disabled = false; showError(cfg.i18n.error); });
				});
			}
			if (skipBtn) {
				skipBtn.addEventListener('click', function () {
					skipBtn.disabled = true;
					post('ghost_mode_password_skip', {}).finally(done);
				});
			}
		})();
		</script>
		<?php
	}

	public function render_notice() {
		if ( ! self::should_show_notice() ) {
			return;
		}
		$days    = self::max_days();
		$profile = admin_url( 'profile.php#password' );
		$dismiss = wp_nonce_url(
			admin_url( 'admin-post.php?action=ghost_mode_password_notice_dismiss' ),
			'ghost_mode_password_notice_dismiss'
		);
		?>
		<div class="notice notice-warning is-dismissible ghost-mode-password-notice">
			<p>
				<strong><?php esc_html_e( 'Ghost Mode:', 'ghost-mode' ); ?></strong>
				<?php
				printf(
					/* translators: %d: number of days */
					esc_html__( 'Your password is older than %d days. Consider updating it for better account security.', 'ghost-mode' ),
					(int) $days
				);
				?>
			</p>
			<p>
				<a class="button button-primary" href="<?php echo esc_url( $profile ); ?>"><?php esc_html_e( 'Change password', 'ghost-mode' ); ?></a>
				<a class="button" href="<?php echo esc_url( $dismiss ); ?>"><?php esc_html_e( 'Remind me later', 'ghost-mode' ); ?></a>
			</p>
		</div>
		<?php
	}

	public function ajax_change() {
		check_ajax_referer( 'ghost_mode_password_age', 'nonce' );
		if ( ! is_user_logged_in() ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized.', 'ghost-mode' ) ), 403 );
		}

		$user_id = get_current_user_id();
		$pass1   = isset( $_POST['password'] ) ? (string) wp_unslash( $_POST['password'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$pass2   = isset( $_POST['password2'] ) ? (string) wp_unslash( $_POST['password2'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized

		if ( strlen( $pass1 ) < 8 ) {
			wp_send_json_error( array( 'message' => __( 'Use at least 8 characters.', 'ghost-mode' ) ) );
		}
		if ( $pass1 !== $pass2 ) {
			wp_send_json_error( array( 'message' => __( 'Passwords do not match.', 'ghost-mode' ) ) );
		}
		if ( ! get_userdata( $user_id ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized.', 'ghost-mode' ) ), 403 );
		}

		wp_set_password( $pass1, $user_id );
		self::mark_changed( $user_id );
		wp_set_auth_cookie( $user_id, true, is_ssl() );

		wp_send_json_success( array( 'message' => __( 'Password updated.', 'ghost-mode' ) ) );
	}

	public function ajax_skip() {
		check_ajax_referer( 'ghost_mode_password_age', 'nonce' );
		if ( ! is_user_logged_in() ) {
			wp_send_json_error( null, 403 );
		}

		$user_id = get_current_user_id();
		self::save_nag(
			$user_id,
			array(
				'mode'       => 'notice',
				'skip_until' => time() + ( self::SKIP_DAYS * DAY_IN_SECONDS ),
				'active'     => 0,
			)
		);
		wp_send_json_success();
	}

	public function handle_notice_dismiss() {
		if ( ! is_user_logged_in() ) {
			wp_die( esc_html__( 'Unauthorized', 'ghost-mode' ) );
		}
		check_admin_referer( 'ghost_mode_password_notice_dismiss' );

		self::save_nag(
			get_current_user_id(),
			array(
				'mode'       => 'notice',
				'skip_until' => time() + ( self::SKIP_DAYS * DAY_IN_SECONDS ),
				'active'     => 0,
			)
		);

		wp_safe_redirect( wp_get_referer() ? wp_get_referer() : admin_url() );
		exit;
	}
}
