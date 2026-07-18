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

		add_action( 'admin_bar_menu', array( $this, 'add_admin_bar_item' ), 80 );
		add_action( 'admin_head', array( $this, 'print_admin_bar_styles' ) );
		add_action( 'wp_head', array( $this, 'print_admin_bar_styles' ) );

		add_action( 'admin_footer', array( $this, 'render_modal' ), 5 );
		add_action( 'wp_footer', array( $this, 'render_modal' ), 5 );
		add_action( 'admin_notices', array( $this, 'render_notice' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );
		add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );

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
	 * Lock icon in admin bar for overdue password and/or failed-attempt review.
	 *
	 * @param int $user_id User ID.
	 */
	public static function should_show_admin_bar( $user_id = 0 ) {
		$user_id = $user_id ? (int) $user_id : get_current_user_id();
		if ( $user_id <= 0 || ! is_admin_bar_showing() ) {
			return false;
		}
		return function_exists( 'ghost_mode_user_has_alert' ) && ghost_mode_user_has_alert( $user_id );
	}

	/**
	 * @param WP_Admin_Bar $wp_admin_bar Admin bar.
	 */
	public function add_admin_bar_item( $wp_admin_bar ) {
		if ( ! self::should_show_admin_bar() || ! ( $wp_admin_bar instanceof WP_Admin_Bar ) ) {
			return;
		}

		$user_id       = get_current_user_id();
		$password_stale = self::is_enabled() && self::is_stale( $user_id );
		$has_review     = class_exists( 'Ghost_Mode_Attempt_Review' ) && Ghost_Mode_Attempt_Review::get_review( $user_id );

		if ( $password_stale && $has_review ) {
			$tip  = __( 'Security alerts: change your password and review recent failed login attempts.', 'ghost-mode' );
			$href = '#ghost-mode-change-password';
		} elseif ( $password_stale ) {
			$tip  = __( 'Change your password — it has not been updated recently.', 'ghost-mode' );
			$href = '#ghost-mode-change-password';
		} else {
			$tip  = __( 'Review failed login attempts on your account.', 'ghost-mode' );
			$href = '#ghost-mode-review-modal';
		}

		$title = sprintf(
			'<span class="ab-icon dashicons dashicons-lock" aria-hidden="true"></span><span class="ghost-mode-ab-dot" aria-hidden="true"></span><span class="screen-reader-text">%s</span>',
			esc_html( $tip )
		);

		$wp_admin_bar->add_node(
			array(
				'id'    => 'ghost-mode-alerts',
				'title' => $title,
				'href'  => $href,
				'meta'  => array(
					'title' => $tip,
					'class' => 'ghost-mode-ab-alerts',
				),
			)
		);
	}

	public function print_admin_bar_styles() {
		if ( ! self::should_show_admin_bar() ) {
			return;
		}
		?>
		<style id="ghost-mode-ab-alerts-css">
			#wpadminbar #wp-admin-bar-ghost-mode-alerts > .ab-item {
				position: relative;
				display: flex;
				align-items: center;
			}
			#wpadminbar #wp-admin-bar-ghost-mode-alerts .ab-icon {
				margin-right: 0 !important;
				padding: 6px 0 !important;
				font-size: 20px !important;
				line-height: 1.45 !important;
			}
			#wpadminbar #wp-admin-bar-ghost-mode-alerts .ab-icon:before {
				content: "\f160";
				top: 2px;
			}
			#wpadminbar #wp-admin-bar-ghost-mode-alerts .ghost-mode-ab-dot {
				position: absolute;
				top: 6px;
				right: 4px;
				width: 8px;
				height: 8px;
				border-radius: 50%;
				background: #d63638;
				box-shadow: 0 0 0 2px #1d2327;
				pointer-events: none;
			}
			#wpadminbar #wp-admin-bar-ghost-mode-alerts:hover .ghost-mode-ab-dot,
			#wpadminbar #wp-admin-bar-ghost-mode-alerts.hover .ghost-mode-ab-dot {
				box-shadow: 0 0 0 2px #2c3338;
			}
		</style>
		<?php
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
		if ( ! is_user_logged_in() || ! self::is_stale( get_current_user_id() ) ) {
			return;
		}
		// Dashicons needed on front when admin bar is shown.
		if ( ! is_admin() ) {
			wp_enqueue_style( 'dashicons' );
		}
	}

	public function render_modal() {
		static $rendered = false;
		if ( $rendered || ! is_user_logged_in() || ! self::is_stale( get_current_user_id() ) ) {
			return;
		}
		$rendered = true;

		$auto_open = self::should_show_modal();
		$days      = self::max_days();
		$nonce     = wp_create_nonce( 'ghost_mode_password_age' );
		$ajax      = admin_url( 'admin-ajax.php' );
		?>
		<div id="ghost-mode-password-modal" class="ghost-mode-password-modal<?php echo $auto_open ? ' is-open' : ''; ?>" role="dialog" aria-modal="true" aria-labelledby="ghost-mode-password-title"<?php echo $auto_open ? '' : ' hidden'; ?>>
			<div class="ghost-mode-password-modal__backdrop" data-ghost-mode-pw-close></div>
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
				<div class="ghost-mode-password-modal__field">
					<input class="ghost-mode-password-modal__input" type="password" id="ghost_mode_pw_new" autocomplete="new-password">
					<button type="button" class="ghost-mode-password-modal__toggle" data-target="ghost_mode_pw_new" aria-label="<?php esc_attr_e( 'Show password', 'ghost-mode' ); ?>" aria-pressed="false">
						<svg class="ghost-mode-eye-open" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z"/><circle cx="12" cy="12" r="3"/></svg>
						<svg class="ghost-mode-eye-closed" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 19c-7 0-11-7-11-7a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 7 11 7a18.5 18.5 0 0 1-2.16 3.19M1 1l22 22"/><path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"/></svg>
					</button>
				</div>
				<label class="ghost-mode-password-modal__label" for="ghost_mode_pw_confirm"><?php esc_html_e( 'Confirm new password', 'ghost-mode' ); ?></label>
				<div class="ghost-mode-password-modal__field">
					<input class="ghost-mode-password-modal__input" type="password" id="ghost_mode_pw_confirm" autocomplete="new-password">
					<button type="button" class="ghost-mode-password-modal__toggle" data-target="ghost_mode_pw_confirm" aria-label="<?php esc_attr_e( 'Show password', 'ghost-mode' ); ?>" aria-pressed="false">
						<svg class="ghost-mode-eye-open" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z"/><circle cx="12" cy="12" r="3"/></svg>
						<svg class="ghost-mode-eye-closed" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 19c-7 0-11-7-11-7a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 7 11 7a18.5 18.5 0 0 1-2.16 3.19M1 1l22 22"/><path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"/></svg>
					</button>
				</div>
				<p class="ghost-mode-password-modal__error" id="ghost_mode_pw_error" hidden></p>
				<p class="ghost-mode-password-modal__ok" id="ghost_mode_pw_ok" hidden></p>
				<div class="ghost-mode-password-modal__actions">
					<button type="button" class="button button-primary button-hero" id="ghost_mode_pw_save"><?php esc_html_e( 'Update password', 'ghost-mode' ); ?></button>
					<button type="button" class="button button-secondary button-hero" id="ghost_mode_pw_skip"><?php esc_html_e( 'Not now', 'ghost-mode' ); ?></button>
				</div>
				<div class="ghost-mode-modal__brand" aria-hidden="true">Glowingdark Carbon Dome</div>
			</div>
		</div>
		<style>
			.ghost-mode-password-modal{position:fixed!important;inset:0!important;z-index:100010!important;display:none;align-items:center;justify-content:center;padding:24px;box-sizing:border-box}
			.ghost-mode-password-modal.is-open{display:flex!important}
			.ghost-mode-password-modal__backdrop{position:absolute;inset:0;background:rgba(15,23,42,.55)}
			.ghost-mode-password-modal__card{position:relative;z-index:1;max-width:480px;width:100%;background:#fff;border-radius:14px;padding:28px 28px 24px;box-shadow:0 24px 64px rgba(0,0,0,.25);box-sizing:border-box}
			.ghost-mode-password-modal__badge{display:inline-flex;align-items:center;justify-content:center;height:28px;margin:0 0 12px;padding:0 12px;border:0;border-radius:999px;background:#2271b1;color:#fff;font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase}
			.ghost-mode-password-modal__card h2{margin:0 0 10px;font-size:1.4rem;line-height:1.3;color:#1d2327}
			.ghost-mode-password-modal__lead{margin:0 0 16px;font-size:14px;line-height:1.5;color:#1d2327}
			.ghost-mode-password-modal__label{display:block;margin:0 0 6px;font-weight:600;font-size:13px}
			.ghost-mode-password-modal__field{position:relative;margin:0 0 14px}
			.ghost-mode-password-modal__input{display:block;width:100%;height:40px;margin:0;padding:0 40px 0 12px;border:1px solid #c3c4c7;border-radius:6px;box-sizing:border-box}
			.ghost-mode-password-modal__toggle{position:absolute;top:50%;right:6px;transform:translateY(-50%);display:inline-flex;align-items:center;justify-content:center;width:32px;height:32px;padding:0;border:0;border-radius:4px;background:transparent;color:#646970;cursor:pointer}
			.ghost-mode-password-modal__toggle:hover{color:#1d2327;background:#f0f0f1}
			.ghost-mode-password-modal__toggle .ghost-mode-eye-closed{display:none}
			.ghost-mode-password-modal__toggle.is-visible .ghost-mode-eye-open{display:none}
			.ghost-mode-password-modal__toggle.is-visible .ghost-mode-eye-closed{display:block}
			.ghost-mode-password-modal__error{margin:0 0 12px;color:#b32d2e;font-size:13px}
			.ghost-mode-password-modal__ok{margin:0 0 12px;color:#1f9d6a;font-size:13px}
			.ghost-mode-password-modal__actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:8px}
			.ghost-mode-modal__brand{display:block;width:fit-content;max-width:100%;margin:18px auto 0;padding:0;border:0;background:none;color:#2271b1;font-size:10px;font-weight:600;letter-spacing:.04em;line-height:1.2;text-align:center;white-space:nowrap;pointer-events:none;user-select:none;text-transform:uppercase}
			.ghost-mode-password-modal .button{cursor:pointer}
		</style>
		<script>
		(function () {
			if (window.ghostModePasswordAgeBound) { return; }
			window.ghostModePasswordAgeBound = true;

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

			var modal = document.getElementById('ghost-mode-password-modal');
			if (!modal) { return; }
			var pass1 = document.getElementById('ghost_mode_pw_new');
			var pass2 = document.getElementById('ghost_mode_pw_confirm');
			var errEl = document.getElementById('ghost_mode_pw_error');
			var okEl = document.getElementById('ghost_mode_pw_ok');
			var saveBtn = document.getElementById('ghost_mode_pw_save');
			var skipBtn = document.getElementById('ghost_mode_pw_skip');

			modal.querySelectorAll('.ghost-mode-password-modal__toggle').forEach(function (btn) {
				btn.addEventListener('click', function () {
					var id = btn.getAttribute('data-target');
					var input = id ? document.getElementById(id) : null;
					if (!input) { return; }
					var show = input.type === 'password';
					input.type = show ? 'text' : 'password';
					btn.classList.toggle('is-visible', show);
					btn.setAttribute('aria-label', show ? <?php echo wp_json_encode( __( 'Hide password', 'ghost-mode' ) ); ?> : <?php echo wp_json_encode( __( 'Show password', 'ghost-mode' ) ); ?>);
					btn.setAttribute('aria-pressed', show ? 'true' : 'false');
				});
			});

			function openModal(e) {
				if (e) { e.preventDefault(); }
				modal.hidden = false;
				modal.classList.add('is-open');
				if (pass1) { pass1.focus(); }
			}
			function closeModal() {
				modal.classList.remove('is-open');
				modal.hidden = true;
			}
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
				closeModal();
				window.location.reload();
			}

			document.querySelectorAll('#wp-admin-bar-ghost-mode-alerts > .ab-item[href="#ghost-mode-change-password"], a[href="#ghost-mode-change-password"]').forEach(function (el) {
				el.addEventListener('click', openModal);
			});
			document.querySelectorAll('#wp-admin-bar-ghost-mode-alerts > .ab-item[href="#ghost-mode-review-modal"], a[href="#ghost-mode-review-modal"]').forEach(function (el) {
				el.addEventListener('click', function (e) {
					var review = document.getElementById('ghost-mode-review-modal');
					if (!review) { return; }
					e.preventDefault();
					review.scrollIntoView({ block: 'center' });
					review.style.display = 'flex';
				});
			});

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
				<a class="button button-primary" href="#ghost-mode-change-password"><?php esc_html_e( 'Change password', 'ghost-mode' ); ?></a>
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
