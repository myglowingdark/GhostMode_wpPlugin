<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * After failed logins, ask the real user on next successful login
 * whether those attempts were them — and offer to block attacker IPs.
 *
 * Failures are tracked by account (when username/email matches a user)
 * AND by IP, so wrong-username tries still surface after a correct login.
 */
class Ghost_Mode_Attempt_Review {

	const RECENT_OPTION = 'ghost_mode_recent_failures';
	const USER_META     = 'ghost_mode_attempt_review';
	const MIN_FAILURES  = 2;
	const RETENTION     = DAY_IN_SECONDS;

	public function __construct() {
		// Track independently of lockout (so review works even if lockout is off).
		add_action( 'wp_login_failed', array( $this, 'on_login_failed' ), 20, 2 );
		add_action( 'wp_login', array( $this, 'on_successful_login' ), 25, 2 );
		add_action( 'admin_notices', array( $this, 'render_notice' ) );
		add_action( 'admin_footer', array( $this, 'render_modal' ) );
		add_action( 'admin_notices', array( __CLASS__, 'maybe_flash_notice' ) );
		add_action( 'admin_post_ghost_mode_review_was_me', array( $this, 'handle_was_me' ) );
		add_action( 'admin_post_ghost_mode_review_not_me', array( $this, 'handle_not_me' ) );
		add_action( 'admin_post_ghost_mode_review_block', array( $this, 'handle_block' ) );
		add_action( 'admin_post_ghost_mode_review_dismiss', array( $this, 'handle_dismiss' ) );
	}

	/**
	 * Whether attempt review is enabled.
	 */
	public static function is_enabled() {
		$settings = ghost_mode_get_settings();
		return ( $settings['attempt_review_enabled'] ?? 'yes' ) === 'yes';
	}

	/**
	 * @param string        $username Username or email attempted.
	 * @param WP_Error|null $error    Error object.
	 */
	public function on_login_failed( $username, $error = null ) {
		unset( $error );
		if ( ! self::is_enabled() ) {
			return;
		}
		self::track_failure( $username );
	}

	/**
	 * Resolve storage keys for a login attempt (raw input + canonical account).
	 *
	 * @param string $login Username or email.
	 * @return string[]
	 */
	public static function resolve_store_keys( $login ) {
		$raw = trim( (string) $login );
		if ( $raw === '' ) {
			return array();
		}

		$keys = array( strtolower( $raw ) );

		$user = get_user_by( 'login', $raw );
		if ( ! $user && is_email( $raw ) ) {
			$user = get_user_by( 'email', $raw );
		}
		// sanitize_user can strip email characters — also try unsanitized email lookup.
		if ( ! $user && strpos( $raw, '@' ) !== false ) {
			$user = get_user_by( 'email', sanitize_email( $raw ) );
		}

		if ( $user instanceof WP_User ) {
			$keys[] = strtolower( $user->user_login );
			if ( is_email( $user->user_email ) ) {
				$keys[] = strtolower( $user->user_email );
			}
			$keys[] = 'uid:' . (int) $user->ID;
		}

		$ip = Ghost_Mode_Lockout::get_client_ip();
		if ( $ip && $ip !== '0.0.0.0' ) {
			$keys[] = 'ip:' . md5( $ip );
		}

		return array_values( array_unique( array_filter( $keys ) ) );
	}

	/**
	 * Append a failed attempt for later review.
	 *
	 * @param string $username Attempted username or email.
	 */
	public static function track_failure( $username ) {
		$username = trim( (string) $username );
		if ( $username === '' ) {
			return;
		}

		$ip   = Ghost_Mode_Lockout::get_client_ip();
		$mac  = Ghost_Mode_Lockout::get_client_mac();
		$now  = time();
		$keys = self::resolve_store_keys( $username );
		if ( empty( $keys ) ) {
			return;
		}

		$store = get_option( self::RECENT_OPTION, array() );
		if ( ! is_array( $store ) ) {
			$store = array();
		}

		$row = array(
			'ip'       => $ip,
			'mac'      => $mac,
			'time'     => $now,
			'ua'       => self::short_ua(),
			'username' => $username,
		);

		foreach ( $keys as $key ) {
			if ( ! isset( $store[ $key ] ) || ! is_array( $store[ $key ] ) ) {
				$store[ $key ] = array();
			}
			$store[ $key ][] = $row;
			$store[ $key ]   = array_values(
				array_filter(
					array_slice( $store[ $key ], -30 ),
					static function ( $item ) use ( $now ) {
						return is_array( $item ) && ( absint( $item['time'] ?? 0 ) >= ( $now - self::RETENTION ) );
					}
				)
			);
		}

		foreach ( $store as $ukey => $rows ) {
			if ( ! is_array( $rows ) || empty( $rows ) ) {
				unset( $store[ $ukey ] );
			}
		}

		update_option( self::RECENT_OPTION, $store, false );
	}

	/**
	 * @param string  $user_login Username.
	 * @param WP_User $user       User.
	 */
	public function on_successful_login( $user_login, $user ) {
		if ( ! ( $user instanceof WP_User ) ) {
			return;
		}

		if ( ! self::is_enabled() ) {
			self::clear_recent_for_account( $user );
			return;
		}

		$recent = self::collect_recent_for_login( $user_login, $user );
		if ( count( $recent ) < self::MIN_FAILURES ) {
			self::clear_recent_for_account( $user );
			return;
		}

		$success_ip = Ghost_Mode_Lockout::get_client_ip();
		$ips        = array();
		$macs       = array();
		$usernames  = array();

		foreach ( $recent as $row ) {
			$ip = trim( (string) ( $row['ip'] ?? '' ) );
			if ( $ip !== '' && filter_var( $ip, FILTER_VALIDATE_IP ) && $ip !== $success_ip ) {
				$ips[ $ip ] = true;
			}
			$mac = trim( (string) ( $row['mac'] ?? '' ) );
			if ( $mac !== '' ) {
				$macs[ $mac ] = true;
			}
			$tried = trim( (string) ( $row['username'] ?? '' ) );
			if ( $tried !== '' ) {
				$usernames[ $tried ] = true;
			}
		}

		// Same-IP failures (wrong password / username typos) still count.
		if ( empty( $ips ) ) {
			foreach ( $recent as $row ) {
				$ip = trim( (string) ( $row['ip'] ?? '' ) );
				if ( $ip !== '' && filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					$ips[ $ip ] = true;
				}
			}
		}

		$review = array(
			'stage'      => 'ask_was_you',
			'count'      => count( $recent ),
			'ips'        => array_keys( $ips ),
			'macs'       => array_keys( $macs ),
			'tried'      => array_keys( $usernames ),
			'created_at' => time(),
			'username'   => $user_login,
		);

		update_user_meta( (int) $user->ID, self::USER_META, $review );
		self::clear_recent_for_account( $user );
	}

	/**
	 * Merge recent failures for login name, email, user id, and current IP.
	 *
	 * @param string  $user_login Login.
	 * @param WP_User $user       User.
	 * @return array<int, array>
	 */
	public static function collect_recent_for_login( $user_login, WP_User $user ) {
		$keys = array(
			strtolower( (string) $user_login ),
			strtolower( (string) $user->user_login ),
			'uid:' . (int) $user->ID,
		);
		if ( is_email( $user->user_email ) ) {
			$keys[] = strtolower( $user->user_email );
		}
		$ip = Ghost_Mode_Lockout::get_client_ip();
		if ( $ip && $ip !== '0.0.0.0' ) {
			$keys[] = 'ip:' . md5( $ip );
		}
		$keys = array_unique( $keys );

		$store = get_option( self::RECENT_OPTION, array() );
		if ( ! is_array( $store ) ) {
			return array();
		}

		$now  = time();
		$seen = array();
		$out  = array();

		foreach ( $keys as $key ) {
			if ( empty( $store[ $key ] ) || ! is_array( $store[ $key ] ) ) {
				continue;
			}
			foreach ( $store[ $key ] as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$t = absint( $row['time'] ?? 0 );
				if ( $t < ( $now - self::RETENTION ) ) {
					continue;
				}
				$dedupe = md5( ( $row['ip'] ?? '' ) . '|' . ( $row['username'] ?? '' ) . '|' . $t );
				if ( isset( $seen[ $dedupe ] ) ) {
					continue;
				}
				$seen[ $dedupe ] = true;
				$out[]           = $row;
			}
		}

		usort(
			$out,
			static function ( $a, $b ) {
				return absint( $a['time'] ?? 0 ) <=> absint( $b['time'] ?? 0 );
			}
		);

		return $out;
	}

	/**
	 * @param WP_User $user User.
	 */
	public static function clear_recent_for_account( WP_User $user ) {
		$store = get_option( self::RECENT_OPTION, array() );
		if ( ! is_array( $store ) ) {
			return;
		}

		$keys = array(
			strtolower( $user->user_login ),
			'uid:' . (int) $user->ID,
			'ip:' . md5( Ghost_Mode_Lockout::get_client_ip() ),
		);
		if ( is_email( $user->user_email ) ) {
			$keys[] = strtolower( $user->user_email );
		}

		foreach ( $keys as $key ) {
			unset( $store[ $key ] );
		}
		update_option( self::RECENT_OPTION, $store, false );
	}

	/**
	 * @param int $user_id User ID.
	 * @return array<string, mixed>|null
	 */
	public static function get_review( $user_id ) {
		$review = get_user_meta( $user_id, self::USER_META, true );
		if ( ! is_array( $review ) || empty( $review['stage'] ) ) {
			return null;
		}
		if ( absint( $review['created_at'] ?? 0 ) < ( time() - WEEK_IN_SECONDS ) ) {
			delete_user_meta( $user_id, self::USER_META );
			return null;
		}
		return $review;
	}

	public static function clear_review( $user_id ) {
		delete_user_meta( $user_id, self::USER_META );
	}

	public function render_notice() {
		// Modal is the primary UI; keep a compact notice as fallback.
		if ( ! is_user_logged_in() || ! self::get_review( get_current_user_id() ) ) {
			return;
		}
		echo '<div class="notice notice-warning"><p><strong>' . esc_html__( 'Ghost Mode:', 'ghost-mode' ) . '</strong> ';
		echo esc_html__( 'Unusual failed login attempts were detected before your sign-in. Please review the security prompt.', 'ghost-mode' );
		echo '</p></div>';
	}

	/**
	 * Full-screen style modal so the review is hard to miss.
	 */
	public function render_modal() {
		if ( ! is_user_logged_in() ) {
			return;
		}

		$review = self::get_review( get_current_user_id() );
		if ( ! $review ) {
			return;
		}

		$stage   = (string) ( $review['stage'] ?? '' );
		$count   = absint( $review['count'] ?? 0 );
		$ips     = isset( $review['ips'] ) && is_array( $review['ips'] ) ? $review['ips'] : array();
		$tried   = isset( $review['tried'] ) && is_array( $review['tried'] ) ? $review['tried'] : array();
		$ip_list = ! empty( $ips ) ? implode( ', ', array_map( 'strval', $ips ) ) : __( '(unknown)', 'ghost-mode' );
		$tried_l = ! empty( $tried ) ? implode( ', ', array_map( 'strval', $tried ) ) : '';

		$was_me   = wp_nonce_url( admin_url( 'admin-post.php?action=ghost_mode_review_was_me' ), 'ghost_mode_review_was_me' );
		$not_me   = wp_nonce_url( admin_url( 'admin-post.php?action=ghost_mode_review_not_me' ), 'ghost_mode_review_not_me' );
		$block    = wp_nonce_url( admin_url( 'admin-post.php?action=ghost_mode_review_block' ), 'ghost_mode_review_block' );
		$dismiss  = wp_nonce_url( admin_url( 'admin-post.php?action=ghost_mode_review_dismiss' ), 'ghost_mode_review_dismiss' );
		?>
		<div id="ghost-mode-review-modal" class="ghost-mode-review-modal" role="dialog" aria-modal="true" aria-labelledby="ghost-mode-review-title">
			<div class="ghost-mode-review-modal__backdrop"></div>
			<div class="ghost-mode-review-modal__card">
				<?php if ( $stage === 'ask_was_you' ) : ?>
					<h2 id="ghost-mode-review-title"><?php esc_html_e( 'Were these failed login attempts you?', 'ghost-mode' ); ?></h2>
					<p>
						<?php
						printf(
							/* translators: %d: number of attempts */
							esc_html__( 'There were %d failed login attempt(s) before you signed in successfully.', 'ghost-mode' ),
							(int) $count
						);
						?>
					</p>
					<p><strong><?php esc_html_e( 'IP address(es):', 'ghost-mode' ); ?></strong> <code><?php echo esc_html( $ip_list ); ?></code></p>
					<?php if ( $tried_l !== '' ) : ?>
						<p><strong><?php esc_html_e( 'Usernames tried:', 'ghost-mode' ); ?></strong> <code><?php echo esc_html( $tried_l ); ?></code></p>
					<?php endif; ?>
					<p><?php esc_html_e( 'If that was you (typos, wrong password), choose Yes. If not, we can help you block those IPs.', 'ghost-mode' ); ?></p>
					<div class="ghost-mode-review-modal__actions">
						<a class="button button-primary button-hero" href="<?php echo esc_url( $was_me ); ?>"><?php esc_html_e( 'Yes, it was me', 'ghost-mode' ); ?></a>
						<a class="button button-secondary button-hero" href="<?php echo esc_url( $not_me ); ?>"><?php esc_html_e( 'No, it was not me', 'ghost-mode' ); ?></a>
					</div>
				<?php elseif ( $stage === 'ask_block' ) : ?>
					<h2 id="ghost-mode-review-title"><?php esc_html_e( 'Block these suspicious IPs?', 'ghost-mode' ); ?></h2>
					<p><?php esc_html_e( 'These IP address(es) tried to access your account and failed. Block them so they cannot try again?', 'ghost-mode' ); ?></p>
					<p><code><?php echo esc_html( $ip_list ); ?></code></p>
					<div class="ghost-mode-review-modal__actions">
						<a class="button button-primary button-hero" href="<?php echo esc_url( $block ); ?>"><?php esc_html_e( 'Yes, block these IPs', 'ghost-mode' ); ?></a>
						<a class="button button-secondary button-hero" href="<?php echo esc_url( $dismiss ); ?>"><?php esc_html_e( 'No, leave them', 'ghost-mode' ); ?></a>
					</div>
				<?php endif; ?>
			</div>
		</div>
		<style>
			.ghost-mode-review-modal{position:fixed;inset:0;z-index:100000;display:flex;align-items:center;justify-content:center;padding:24px}
			.ghost-mode-review-modal__backdrop{position:absolute;inset:0;background:rgba(15,23,42,.55)}
			.ghost-mode-review-modal__card{position:relative;z-index:1;max-width:520px;width:100%;background:#fff;border-radius:12px;padding:28px 28px 24px;box-shadow:0 24px 64px rgba(0,0,0,.25)}
			.ghost-mode-review-modal__card h2{margin:0 0 12px;font-size:1.35rem;line-height:1.3}
			.ghost-mode-review-modal__card p{margin:0 0 12px;font-size:14px;line-height:1.5}
			.ghost-mode-review-modal__card code{font-size:12px;word-break:break-all}
			.ghost-mode-review-modal__actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:18px}
		</style>
		<?php
	}

	public function handle_was_me() {
		$this->guard( 'ghost_mode_review_was_me' );
		self::clear_review( get_current_user_id() );
		$this->redirect_with( 'review_ok' );
	}

	public function handle_not_me() {
		$this->guard( 'ghost_mode_review_not_me' );
		$user_id = get_current_user_id();
		$review  = self::get_review( $user_id );
		if ( ! $review ) {
			$this->redirect_with( 'review_gone' );
		}
		$review['stage'] = 'ask_block';
		update_user_meta( $user_id, self::USER_META, $review );
		$this->redirect_with( 'review_block_ask' );
	}

	public function handle_block() {
		$this->guard( 'ghost_mode_review_block' );
		$user_id = get_current_user_id();
		$review  = self::get_review( $user_id );
		if ( ! $review ) {
			$this->redirect_with( 'review_gone' );
		}

		$ips     = isset( $review['ips'] ) && is_array( $review['ips'] ) ? $review['ips'] : array();
		$macs    = isset( $review['macs'] ) && is_array( $review['macs'] ) ? $review['macs'] : array();
		$user    = wp_get_current_user();
		$blocked = 0;

		foreach ( $ips as $ip ) {
			if ( Ghost_Mode_Lockout::block_value( 'ip', (string) $ip, $user->user_login, 'user_review' ) ) {
				$blocked++;
			}
		}
		foreach ( $macs as $mac ) {
			Ghost_Mode_Lockout::block_value( 'mac', (string) $mac, $user->user_login, 'user_review' );
		}

		self::clear_review( $user_id );
		$this->redirect_with( 'review_blocked', array( 'blocked' => $blocked ) );
	}

	public function handle_dismiss() {
		$this->guard( 'ghost_mode_review_dismiss' );
		self::clear_review( get_current_user_id() );
		$this->redirect_with( 'review_dismissed' );
	}

	/**
	 * @param string $action Nonce/action.
	 */
	private function guard( $action ) {
		if ( ! is_user_logged_in() ) {
			wp_die( esc_html__( 'Unauthorized', 'ghost-mode' ) );
		}
		check_admin_referer( $action );
	}

	/**
	 * @param string               $flag Query flag.
	 * @param array<string, mixed> $extra Extra args.
	 */
	private function redirect_with( $flag, $extra = array() ) {
		$args = array_merge( array( 'gm_review' => $flag ), $extra );
		$ref  = wp_get_referer();
		if ( ! $ref || strpos( $ref, 'admin-post.php' ) !== false ) {
			$ref = admin_url();
		}
		wp_safe_redirect( add_query_arg( $args, $ref ) );
		exit;
	}

	private static function short_ua() {
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		return strlen( $ua ) > 120 ? substr( $ua, 0, 117 ) . '...' : $ua;
	}

	/**
	 * Flash messages after review actions.
	 */
	public static function maybe_flash_notice() {
		if ( empty( $_GET['gm_review'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$flag = sanitize_key( wp_unslash( $_GET['gm_review'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$map  = array(
			'review_ok'        => array( 'success', __( 'Thanks — those failed attempts were marked as yours. No IPs were blocked.', 'ghost-mode' ) ),
			'review_block_ask' => array( 'warning', __( 'Confirm whether to block the suspicious IP addresses.', 'ghost-mode' ) ),
			'review_blocked'   => array( 'success', __( 'Suspicious IP address(es) have been blocked.', 'ghost-mode' ) ),
			'review_dismissed' => array( 'info', __( 'Review dismissed. No IPs were blocked.', 'ghost-mode' ) ),
			'review_gone'      => array( 'info', __( 'That review is no longer available.', 'ghost-mode' ) ),
		);
		if ( ! isset( $map[ $flag ] ) ) {
			return;
		}
		list( $type, $msg ) = $map[ $flag ];
		if ( $flag === 'review_blocked' && isset( $_GET['blocked'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$n   = absint( $_GET['blocked'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$msg = sprintf(
				/* translators: %d: number of IPs */
				_n( '%d suspicious IP has been blocked.', '%d suspicious IPs have been blocked.', $n, 'ghost-mode' ),
				$n
			);
		}
		printf(
			'<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>',
			esc_attr( $type ),
			esc_html( $msg )
		);
	}
}
