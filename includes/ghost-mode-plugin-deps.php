<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! function_exists( 'ghost_mode_is_plugin_active_by_main_file' ) ) {
	/**
	 * Whether a plugin is active, matched by main PHP filename (folder-independent).
	 *
	 * @param string $main_file e.g. ngobuddy.php
	 */
	function ghost_mode_is_plugin_active_by_main_file( $main_file ) {
		$main_file = basename( ltrim( $main_file, '/' ) );
		if ( $main_file === '' ) {
			return false;
		}

		if ( ! function_exists( 'is_plugin_active' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		foreach ( (array) get_option( 'active_plugins', array() ) as $plugin_file ) {
			if ( basename( $plugin_file ) === $main_file && is_plugin_active( $plugin_file ) ) {
				return true;
			}
		}

		if ( is_multisite() ) {
			$network_active = (array) get_site_option( 'active_sitewide_plugins', array() );
			foreach ( array_keys( $network_active ) as $plugin_file ) {
				if ( basename( $plugin_file ) === $main_file ) {
					return true;
				}
			}
		}

		return false;
	}
}

if ( ! function_exists( 'ghost_mode_is_ngobuddy_active' ) ) {
	/**
	 * Soft detect NGOBuddy (optional complement — not required).
	 * When active, Ghost Mode settings appear under the NGOBuddy menu.
	 */
	function ghost_mode_is_ngobuddy_active() {
		return defined( 'GDNB_DONATIONS_VERSION' )
			|| defined( 'NBF_DONATIONS_VERSION' )
			|| ghost_mode_is_plugin_active_by_main_file( 'ngobuddy.php' )
			|| ghost_mode_is_plugin_active_by_main_file( 'nbf-donations.php' );
	}
}
