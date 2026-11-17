<?php
/**
 * Plugin Name: Form 9 — First Login Access Window
 * Description: Restrict form 9 to 14 days after first recorded login, with inline access notices.
 * Version: 1.0.0
 *
 * REPLACE the previous version; do not activate both copies.
 * Install in wp-content/mu-plugins/, or use a PHP snippets plugin set to run
 * everywhere (omit the opening PHP tag there).
 *
 * Existing users need a known historical UTC Unix timestamp migrated to the key
 * below, or must log out/in to start their window after installation. Registration
 * dates are never used. Later logins never reset a recorded timestamp.
 *
 * Exclude form/resume pages from full-page/CDN caching and purge existing caches.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class GW_Form_9_First_Login_Access {

	const FORM_ID         = 9;
	const WINDOW_DAYS     = 14;
	const FIRST_LOGIN_KEY = '_gw_form_9_first_login_utc';

	public static function init() {
		add_action( 'wp_login', array( __CLASS__, 'record_first_login' ), 1, 2 );

		// Stop rendering before resume loading or GPASC autoloading can run.
		add_filter( 'gform_form_args', array( __CLASS__, 'check_form_args' ), 1 );
		add_filter( 'gform_form_not_found_message', array( __CLASS__, 'access_notice' ), 10, 2 );

		// Stop stale POSTs before validation, uploads, entry creation, or draft saves.
		add_filter( 'gform_pre_process_9', array( __CLASS__, 'check_submission' ), 1 );

		// Defense in depth for direct draft writes, including GPASC blank-draft AJAX.
		add_filter( 'gform_incomplete_submission_pre_save', array( __CLASS__, 'check_draft_save' ), 1, 3 );
	}

	public static function record_first_login( $user_login, $user ) {
		add_user_meta( $user->ID, self::FIRST_LOGIN_KEY, time(), true );
	}

	private static function is_target_form( $form_id ) {
		if ( $form_id && ! is_numeric( $form_id ) ) {
			$form_id = GFFormsModel::get_form_id( $form_id );
		}
		return (int) $form_id === self::FORM_ID;
	}

	public static function check_form_args( $args ) {
		if ( isset( $args['form_id'] ) && self::is_target_form( $args['form_id'] ) && self::denial_message() ) {
			// GF's empty-ID branch returns replaceable HTML without loading the form.
			// The not-found filter receives the ORIGINAL requested form ID/title.
			$args['form_id'] = 0;
			self::prevent_caching();
		}
		return $args;
	}

	public static function access_notice( $html, $form_id ) {
		$message = self::is_target_form( $form_id ) ? self::denial_message() : '';
		if ( $message ) {
			return '<div class="gw-form-9-access-notice" role="status" style="box-sizing:border-box;width:100%;max-width:48rem;margin:2rem auto;padding:1.5rem;text-align:center;"><p style="margin:0;">' . esc_html( $message ) . '</p></div>';
		}
		return $html;
	}

	public static function check_submission( $form ) {
		$message = self::denial_message();
		if ( $message ) {
			self::prevent_caching();
			// Mark only this in-memory copy inactive so process_form() returns early.
			// Do NOT persist this change: the form remains active for eligible users.
			$form['is_active'] = false;

			// GFAPI and native AJAX understand form-level errors and re-render the embed.
			GFFormDisplay::$submission[ self::FORM_ID ] = array(
				'is_valid'         => false,
				'form'             => $form,
				'form_level_error' => $message,
			);
		}
		return $form;
	}

	public static function check_draft_save( $submission_json, $resume_token, $form ) {
		if ( (int) $form['id'] === self::FORM_ID ) {
			$message = self::denial_message();
			if ( $message ) {
				self::prevent_caching();
				// Direct/background writes cannot proceed. Ordinary views and POSTs
				// are handled above without invoking WordPress's standalone error page.
				if ( wp_doing_ajax() ) {
					wp_send_json_error( array( 'message' => $message ), 403 );
				}
				wp_die( esc_html( $message ), 'Application access unavailable', array( 'response' => 403 ) );
			}
		}
		return $submission_json;
	}

	private static function denial_message() {
		if ( ! is_user_logged_in() ) {
			return 'Please log in to access this application form.';
		}

		$first_login = get_user_meta( get_current_user_id(), self::FIRST_LOGIN_KEY, true );
		if ( ! is_scalar( $first_login ) || ! ctype_digit( (string) $first_login ) || (int) $first_login <= 0 || (int) $first_login > time() ) {
			return 'Your first login has not been recorded. Please log out and log back in. If this message persists, contact the application office.';
		}

		if ( time() >= (int) $first_login + self::WINDOW_DAYS * DAY_IN_SECONDS ) {
			return 'Your 14-day application access period has expired. You can no longer open, resume, save, or submit this application. Please contact the application office if you need assistance.';
		}
		return '';
	}

	private static function prevent_caching() {
		if ( ! headers_sent() ) {
			nocache_headers();
		}
	}
}

GW_Form_9_First_Login_Access::init();
?>
