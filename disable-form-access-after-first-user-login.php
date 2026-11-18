<?php
/**
 * Snippet Name: Form 9 — First Login Access Window
 * Description: Restrict form 9 to 14 days after first recorded login, with inline access notices and an admin override on the user profile.
 * Version: 1.1.0
 *
 * Install in wp-content/mu-plugins/, or use a PHP snippets plugin set to run
 * everywhere (omit the opening PHP tag there).
 *
 * Existing users need a known historical UTC Unix timestamp migrated to the key
 * below, or must log out/in to start their window after installation. Registration
 * dates are never used. Later logins never reset a recorded timestamp.
 *
 * Admin override: users with the edit_users capability see a "Form 9 Application
 * Access" section at the bottom of Users → Edit User (and their own Profile).
 * From there they can view the status, edit the timestamp (entered in the site
 * timezone, stored as UTC Unix), or remove it. Removing it starts a fresh 14-day
 * window at the user's next login.
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
	const AUDIT_KEY       = '_gw_form_9_first_login_audit';

	// Admin profile section.
	const FIELD_DATE   = 'gw_form_9_first_login_local';
	const FIELD_ORIG   = 'gw_form_9_first_login_original';
	const FIELD_ACTION = 'gw_form_9_action';
	const NONCE_FIELD  = '_gw_form_9_nonce';
	const NONCE_ACTION = 'gw_form_9_first_login_admin_';
	const INPUT_FORMAT = 'Y-m-d\TH:i:s';

	/** @var array<int,int> user_id => new timestamp (0 = remove), set during validation, written after a successful profile save. */
	private static $pending = array();

	public static function init() {
		add_action( 'wp_login', array( __CLASS__, 'record_first_login' ), 1, 2 );

		// Stop rendering before resume loading or GPASC autoloading can run.
		add_filter( 'gform_form_args', array( __CLASS__, 'check_form_args' ), 1 );
		add_filter( 'gform_form_not_found_message', array( __CLASS__, 'access_notice' ), 10, 2 );

		// Stop stale POSTs before validation, uploads, entry creation, or draft saves.
		add_filter( 'gform_pre_process_9', array( __CLASS__, 'check_submission' ), 1 );

		// Defense in depth for direct draft writes, including GPASC blank-draft AJAX.
		add_filter( 'gform_incomplete_submission_pre_save', array( __CLASS__, 'check_draft_save' ), 1, 3 );

		// Admin override section, rendered last so it sits at the bottom of the user record.
		add_action( 'show_user_profile', array( __CLASS__, 'render_admin_section' ), PHP_INT_MAX );
		add_action( 'edit_user_profile', array( __CLASS__, 'render_admin_section' ), PHP_INT_MAX );
		add_action( 'user_profile_update_errors', array( __CLASS__, 'validate_admin_section' ), 10, 3 );
		add_action( 'profile_update', array( __CLASS__, 'save_admin_section' ), 10, 1 );
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

	/**
	 * Returns the stored first-login timestamp as a positive int, or 0 if missing/invalid.
	 */
	private static function get_first_login( $user_id ) {
		$value = get_user_meta( $user_id, self::FIRST_LOGIN_KEY, true );
		if ( ! is_scalar( $value ) || ! ctype_digit( (string) $value ) ) {
			return 0;
		}
		return (int) $value;
	}

	private static function denial_message() {
		if ( ! is_user_logged_in() ) {
			return 'Please log in to access this application form.';
		}

		$first_login = self::get_first_login( get_current_user_id() );
		if ( $first_login <= 0 || $first_login > time() ) {
			return 'Your first login has not been recorded. Please log out and log back in. If this message persists, contact the application office.';
		}

		if ( time() >= $first_login + self::WINDOW_DAYS * DAY_IN_SECONDS ) {
			return 'Your 14-day application access period has expired. You can no longer open, resume, save, or submit this application. Please contact the application office if you need assistance.';
		}
		return '';
	}

	private static function prevent_caching() {
		if ( ! headers_sent() ) {
			nocache_headers();
		}
	}

	/* ---------------------------------------------------------------------
	 * Admin override section on the user record
	 * ------------------------------------------------------------------- */

	private static function can_manage( $user_id ) {
		return current_user_can( 'edit_users' ) && current_user_can( 'edit_user', $user_id );
	}

	private static function notice_key( $user_id ) {
		return 'gw_form_9_notice_' . get_current_user_id() . '_' . (int) $user_id;
	}

	/**
	 * Human-readable description of a raw stored value (for "before/after" displays).
	 */
	private static function describe_value( $raw ) {
		if ( null === $raw || '' === $raw || false === $raw ) {
			return '(blank)';
		}
		if ( ! is_scalar( $raw ) ) {
			return '(invalid, non-scalar value)';
		}
		if ( ctype_digit( (string) $raw ) && (int) $raw > 0 ) {
			return wp_date( 'Y-m-d H:i:s T', (int) $raw ) . ' — Unix ' . $raw;
		}
		return '(invalid: ' . $raw . ')';
	}

	/**
	 * Parse a datetime-local value in the site timezone. Returns a Unix timestamp or null.
	 */
	private static function parse_local( $value ) {
		foreach ( array( 'Y-m-d\TH:i:s', 'Y-m-d\TH:i' ) as $format ) {
			$dt = DateTimeImmutable::createFromFormat( '!' . $format, $value, wp_timezone() );
			// Round-trip check rejects overflow dates (Feb 30) and times skipped by DST.
			if ( $dt && $dt->format( $format ) === $value && $dt->getTimestamp() > 0 ) {
				return $dt->getTimestamp();
			}
		}
		return null;
	}

	private static function admin_status( $raw, $first ) {
		$now = time();

		if ( $first <= 0 ) {
			if ( '' === $raw || null === $raw ) {
				return array(
					'Not recorded',
					'#646970',
					'No timestamp is stored. A new 14-day window will start the next time this user logs in. If they are logged in right now, they must log out and back in first.',
				);
			}
			return array( 'Invalid value', '#b32d2e', 'The stored value is not a valid timestamp, so the user is blocked. Remove it or enter a valid time.' );
		}

		if ( $first > $now ) {
			return array( 'Invalid (future)', '#b32d2e', 'The stored time is in the future, so the user is blocked. Remove it or enter a valid time.' );
		}

		$end = $first + self::WINDOW_DAYS * DAY_IN_SECONDS;
		if ( $now >= $end ) {
			return array(
				'Expired',
				'#b32d2e',
				'Access expired on ' . wp_date( 'Y-m-d H:i:s T', $end ) . ' (' . human_time_diff( $end, $now ) . ' ago). To give an extension, remove the timestamp or enter a later time.',
			);
		}

		return array(
			'Active',
			'#00a32a',
			'Access ends ' . wp_date( 'Y-m-d H:i:s T', $end ) . ' (' . human_time_diff( $now, $end ) . ' remaining).',
		);
	}

	public static function render_admin_section( $user ) {
		if ( ! ( $user instanceof WP_User ) || ! self::can_manage( $user->ID ) ) {
			return;
		}

		$raw    = get_user_meta( $user->ID, self::FIRST_LOGIN_KEY, true );
		$first  = self::get_first_login( $user->ID );
		$status = self::admin_status( $raw, $first );
		$input  = $first > 0 ? wp_date( self::INPUT_FORMAT, $first ) : '';
		$tz     = wp_timezone();
		$offset = $tz->getOffset( new DateTimeImmutable( 'now', $tz ) );

		$notice = get_transient( self::notice_key( $user->ID ) );
		if ( $notice ) {
			delete_transient( self::notice_key( $user->ID ) );
		}

		$audit = get_user_meta( $user->ID, self::AUDIT_KEY, true );

		$confirm_text = "Remove the Form 9 first-login timestamp for this user?\n\n"
			. 'Current: ' . self::describe_value( $raw ) . "\n"
			. "After: (blank)\n\n"
			. 'They will get a new ' . self::WINDOW_DAYS . '-day window at their next login.';
		?>
		<div id="gw-form-9-access" style="margin:2.5em 0 1.5em;padding:1em 1.5em 0.5em;border:2px solid #2271b1;border-left-width:6px;background:#fff;">
			<h2 style="margin-top:0.25em;">Form 9 Application Access (<?php echo (int) self::WINDOW_DAYS; ?>-day window)</h2>

			<?php if ( is_array( $notice ) ) : ?>
				<div class="notice notice-success inline" style="margin:0 0 1em;">
					<p>
						<strong>First-login timestamp updated.</strong><br>
						Before: <code><?php echo esc_html( self::describe_value( $notice['old'] ) ); ?></code><br>
						After: <code><?php echo esc_html( self::describe_value( $notice['new'] ) ); ?></code>
					</p>
				</div>
			<?php endif; ?>

			<table class="form-table" role="presentation">
				<tr>
					<th scope="row">Status</th>
					<td>
						<span style="display:inline-block;padding:2px 10px;border-radius:3px;color:#fff;font-weight:600;background:<?php echo esc_attr( $status[1] ); ?>;"><?php echo esc_html( $status[0] ); ?></span>
						<p class="description"><?php echo esc_html( $status[2] ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row">Current stored value</th>
					<td>
						<code style="display:inline-block;padding:4px 8px;"><?php echo esc_html( self::describe_value( $raw ) ); ?></code>
						<p class="description">Meta key: <code><?php echo esc_html( self::FIRST_LOGIN_KEY ); ?></code></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="<?php echo esc_attr( self::FIELD_DATE ); ?>">First login time</label></th>
					<td>
						<input type="datetime-local" step="1"
							id="<?php echo esc_attr( self::FIELD_DATE ); ?>"
							name="<?php echo esc_attr( self::FIELD_DATE ); ?>"
							value="<?php echo esc_attr( $input ); ?>">
						<button type="button" class="button" id="gw-form-9-now">Use current time</button>
						<p class="description">
							Entered in the site timezone (<?php echo esc_html( wp_timezone_string() ); ?>). The window ends <?php echo (int) self::WINDOW_DAYS; ?> days after this time.
							Clearing the field and saving has the same effect as Remove timestamp.
						</p>
					</td>
				</tr>
				<tr>
					<th scope="row">Actions</th>
					<td>
						<button type="submit" class="button button-primary" name="gw_form_9_save" value="1">Save first-login time</button>
						<button type="submit" class="button" id="gw-form-9-clear"
							name="<?php echo esc_attr( self::FIELD_ACTION ); ?>" value="clear"
							style="margin-left:0.5em;color:#b32d2e;border-color:#b32d2e;">Remove timestamp</button>
						<p class="description">These buttons save the whole user record, the same as Update User. Changes made in this section are also saved when you click Update User.</p>
					</td>
				</tr>
				<?php if ( is_array( $audit ) && ! empty( $audit['at'] ) ) : ?>
					<?php $by = get_userdata( (int) $audit['by'] ); ?>
					<tr>
						<th scope="row">Last admin change</th>
						<td>
							<?php echo esc_html( wp_date( 'Y-m-d H:i:s T', (int) $audit['at'] ) ); ?>
							by <?php echo esc_html( $by ? $by->display_name : 'user #' . (int) $audit['by'] ); ?><br>
							<code><?php echo esc_html( self::describe_value( $audit['old'] ) ); ?></code>
							&rarr; <code><?php echo esc_html( self::describe_value( $audit['new'] ) ); ?></code>
						</td>
					</tr>
				<?php endif; ?>
			</table>

			<?php wp_nonce_field( self::NONCE_ACTION . $user->ID, self::NONCE_FIELD ); ?>
			<input type="hidden" name="<?php echo esc_attr( self::FIELD_ORIG ); ?>" value="<?php echo esc_attr( $input ); ?>">

			<script>
			( function () {
				var clearBtn = document.getElementById( 'gw-form-9-clear' );
				var nowBtn   = document.getElementById( 'gw-form-9-now' );
				var field    = document.getElementById( <?php echo wp_json_encode( self::FIELD_DATE ); ?> );
				var offset   = <?php echo (int) $offset; ?>;
				var message  = <?php echo wp_json_encode( $confirm_text ); ?>;

				if ( clearBtn ) {
					clearBtn.addEventListener( 'click', function ( e ) {
						if ( ! window.confirm( message ) ) {
							e.preventDefault();
						}
					} );
				}

				if ( nowBtn && field ) {
					nowBtn.addEventListener( 'click', function () {
						var d = new Date( Date.now() + offset * 1000 );
						var p = function ( n ) { return String( n ).padStart( 2, '0' ); };
						field.value = d.getUTCFullYear() + '-' + p( d.getUTCMonth() + 1 ) + '-' + p( d.getUTCDate() ) +
							'T' + p( d.getUTCHours() ) + ':' + p( d.getUTCMinutes() ) + ':' + p( d.getUTCSeconds() );
					} );
				}
			} )();
			</script>
		</div>
		<?php
	}

	/**
	 * Validate before WordPress saves the user. Errors here block the whole save,
	 * matching how core profile fields behave. Valid changes are queued and written
	 * in save_admin_section() only after the user update succeeds.
	 */
	public static function validate_admin_section( $errors, $update, $user ) {
		if ( ! $update || empty( $user->ID ) || ! isset( $_POST[ self::NONCE_FIELD ] ) ) {
			return;
		}

		$user_id = (int) $user->ID;
		$nonce   = sanitize_text_field( wp_unslash( $_POST[ self::NONCE_FIELD ] ) );

		if ( ! self::can_manage( $user_id ) || ! wp_verify_nonce( $nonce, self::NONCE_ACTION . $user_id ) ) {
			$errors->add( 'gw_form_9_nonce', '<strong>Error:</strong> The Form 9 access change could not be verified. Reload the page and try again.' );
			return;
		}

		$action = isset( $_POST[ self::FIELD_ACTION ] ) ? sanitize_key( wp_unslash( $_POST[ self::FIELD_ACTION ] ) ) : '';
		if ( 'clear' === $action ) {
			self::$pending[ $user_id ] = 0;
			return;
		}

		$submitted = isset( $_POST[ self::FIELD_DATE ] ) ? trim( sanitize_text_field( wp_unslash( $_POST[ self::FIELD_DATE ] ) ) ) : '';
		$original  = isset( $_POST[ self::FIELD_ORIG ] ) ? trim( sanitize_text_field( wp_unslash( $_POST[ self::FIELD_ORIG ] ) ) ) : '';

		if ( $submitted === $original ) {
			return; // Unchanged; leave the stored value alone.
		}

		if ( '' === $submitted ) {
			self::$pending[ $user_id ] = 0;
			return;
		}

		$timestamp = self::parse_local( $submitted );
		if ( null === $timestamp ) {
			$errors->add( 'gw_form_9_invalid', '<strong>Error:</strong> The Form 9 first login time is not a valid date and time in the site timezone.' );
			return;
		}
		if ( $timestamp > time() ) {
			$errors->add( 'gw_form_9_future', '<strong>Error:</strong> The Form 9 first login time cannot be in the future. To extend access, use a recent time or remove the timestamp.' );
			return;
		}

		self::$pending[ $user_id ] = $timestamp;
	}

	public static function save_admin_section( $user_id ) {
		$user_id = (int) $user_id;
		if ( ! array_key_exists( $user_id, self::$pending ) ) {
			return;
		}

		$new = self::$pending[ $user_id ];
		unset( self::$pending[ $user_id ] );

		$old = get_user_meta( $user_id, self::FIRST_LOGIN_KEY, true );
		$old = is_scalar( $old ) ? (string) $old : '';

		if ( $new > 0 ) {
			update_user_meta( $user_id, self::FIRST_LOGIN_KEY, $new );
		} else {
			delete_user_meta( $user_id, self::FIRST_LOGIN_KEY );
		}

		$record = array(
			'old' => $old,
			'new' => $new > 0 ? (string) $new : '',
		);

		update_user_meta( $user_id, self::AUDIT_KEY, $record + array(
			'by' => get_current_user_id(),
			'at' => time(),
		) );

		set_transient( self::notice_key( $user_id ), $record, 5 * MINUTE_IN_SECONDS );
	}
}

GW_Form_9_First_Login_Access::init();
