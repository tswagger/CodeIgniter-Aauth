<?php
/**
 * CodeIgniter-Aauth
 *
 * Aauth is a User Authorization Library for CodeIgniter 4.x, which aims to make
 * easy some essential jobs such as login, permissions and access operations.
 * Despite ease of use, it has also very advanced features like grouping,
 * access management, public access etc..
 *
 * @package   CodeIgniter-Aauth
 * @since     3.0.0
 * @author    Emre Akay
 * @author    Raphael "REJack" Jackstadt
 * @copyright 2014-2019 Emre Akay
 * @license   https://opensource.org/licenses/MIT   MIT License
 * @link      https://github.com/emreakay/CodeIgniter-Aauth
 */

namespace Config;

use CodeIgniter\Config\BaseConfig;

/**
 * Aauth Config
 *
 * @package CodeIgniter-Aauth
 *
 * phpcs:disable Squiz.Commenting.VariableComment
 */
class Aauth extends BaseConfig
{
	/*
	|--------------------------------------------------------------------------
	| Link Variables
	|--------------------------------------------------------------------------
	|
	| 'linkNoPermission'
	|
	|	If user don't have permission to see the page he will be redirected
	|	the page specified.
	|	Available Options:
	|	 - false (control() returns booleans)
	|	 - 'error' (control() throws an error)
	|	 - any uri/url string (control() redirect to set value)
	|	(default: false)
	|
	| 'linkResetPassword'
	|
	|	Link for reset_password without site_url or base_url
	|	(default: '/account/reset_password/index')
	|
	| 'linkVerification'
	|
	|	Link for verification without site_url or base_url
	|	(default: '/account/verification/index')
	|
	*/
	public $linkNoPermission  = false;
	public $linkResetPassword = '/account/reset_password/index';
	public $linkVerification  = '/account/verification/index';

	/*
	|--------------------------------------------------------------------------
	| User Variables
	|--------------------------------------------------------------------------
	|
	| 'userActiveTime'
	|
	|	User Active Time, time range for session time checkup
	|	(default: '5 minutes')
	|
	| 'userVerification'
	|
	|	User Verification, if TRUE sends a verification email on account creation
	|	(default: false)
	|
	| 'userRegexPattern'
	|
	|	Regex pattern for valid chars for username
	|	(default: '^[a-zA-Z0-9]{3,}$')
	|
	*/
	public $userActiveTime   = '5 minutes';
	public $userVerification = false;
	public $userRegexPattern = '^[a-zA-Z0-9]{3,}$';

	/*
	|--------------------------------------------------------------------------
	| Password Variables
	|--------------------------------------------------------------------------
	|
	| 'passwordMin'
	|
	|	Password min char length
	|	(default: 8)
	|
	| 'passwordMax'
	|
	|	Password max char length
	|	(default: 32)
	|
	| 'passwordHashAlgo'
	|
	|	password_hash algorithm (PASSWORD_DEFAULT, PASSWORD_BCRYPT)
	|	for details see http://php.net/manual/de/password.constants.php
	|	(default: PASSWORD_DEFAULT)
	|
	| 'passwordHashOptions'
	|
	|	password_hash options array
	|	for details see http://php.net/manual/en/function.password-hash.php
	|	(default: [])
	|
	*/
	public $passwordMin         = 8;
	public $passwordMax         = 32;
	public $passwordHashAlgo    = PASSWORD_DEFAULT;
	public $passwordHashOptions = [];

	/*
	|--------------------------------------------------------------------------
	| Login Variables
	|--------------------------------------------------------------------------
	|
	| 'loginRemember'
	|
	|	Remember time (in relative format) elapsed after connecting and automatic
	|	logout for usage with cookies.
	|	Relative format (e.g. '+ 1 week', '+ 1 month') for details see
	|	http://php.net/manual/de/datetime.formats.relative.php
	|	(default: '+14 days')
	|
	| 'loginRememberCookie'
	|
	|	Remember cookie name.
	|	(default: 'remember')
	|
	| 'loginSingleMode'
	|
	|	Login Single Mode, if true only one session per user can be active.
	|	(default: false)
	|
	| 'loginUseUsername'
	|
	|	Login Identificator, if TRUE username needed to login else email address
	|	(default: false)
	|
	| 'loginAccurateErrors'
	|
	|	Enables unified error message (loginFailedAll vs loginFailedEmail/loginFailedUsername)
	|	(default: false)
	|
	| 'loginProtection'
	|
	|	Enables the DDoS Protection, user will be banned temporary when he exceed the login 'try'
	|	(default: true)
	|
	| 'loginAttemptCookie'
	|
	|	Login attempts count & block trough Cookie instead of Login Attempt DB & IP
	|	You can set a string to set the cookie name, default cookie name is logins.
	|	(default: false)
	|
	| 'loginAttemptLimit'
	|
	|	Login attempts limit
	|	(default: 10)
	|
	| 'loginAttemptLimitTimePeriod'
	|
	|	Period of time for max login attempts
	|	(default: '5 minutes')
	|
	| 'loginAttemptRemoveSuccessful'
	|
	|	Enables removing login attempt after successful login
	|	(default: true)
	|
	*/
	public $loginRemember                = '+14 days';
	public $loginRememberCookie          = 'remember';
	public $loginSingleMode              = false;
	public $loginUseUsername             = false;
	public $loginAccurateErrors          = false;
	public $loginProtection              = true;
	public $loginAttemptCookie           = false;
	public $loginAttemptLimit            = 10;
	public $loginAttemptLimitTimePeriod  = '5 minutes';
	public $loginAttemptRemoveSuccessful = true;

	/*
	|--------------------------------------------------------------------------
	| Email Variables
	|--------------------------------------------------------------------------
	|
	| 'emailFrom'
	|
	|	Sender email address, used for remind_password, send_verification and
	|	reset_password
	|	(default: 'admin@example.com')
	|
	| 'emailFromName'
	|
	|	Sender name, used for remind_password, send_verification and
	|	reset_password
	|	(default: 'Aauth v3')
	|
	| 'emailConfig'
	|
	|	Array of Config for CI's Email Library
	|	(default: [])
	|
	*/
	public $emailFrom     = 'sys@xpresspaper.eu';
	public $emailFromName = 'Aauth v3';
	public $emailConfig   = [];

	/*
	|--------------------------------------------------------------------------
	| Time-based One-time Password Algorithm Variables
	|--------------------------------------------------------------------------
	|
	| 'totpEnabled'
	|
	|	Enables the Time-based One-time Password Algorithm
	|	(default: false)
	|
	| 'totpOnIpChange'
	|
	|	TOTP only on IP Change
	|	(default: false)
	|
	| 'totpResetPassword'
	|
	|	Reset TOTP secret on reset_password()
	|	(default: false)
	|
	| 'totpLogin'
	|
	|	TOTP required if uses has TOTP secret on login()
	|	(default: false)
	|
	| 'totpLink'
	|
	|	Redirect path to TOTP Verification page
	|	(default: '/account/twofactor_verification/index')
	|
	*/
	public $totpEnabled       = false;
	public $totpOnIpChange    = false;
	public $totpResetPassword = false;
	public $totpLogin         = false;
	public $totpLink          = '/account/twofactor_verification/index';

	/*
	|--------------------------------------------------------------------------
	| CAPTCHA Variables
	|--------------------------------------------------------------------------
	|
	| 'captchaEnabled'
	|
	|	Enables CAPTCHA
	|	(default: false)
	|
	| 'captchaType'
	|
	|	CAPTCHA Types
	|	Available Options:
	|	 - 'recaptcha' (for details see https://www.google.com/captcha/admin)
	|	 - 'hcaptcha' (for details see https://hcaptcha.com/docs)
	|	(default: 'recaptcha')
	|
	| 'captchaLoginAttempts'
	|
	|	Login Attempts to display CAPTCHA
	|	(default: 6)
	|
	| 'captchaSiteKey'
	|
	|	The CAPTCHA siteKey
	|	(default: '')
	|
	| 'captchaSecret'
	|
	|	The CAPTCHA secretKey
	|	(default: '')
	|
	*/
	public $captchaEnabled       = false;
	public $captchaType          = 'recaptcha';
	public $captchaLoginAttempts = 6;
	public $captchaSiteKey       = '';
	public $captchaSecret        = '';

	/*
	|--------------------------------------------------------------------------
	| Social Login Variables
	|--------------------------------------------------------------------------
	|
	| 'socialEnabled'
	|
	|	Enables the oAuth2 functionalities to login or createUser trough social
	|	logins like google, facebook, twitter, github and many more.
	|	(default: false)
	|
	| 'socialRemeber'
	|
	|	Remember social login user.
	|	Available Options:
	|	 - false (disabled)
	|	 - true (use social expires date)
	|	 - Relative date format (e.g. '+ 1 week', '+ 1 month') for details
	|		  see http://php.net/manual/de/datetime.formats.relative.php
	|	(default: true)
	|
	| 'socialProviders'
	|
	|	Social Provider list
	|	(default: [])
	|
	*/
	public $socialEnabled   = false;
	public $socialRemember  = true;
	public $socialProviders = [];

	/*
	|--------------------------------------------------------------------------
	| Group Variables
	|--------------------------------------------------------------------------
	|
	| 'groupAdmin'
	|
	|	Name of admin group
	|	(default: 'admin')
	|
	| 'groupDefault'
	|
	|	Name of default group, the new user is added in it
	|	(default: 'default')
	|
	| 'groupPublic'
	|
	|	Name of Public group , people who not logged in
	|	(default: 'public')
	|
	*/
	public $groupAdmin   = 'admin';
	public $groupDefault = 'default';
	public $groupPublic  = 'public';

	/*
	|--------------------------------------------------------------------------
	| Modules Variables
	|--------------------------------------------------------------------------
	|
	| 'modules'
	|
	|	Array of active modules
	|	(default: [])
	|
	*/
	public $modules = [];

	/*
	|--------------------------------------------------------------------------
	| Database Variables
	|--------------------------------------------------------------------------
	|
	| 'dbProfile'
	|
	|	The configuration database profile (defined in Config/Database.php)
	|	(default: 'default')
	|
	| 'dbReturnType'
	|
	|	The format that the results should be returned as, for any get* &
	|	list* function. (e.g. getUser, listUsers, ...).
	|	Available types:
	|	 - array
	|	 - object
	|	(default: 'array')
	|
	| 'dbTableUsers'
	|
	|	The table which contains users
	|	(default: 'aauth_users')
	|
	| 'dbTableUserSessions'
	|
	|	The table which contains user sessions
	|	(default: 'aauth_user_sessions')
	|
	| 'dbTableUserVariables'
	|
	|	The table which contains users variables
	|	(default: 'aauth_user_variables')
	|
	| 'dbTableLoginAttempts'
	|
	|	The table which contains login attempts
	|	(default: 'aauth_login_attempts')
	|
	| 'dbTableLoginTokens'
	|
	|	The table which contains login tokens
	|	(default: 'aauth_login_tokens')
	|
	| 'dbTableGroups'
	|
	|	The table which contains groups
	|	(default: 'aauth_groups')
	|
	| 'dbTableGroupToUser'
	|
	|	The table which contains join of users and groups
	|	(default: 'aauth_group_to_user')
	|
	| 'dbTableGroupToGroup'
	|
	|	The table which contains join of subgroups and groups
	|	(default: 'aauth_group_to_group')
	|
	| 'dbTableGroupVariables'
	|
	|	The table which contains group variables
	|	(default: 'aauth_group_variables')
	|
	| 'dbTablePerms'
	|
	|	The table which contains permissions
	|	(default: 'aauth_perms')
	|
	| 'dbTablePermToUser'
	|
	|	The table which contains permissions for users
	|	(default: 'aauth_perm_to_user')
	|
	| 'dbTablePermToGroup'
	|
	|	The table which contains permissions for groups
	|	(default: 'aauth_perm_to_group')
	|
	| 'dbSoftDeleteUsers'
	|
	|	Enables soft delete for Users
	|	 If this is enabled, it simply set a flag when rows are deleted.
	|	(default: true)
	|
	| 'dbSoftDeleteGroups'
	|
	|	Enables soft delete for Groups
	|	 If this is enabled, it simply set a flag when rows are deleted.
	|	(default: true)
	|
	| 'dbSoftDeletePerms'
	|
	|	Enables soft delete for Perms
	|	 If this is enabled, it simply set a flag when rows are deleted.
	|	(default: true)
	|
	*/
	public $dbProfile             = 'default';
	public $dbTableUsers          = 'aauth_users';
	public $dbTableUserSessions   = 'aauth_user_sessions';
	public $dbTableUserVariables  = 'aauth_user_variables';
	public $dbTableLoginAttempts  = 'aauth_login_attempts';
	public $dbTableLoginTokens    = 'aauth_login_tokens';
	public $dbTableGroups         = 'aauth_groups';
	public $dbTableGroupToUser    = 'aauth_group_to_user';
	public $dbTableGroupToGroup   = 'aauth_group_to_group';
	public $dbTableGroupVariables = 'aauth_group_variables';
	public $dbTablePerms          = 'aauth_perms';
	public $dbTablePermToUser     = 'aauth_perm_to_user';
	public $dbTablePermToGroup    = 'aauth_perm_to_group';
	public $dbSoftDeleteUsers     = true;
	public $dbSoftDeleteGroups    = true;
	public $dbSoftDeletePerms     = true;

}
