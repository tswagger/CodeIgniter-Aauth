<?php

namespace App\Entities\Aauth;

use CodeIgniter\Entity;

/**
 * Entity Class Permission
 *
 * @package CodeIgniter-Aauth
 * @author Tim Swagger <tim@renowne.com>
 * @copyright 2014-2019 Emre Akay
 * @license   https://opensource.org/licenses/MIT   MIT License
 * @link      https://github.com/emreakay/CodeIgniter-Aauth
 * @since     4.0.0
 */
class Permission extends Entity {

	/**
	 * Takes a Permission Entity object and returns it cast as a Permission Entity object
	 *
	 * This is useful for IDE code completion.
	 *
	 * Example: $permissionOne = Permission::type($permModel->first($id));
	 *
	 * @param ?Permission|object $permission
	 * @return ?Permission
	 */
	static function type($permission): ?\App\Entities\Aauth\Permission {
		return $permission;
	}

}
