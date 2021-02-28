<?php

namespace App\Entities\Aauth;

use CodeIgniter\Entity;
use CodeIgniter\Database\BaseConnection;

/**
 * Entity Class Group
 *
 * @package CodeIgniter-Aauth
 * @author Tim Swagger <tim@renowne.com>
 * @copyright 2014-2019 Emre Akay
 * @license   https://opensource.org/licenses/MIT   MIT License
 * @link      https://github.com/emreakay/CodeIgniter-Aauth
 * @since     4.0.0
 */
class Group extends Entity {


	/**
	 * Database Handle
	 * @var BaseConnection $db
	 */
	protected BaseConnection $db;

	/**
	 * Group constructor.
	 * @param array|null $data
	 */
	public function __construct(array $data = null) {
		parent::__construct($data);

		$this->db = \Config\Database::connect();

	}

	/**
	 * Takes a Group Entity object and returns it cast as a Group Entity object
	 *
	 * This is useful for IDE code completion.
	 *
	 * Example: $groupOne = Group::type($groupModel->first($id));
	 *
	 * @param ?Group|object $group
	 * @return ?Group
	 */
	static function type($group): ?\App\Entities\Aauth\Group {
		return $group;
	}

	/**
	 * Add User to Group
	 *
	 * @param int $userId User ID
	 *
	 * @return bool Success Indicator
	 */
	public function addUser(int $userId): bool {
		$groupToUserModel = new \App\Models\Aauth\GroupToUserModel($this->db);

		return $groupToUserModel->create($this->id, $userId);
	}

	/**
	 * Remove User from Group
	 *
	 * @param int $userId User ID
	 * @return bool Success Indicator
	 */
	public function removeUser(int $userId): bool {
		$groupToUserModel = new \App\Models\Aauth\GroupToUserModel($this->db);

		return $groupToUserModel->delete($this->id, $userId);
	}

	/**
	 * List Users who are members of this group
	 *
	 * @return User[] Array of Users
	 */
	public function getUsers(): array {
		$groupToUserModel = new \App\Models\Aauth\GroupToUserModel($this->db);
		$userModel = new \App\Models\Aauth\UserModel();

		$userGroupList = $groupToUserModel->get(null, $this->id, null, null);
		$userList = array();
		foreach ($userGroupList as $listItem) {
			$userList[] = $listItem->user_id;
		}

		return $userModel->whereIn('id', $userList)->findAll();
	}
}
