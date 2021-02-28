<?php namespace App\Entities\Aauth;

use CodeIgniter\Database\BaseConnection;
use CodeIgniter\Entity;

/**
 * Entity Class User
 *
 * @package CodeIgniter-Aauth
 * @author Tim Swagger <tim@renowne.com>
 * @copyright 2014-2019 Emre Akay
 * @license   https://opensource.org/licenses/MIT   MIT License
 * @link      https://github.com/emreakay/CodeIgniter-Aauth
 * @since     4.0.0
 */
class User extends Entity {

	/**
	 * Database Handle
	 * @var BaseConnection $db
	 */
	protected BaseConnection $db;

	/**
	 * User constructor.
	 * @param array|null $data
	 */
	public function __construct(array $data = null) {
		parent::__construct($data);

		$this->db = \Config\Database::connect();

	}

	/**
	 * Takes a User Entity object and returns it cast as a User Entity object
	 *
	 * This is useful for IDE code completion.
	 *
	 * Example: $userOne = User::type($userModel->first($id));
	 *
	 * @param ?User|object $group
	 * @return ?User
	 */
	static function type($group): ?User {
		return $group;
	}

	/**
	 * Add User to Group
	 *
	 * @param int $groupId Group ID
	 *
	 * @return bool Success Indicator
	 */
	public function addToGroup(int $groupId): bool {
		$groupToUserModel = new \App\Models\Aauth\GroupToUserModel($this->db);

		return $groupToUserModel->create($groupId, $this->id);
	}

	/**
	 * Remove User from Group
	 *
	 * @param int $groupId Group ID
	 * @return bool Success Indicator
	 */
	public function removeFromGroup(int $groupId): bool {
		$groupToUserModel = new \App\Models\Aauth\GroupToUserModel($this->db);

		return $groupToUserModel->delete($groupId, $this->id);
	}

	/**
	 * List Groups user is a member of
	 *
	 * @return Group[] Array of Groups
	 */
	public function getGroups(): array {
		$groupToUserModel = new \App\Models\Aauth\GroupToUserModel($this->db);
		$groupModel = new \App\Models\Aauth\GroupModel();

		$userGroupList = $groupToUserModel->get($this->id, null, null, null);
		$groupList = array();
		foreach($userGroupList as $listItem) {
			$groupList[] = $listItem->group_id;
		}

		return $groupModel->whereIn('id',$groupList)->findAll();
	}
}
