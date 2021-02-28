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
 * @author    Emre Akay
 * @author    Raphael "REJack" Jackstadt
 * @copyright 2014-2019 Emre Akay
 * @license   https://opensource.org/licenses/MIT   MIT License
 * @link      https://github.com/emreakay/CodeIgniter-Aauth
 * @since     3.0.0
 */

namespace App\Models\Aauth;

use Config\Aauth as AauthConfig;
use Config\Database;
use CodeIgniter\Database\ConnectionInterface;

/**
 * Group To User Model
 *
 * @package CodeIgniter-Aauth
 *
 * @since 3.0.0
 */
class GroupToUserModel
{

	/**
	 * Database Connection
	 *
	 * @var ConnectionInterface
	 */
	protected $db;

	/**
	 * Name of database table
	 *
	 * @var string
	 */
	protected $table;

	/**
	 * The Database connection group that
	 * should be instantiated.
	 *
	 * @var string
	 */
	protected $dbGroup;

	/**
	 * Aauth Config object
	 *
	 * @var AauthConfig
	 */
	protected $config;

	/**
	 * Constructor
	 *
	 * @param ?ConnectionInterface $db Database object
	 */
	public function __construct(?ConnectionInterface &$db = null)
	{

		$this->config  = new AauthConfig();
		$this->dbGroup = $this->config->dbProfile;
		$this->table   = $this->config->dbTableGroupToUser;

		if ($db instanceof ConnectionInterface)
		{
			$this->db = & $db;
		}
		else
		{
			$this->db = Database::connect($this->dbGroup);
		}
	}

	/**
	 * Get all Group Ids by User Id
	 *
	 * @param int $userId User Id
	 *
	 * @return array
	 */
	public function findAllByUserId(int $userId): array
	{
		$builder = $this->db->table($this->table);
		$builder->select('group_id');
		$builder->where('user_id', $userId);

		return $builder->get()->getResult();
	}

	/**
	 * Get all User Ids by Group Id
	 *
	 * @param int $groupId Group Id
	 *
	 * @return array
	 */
	public function findAllByGroupId(int $groupId): array
	{
		$builder = $this->db->table($this->table);
		$builder->select('user_id');
		$builder->where('group_id', $groupId);

		return $builder->get()->getResult();
	}

	/**
	 * Check if exists by Group Id and User Id
	 *
	 * @param int $groupId Group Id
	 * @param int $userId User Id
	 *
	 * @return bool
	 */
	public function exists(int $groupId, int $userId): bool
	{
		$builder = $this->db->table($this->table);

		$builder->where('group_id', $groupId);
		$builder->where('user_id', $userId);

		return $builder->countAllResults() > 0;
	}

	/**
	 * Create connection
	 *
	 * @param int $group_id Group ID
	 * @param int $user_id User ID
	 * @return bool Success Indicator
	 */
	public function create(int $group_id, int $user_id): bool {

		$builder = $this->db->table($this->table);

		$data = array(
			'group_id' => $group_id,
			'user_id' => $user_id
		);
		$builder->insert($data);

		return $this->db->affectedRows();
	}

	/**
	 * Deletes by Group Id and User Id
	 *
	 * At least one parameter is required.  If only one parameter
	 * is given the method will delete all by that parameter.
	 *
	 * Example: delete(null, 5) will delete all groups for User ID 5
	 *
	 * @param ?int $groupId Group Id [default: null]
	 * @param ?int $userId User Id [default: null]
	 *
	 * @return bool True if any entries are deleted. False if no entries or if method failed.
	 */
	public function delete(int $groupId, int $userId): bool {

		// at least one parameter is required
		if(! isset($groupId) && ! isset($userId))
		{
			return false;
		}

		$builder = $this->db->table($this->table);

		if(isset($groupId))
		{
			$builder->where('project_id', $groupId);
		}
		if(isset($userId))
		{
			$builder->where('user_id', $userId);
		}

		$builder->delete();

		return $this->db->affectedRows() > 0;
	}


	/**
	 * Search and Retrieve group-to-user connection data
	 *
	 * @param ?int $group_id Group ID [default: null]
	 * @param ?int $user_id User ID [default: null]
	 * @param ?int $limit Pagination Limit [default: null]
	 * @param ?int $offset Pagination Offset [default: null]
	 * @return array Connection Data
	 */
	public function get(?int $group_id = null, ?int $user_id = null, ?int $limit = null, ?int $offset = null): array {

		if(!isset($group_id) && !isset($user_id)) {
			return array();
		}

		$builder = $this->db->table($this->table);

		if(isset($user_id)) {
			$builder->where('user_id', $user_id);
		}
		if(isset($group_id)) {
			$builder->where('group_id', $group_id);
		}

		$query = $builder->limit($limit, $offset)
			->get();

		return $query->getResult();
	}

}
