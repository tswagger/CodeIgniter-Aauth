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
 * Group To Group Model
 *
 * @package CodeIgniter-Aauth
 *
 * @since 3.0.0
 */
class GroupToGroupModel
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
	protected $DBGroup;

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
		$this->DBGroup = $this->config->dbProfile;
		$this->table   = $this->config->dbTableGroupToGroup;

		if ($db instanceof ConnectionInterface)
		{
			$this->db = & $db;
		}
		else
		{
			$this->db = Database::connect($this->DBGroup);
		}
	}

	/**
	 * Get all Group Ids by Subgroup Id
	 *
	 * @param int $subgroupId Subgroup Id
	 *
	 * @return array
	 */
	public function findAllBySubgroupId(int $subgroupId): array
	{
		$builder = $this->db->table($this->table);
		$builder->select('group_id')
			->where('subgroup_id', $subgroupId);

		return $builder->get()->getResult();
	}

	/**
	 * Get all Subgroup Ids by Group Id
	 *
	 * @param int $groupId Group Id
	 *
	 * @return array
	 */
	public function findAllByGroupId(int $groupId): array
	{
		$builder = $this->db->table($this->table);
		$builder->select('subgroup_id')
			->where('group_id', $groupId);

		return $builder->get()->getResult();
	}

	/**
	 * Check if exists by Group Id and Subgroup Id
	 *
	 * @param int $groupId Group Id
	 * @param int $subgroupId Subgroup Id
	 *
	 * @return bool
	 */
	public function exists(int $groupId, int $subgroupId): bool
	{
		$builder = $this->db->table($this->table);

		$count = $builder->where('group_id', $groupId)
			->where('subgroup_id', $subgroupId)
			->countAllResults();

		return $count > 0;
	}

	/**
	 * Insert
	 *
	 * @param int $groupId Group Id
	 * @param int $subgroupId Subgroup Id
	 *
	 * @return bool
	 */
	public function insert(int $groupId, int $subgroupId): bool
	{
		$builder = $this->db->table($this->table);

		$data = [
			'group_id' => $groupId,
			'subgroup_id' => $subgroupId
		];

		$builder->insert($data);

		return $this->db->affectedRows() > 0;
	}

	/**
	 * Delete by Group Id and Subgroup Id
	 *
	 * @param int $groupId Group Id
	 * @param int $subgroupId Subgroup Id
	 *
	 * @return bool
	 */
	public function delete(int $groupId, int $subgroupId): bool
	{
		$builder = $this->db->table($this->table);
		$builder->where('group_id', $groupId)
			->where('subgroup_id', $subgroupId);

		$builder->delete();

		return $this->db->affectedRows() > 0;
	}

	/**
	 * Deletes all by Group Id
	 *
	 * @param int $groupId Group Id
	 *
	 * @return bool
	 */
	public function deleteAllByGroupId(int $groupId): bool
	{
		$builder = $this->db->table($this->table);
		$builder->where('group_id', $groupId);

		$builder->delete();

		return $this->db->affectedRows() > 0;
	}

	/**
	 * Deletes all by Subgroup Id
	 *
	 * @param int $subgroupId Subgroup Id
	 *
	 * @return bool
	 */
	public function deleteAllBySubgroupId(int $subgroupId): bool
	{
		$builder = $this->db->table($this->table);
		$builder->where('subgroup_id', $subgroupId);

		$builder->delete();

		return $this->db->affectedRows();
	}

}
