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
use CodeIgniter\Database\BaseBuilder;
use CodeIgniter\Database\BaseConnection;
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
	 * Query Builder object
	 *
	 * @var BaseBuilder
	 */
	protected $builder;

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
	 * @var BaseConfig
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
	 * @return ?array
	 */
	public function findAllBySubgroupId(int $subgroupId) : ?array
	{
		$builder = $this->builder();
		$builder->select('group_id');
		$builder->where('subgroup_id', $subgroupId);

		return $builder->get()->getResult('array');
	}

	/**
	 * Get all Subgroup Ids by Group Id
	 *
	 * @param int $groupId Group Id
	 *
	 * @return ?array
	 */
	public function findAllByGroupId(int $groupId) : ?array
	{
		$builder = $this->builder();
		$builder->select('subgroup_id');
		$builder->where('group_id', $groupId);

		return $builder->get()->getResult('array');
	}

	/**
	 * Check if exists by Group Id and Subgroup Id
	 *
	 * @param int $groupId Group Id
	 * @param int $subgroupId Subgroup Id
	 *
	 * @return bool
	 */
	public function exists(int $groupId, int $subgroupId) : bool
	{
		$builder = $this->builder();

		$builder->where('group_id', $groupId);
		$builder->where('subgroup_id', $subgroupId);

		return ($builder->countAllResults() ? true : false);
	}

	/**
	 * Insert
	 *
	 * @param int $groupId Group Id
	 * @param int $subgroupId Subgroup Id
	 *
	 * @return bool
	 */
	public function insert(int $groupId, int $subgroupId) : bool
	{
		$builder = $this->builder();

		$data['group_id']    = $groupId;
		$data['subgroup_id'] = $subgroupId;

		return (bool) $builder->insert($data)->resultID;
	}

	/**
	 * Delete by Group Id and Subgroup Id
	 *
	 * @param int $groupId Group Id
	 * @param int $subgroupId Subgroup Id
	 *
	 * @return bool
	 */
	public function delete(int $groupId, int $subgroupId) : bool
	{
		$builder = $this->builder();
		$builder->where('group_id', $groupId);
		$builder->where('subgroup_id', $subgroupId);

		return $builder->delete()->resultID;
	}

	/**
	 * Deletes all by Group Id
	 *
	 * @param int $groupId Group Id
	 *
	 * @return bool
	 */
	public function deleteAllByGroupId(int $groupId) : bool
	{
		$builder = $this->builder();
		$builder->where('group_id', $groupId);

		return $builder->delete()->resultID;
	}

	/**
	 * Deletes all by Subgroup Id
	 *
	 * @param int $subgroupId Subgroup Id
	 *
	 * @return bool
	 */
	public function deleteAllBySubgroupId(int $subgroupId) : bool
	{
		$builder = $this->builder();
		$builder->where('subgroup_id', $subgroupId);

		return $builder->delete()->resultID;
	}

	/**
	 * Provides a shared instance of the Query Builder.
	 *
	 * @param ?string $table Table Name
	 *
	 * @return BaseBuilder
	 */
	protected function builder(?string $table = null) : BaseBuilder
	{
		if ($this->builder instanceof BaseBuilder)
		{
			return $this->builder;
		}

		$table = empty($table) ? $this->table : $table;

		$this->builder = $this->db->table($table);

		return $this->builder;
	}

}
