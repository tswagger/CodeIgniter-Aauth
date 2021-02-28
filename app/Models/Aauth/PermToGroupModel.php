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
 * Perm To Group Model
 *
 * @package CodeIgniter-Aauth
 *
 * @since 3.0.0
 * @todo come back to
 */
class PermToGroupModel
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
		$this->table   = $this->config->dbTablePermToGroup;

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
	 * Get all Perm Ids by Group Id
	 *
	 * @param int $groupId Group Id
	 * @param ?int $state State (0 = denied, 1 = allowed)
	 *
	 * @return array
	 */
	public function findAllByGroupId(int $groupId, ?int $state = null): array
	{
		$builder = $this->db->table($this->table);

		$builder->where('group_id', $groupId);

		if (isset($state))
		{
			$builder->select('perm_id, state');
		}
		else
		{
			$builder->select('perm_id')
				->where('state', $state);
		}

		return $builder->get()->getResult();
	}

	/**
	 * Get all Group Ids by Perm Id
	 *
	 * @param int $permId Perm Id
	 *
	 * @return array
	 */
	public function findAllByPermId(int $permId): array
	{
		$builder = $this->db->table($this->table);

		$builder->select('group_id, state')
			->where('perm_id', $permId);

		return $builder->get()->getResult();
	}

	/**
	 * Check if Perm Id is allowed by Group Id
	 *
	 * @param int $permId Perm Id
	 * @param int $groupId Group Id
	 *
	 * @return bool
	 */
	public function allowed(int $permId, int $groupId): bool
	{
		$builder = $this->db->table($this->table);

		$builder->where('perm_id', $permId)
			->where('group_id', $groupId)
			->where('state', 1);

		return $builder->countAllResults() > 0;
	}

	/**
	 * Check if Perm Id is allowed by Group Id
	 *
	 * @param int $permId Perm Id
	 * @param int $groupId Group Id
	 *
	 * @return bool
	 */
	public function denied(int $permId, int $groupId) : bool
	{
		$builder = $this->db->table($this->table);

		$builder->where('perm_id', $permId)
			->where('group_id', $groupId)
			->where('state', 0);

		return $builder->countAllResults() > 0;
	}

	/**
	 * Save
	 *
	 * Inserts or Updates Perm to Group
	 *
	 * @param int $permId Perm Id
	 * @param int $groupId Group Id
	 * @param int $state State Int (0 deny, 1 allow) [default: 1]
	 *
	 * @return bool
	 */
	public function save(int $permId, int $groupId, int $state = 1): bool
	{
		$builder = $this->db->table($this->table);

		$builder->where('perm_id', $permId)
			->where('group_id', $groupId);

		$row = $builder->get()->getFirstRow();

		if (! isset($row))
		{
			$data['perm_id']  = $permId;
			$data['group_id'] = $groupId;
			$data['state']    = $state;

			$builder->insert($data);
		}
		else {
			$data['state'] = $state;

			$builder->update($data, ['perm_id' => $permId, 'group_id' => $groupId]);
		}

		return $this->db->affectedRows() > 0;
	}

	/**
	 * Deletes by Perm Id and Group Id
	 *
	 * At least one parameter is required. Method delete all
	 * Permission to Group entries that match the parameters
	 * passed in
	 *
	 * @param ?int $permId Perm Id [default: null]
	 * @param ?int $groupId Group Id [default: null]
	 *
	 * @return bool True if any entries are deleted. False if no entries or if method failed.
	 */
	public function delete(?int $permId = null, ?int $groupId = null): bool
	{
		// at least one parameter is required
		if(! isset($permId) && ! isset($groupId))
		{
			return false;
		}

		$builder = $this->db->table($this->table);

		if(isset($permId))
		{
			$builder->where('perm_id', $permId);
		}
		if(isset($groupId))
		{
			$builder->where('group_id', $groupId);
		}

		$builder->delete();

		return $this->db->affectedRows() > 0;
	}
}
