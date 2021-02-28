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
 * Perm To User Model
 *
 * @package CodeIgniter-Aauth
 *
 * @since 3.0.0
 */
class PermToUserModel
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
	public function __construct(ConnectionInterface &$db = null)
	{
		$this->config  = new AauthConfig();
		$this->DBGroup = $this->config->dbProfile;
		$this->table   = $this->config->dbTablePermToUser;

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
	 * Get all Perm Ids by User Id and optional State
	 *
	 * @param int $userId User Id
	 * @param ?int $state Optional State (0 = denied, 1 = allowed)
	 *
	 * @return array
	 */
	public function findAllByUserId(int $userId, ?int $state = null): array
	{
		$builder = $this->db->table($this->table);
		$builder->where('user_id', $userId);

		if (isset($state))
		{
			$builder->select('perm_id, state');
		}
		else
		{
			$builder->select('perm_id');
			$builder->where('state', $state);
		}

		return $builder->get()->getResult();

	}

	/**
	 * Get all User Ids by Perm Id
	 *
	 * @param int $permId Perm Id
	 *
	 * @return array
	 */
	public function findAllByPermId(int $permId): array
	{
		$builder = $this->db->table($this->table);

		$builder->select('user_id, state')
			->where('perm_id', $permId);

		return $builder->get()->getResult();
	}

	/**
	 * Check if Perm Id is allowed by User Id
	 *
	 * @param int $permId Perm Id
	 * @param int $userId User Id
	 *
	 * @return bool
	 */
	public function allowed(int $permId, int $userId): bool
	{
		$builder = $this->db->table($this->table);

		$builder->where('perm_id', $permId)
			->where('user_id', $userId)
			->where('state', 1);

		return $builder->countAllResults() > 0;
	}

	/**
	 * Check if Perm Id is allowed by User Id
	 *
	 * @param int $permId Perm Id
	 * @param int $userId User Id
	 *
	 * @return bool
	 */
	public function denied(int $permId, int $userId): bool
	{
		$builder = $this->db->table($this->table);

		$builder->where('perm_id', $permId)
			->where('user_id', $userId)
			->where('state', 0);

		return $builder->countAllResults() > 0;
	}

	/**
	 * Save
	 *
	 * Inserts or Updates Perm to User
	 *
	 * @param int $permId Perm Id
	 * @param int $userId User Id
	 * @param int $state State Int (0 deny, 1 allow) [default: 1]
	 *
	 * @return bool
	 */
	public function save(int $permId, int $userId, int $state = 1): bool
	{
		$builder = $this->db->table($this->table);
		$builder->where('perm_id', $permId)
			->where('user_id', $userId);

		$row = $builder->get()->getFirstRow();

		if (! isset($row))
		{
			$data['perm_id'] = $permId;
			$data['user_id'] = $userId;
			$data['state']   = $state;

			$builder->insert($data)->resultID;
		}
		else
		{
			$data['state'] = $state;

			$builder->update($data, ['perm_id' => $permId, 'user_id' => $userId]);
		}

		return $this->db->affectedRows() > 0;
	}

	/**
	 * Deletes by Perm Id and User Id
	 *
	 * At least one parameter is required.  If only one parameter
	 * is given the method will delete all by that parameter.
	 *
	 * Example: delete(null, 5) will delete all permissions for User ID 5
	 *
	 * @param ?int $permId Permission Id [default: null]
	 * @param ?int $userId User Id [default: null]
	 *
	 * @return bool
	 */
	public function delete(?int $permId = null, ?int $userId = null): bool
	{
		// At least one param is required
		if(! isset($permId) && ! isset($userId))
		{
			return false;
		}

		$builder = $this->db->table($this->table);
		if(isset($permId))
		{
			$builder->where('perm_id', $permId);
		}
		if(isset($userId))
		{
			$builder->where('user_id', $userId);
		}

		$builder->delete();
		return $this->db->affectedRows() > 0;
	}

}
