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
	 * @return ?array
	 */
	public function findAllByUserId(int $userId, ?int $state = null) : ?array
	{
		$builder = $this->builder();
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

		return $builder->get()->getResult('array');
	}

	/**
	 * Get all User Ids by Perm Id
	 *
	 * @param int $permId Perm Id
	 *
	 * @return ?array
	 */
	public function findAllByPermId(int $permId) : ?array
	{
		$builder = $this->builder();
		$builder->select('user_id, state');
		$builder->where('perm_id', $permId);

		return $builder->get()->getResult('array');
	}

	/**
	 * Check if Perm Id is allowed by User Id
	 *
	 * @param int $permId Perm Id
	 * @param int $userId User Id
	 *
	 * @return bool
	 */
	public function allowed(int $permId, int $userId) : bool
	{
		$builder = $this->builder();

		$builder->where('perm_id', $permId);
		$builder->where('user_id', $userId);
		$builder->where('state', 1);

		return ($builder->countAllResults() ? true : false);
	}

	/**
	 * Check if Perm Id is allowed by User Id
	 *
	 * @param int $permId Perm Id
	 * @param int $userId User Id
	 *
	 * @return bool
	 */
	public function denied(int $permId, int $userId) : bool
	{
		$builder = $this->builder();

		$builder->where('perm_id', $permId);
		$builder->where('user_id', $userId);
		$builder->where('state', 0);

		return ($builder->countAllResults() ? true : false);
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
	 * @todo only return one type
	 */
	public function save(int $permId, int $userId, int $state = 1) : bool
	{
		$builder = $this->builder();
		$builder->where('perm_id', $permId);
		$builder->where('user_id', $userId);

		if (! $row = $builder->get()->getFirstRow())
		{
			$data['perm_id'] = $permId;
			$data['user_id'] = $userId;
			$data['state']   = $state;

			return $builder->insert($data)->resultID;
		}

		$data['state'] = $state;

		return $builder->update($data, ['perm_id' => $permId, 'user_id' => $userId]);
	}

	/**
	 * Deletes by Perm Id and User Id
	 *
	 * @param int $permId Perm Id
	 * @param int $userId User Id
	 *
	 * @return bool
	 */
	public function delete(int $permId, int $userId) : bool
	{
		$builder = $this->builder();
		$builder->where('perm_id', $permId);
		$builder->where('user_id', $userId);

		return $builder->delete()->resultID;
	}

	/**
	 * Deletes all by Perm Id
	 *
	 * @param int $permId Perm Id
	 *
	 * @return bool
	 */
	public function deleteAllByPermId(int $permId) : bool
	{
		$builder = $this->builder();
		$builder->where('perm_id', $permId);

		return $builder->delete()->resultID;
	}

	/**
	 * Deletes all by User Id
	 *
	 * @param int $userId User Id
	 *
	 * @return bool
	 */
	public function deleteAllByUserId(int $userId) : bool
	{
		$builder = $this->builder();
		$builder->where('user_id', $userId);

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
