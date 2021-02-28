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
use CodeIgniter\Model;
use CodeIgniter\Database\BaseBuilder;
use CodeIgniter\Database\BaseConnection;
use CodeIgniter\Database\ConnectionInterface;

/**
 * Login Token Model
 *
 * @package CodeIgniter-Aauth
 *
 * @since 3.0.0
 */
class LoginTokenModel extends Model
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
	 * The format that the results should be returned as.
	 * Will be overridden if the as* methods are used.
	 *
	 * @var string
	 */
	protected $returnType = 'App\Entities\Aauth\LoginToken';

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
	 * @var AAuthConfig
	 */
	protected $config;

	/**
	 * Constructor
	 *
	 * @param ?ConnectionInterface $db Database object
	 */
	public function __construct(?ConnectionInterface &$db = null)
	{
		parent::__construct();

		$this->config  = new AauthConfig();
		$this->DBGroup = $this->config->dbProfile;
		$this->table   = $this->config->dbTableLoginTokens;
	}

	/**
	 * Find all Login Tokens by User ID
	 *
	 * @param int $userId User id
	 *
	 * @return array
	 */
	public function findAllByUserId(int $userId) : array
	{
		return $this->select('id, user_id, random_hash, selector_hash, expires_at')
			->where('user_id', $userId)
			->findAll();
	}

	/**
	 * Insert Login Token
	 *
	 * @param array|null|object $data Array with data
	 * @param bool $returnID
	 *
	 * @return bool
	 * @throws \ReflectionException
	 * @todo: come back to
	 */
	public function insertToken(array $data = null, bool $returnID = true) : bool
	{
		if(is_object($data)) {
			$data->created_at = date('Y-m-d H:i:s');
			$data->expires_at = date('Y-m-d H:i:s', strtotime($this->config->loginRemember));
			$data->updated_at = date('Y-m-d H:i:s');
		}
		else {
			$data['created_at'] = date('Y-m-d H:i:s');
			$data['expires_at'] = date('Y-m-d H:i:s', strtotime($this->config->loginRemember));
			$data['updated_at'] = date('Y-m-d H:i:s');
		}

		return parent::insert($data, $returnID);
	}

	/**
	 * Update Login Token by tokenId
	 *
	 * @param int $tokenId Login Token id
	 * @param ?string $expiresAt Custom expires at date
	 *
	 * @return bool
	 * @since 4.0.0
	 */
	public function updateToken(int $tokenId, ?string $expiresAt = null): bool
	{

		$data['expires_at'] = date('Y-m-d H:i:s', strtotime($expiresAt ?: $this->config->loginRemember));
		$data['updated_at'] = date('Y-m-d H:i:s');

		try {
			return $this->update($tokenId, $data);
		}
		catch(\ReflectionException $e) {
			log_message('error', $e->getMessage());
			return false;
		}
	}

	/**
	 * Deletes expired Login Tokens by userId.
	 *
	 * @param int $userId User id
	 *
	 * @return bool
	 */
	public function deleteExpired(int $userId): bool
	{
		return $this->where('user_id', $userId)
			->where('expires_at <', date('Y-m-d H:i:s'))
			->delete();
	}

	/**
	 * Deletes all Login Tokens by userId.
	 *
	 * @param int $userId User id
	 *
	 * @return bool
	 */
	public function deleteAll(int $userId) : bool
	{
		return $this->where('user_id', $userId)
			->delete();
	}

}
