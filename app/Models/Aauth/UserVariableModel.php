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

use CodeIgniter\Model;
use App\Entities\Aauth\UserVariable;
use CodeIgniter\Validation\ValidationInterface;
use Config\Aauth as AauthConfig;
use CodeIgniter\Database\ConnectionInterface;

/**
 * User Variable Model.
 *
 * @package CodeIgniter-Aauth
 *
 * @since 3.0.0
 */
class UserVariableModel extends Model
{

	/**
	 * Aauth Config object
	 *
	 * @var AauthConfig
	 */
	protected $config;


	/**
	 * The format that the results should be returned as.
	 * Will be overridden if the as* methods are used.
	 *
	 * @var string
	 */
	protected $returnType = 'App\Entities\Aauth\UserVariable';

	/**
	 * @var string[]
	 */
	protected $allowedFields = ['user_id', 'data_key', 'data_value', 'system'];

	/**
	 * Validation Rules
	 * @var string[] $validationRules
	 */
	protected $validationRules = [
		'user_id' => 'required|is_natural_no_zero',
		'data_key' => 'required'
	];

	/**
	 * Validation Messages
	 * @var string[][] $validationMessages
	 */
	protected $validationMessages = [
		'user_id' => [
			'required' => 'User ID is required.',
			'is_natural_no_zero' => 'User ID must be a valid ID'
		],
		'data_key' => [
			'required' => 'Data Key is required'
		]
	];

	/**
	 * Use timestamps
	 * @var bool $useTimestamps
	 */
	protected $useTimestamps = true;

	/**
	 * Use soft delete
	 * @var bool $useSoftDeletes
	 */
	protected $useSoftDeletes = false;

	/**
	 * UserVariableModel constructor.
	 *
	 * @param ConnectionInterface|null $db
	 * @param ValidationInterface|null $validation
	 */
	public function __construct(ConnectionInterface &$db = null, ValidationInterface $validation = null)
	{
		parent::__construct($db, $validation);
		$this->config = new AauthConfig();
		$this->table = $this->config->dbTableUserVariables;

	}

	/**
	 * Find value from user variable
	 *
	 * Find User Variable by userId, dataKey & optional system
	 *
	 * @param int $userId User id
	 * @param string $dataKey Key of variable
	 * @param bool $system Whether system variable [default: false]
	 *
	 * @return string
	 * @since 4.0.0
	 */
	public function getValue(int $userId, string $dataKey, bool $system = false) : ?string
	{
		$this->select('data_value')
			->where('user_id', $userId)
			->where('data_key', $dataKey)
			->where('system', ($system ? 1 : 0));

		if ($row = $this->first())
		{
			return $row->data_value;
		}

		return null;
	}

	/**
	 * Find all user variables
	 *
	 * @param int $userId User id
	 * @param bool $system Whether system variable [default: false]
	 *
	 * @return UserVariable[]
	 * @since 4.0.0
	 */
	public function findAllByUser(int $userId, bool $system = false) : array
	{
		$this->where('user_id', $userId)
			->where('system', ($system ? 1 : 0));

		return $this->findAll();
	}

	/**
	 * Delete all User Variables by User ID
	 *
	 * @param int $userId User id
	 *
	 * @return bool
	 */
	public function deleteAllByUserId(int $userId) : bool
	{
		return $this->where('user_id', $userId)
			->delete();
	}

}
