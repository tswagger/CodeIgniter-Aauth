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
use App\Entities\Aauth\Permission;
use CodeIgniter\Database\ConnectionInterface;
use CodeIgniter\Validation\ValidationInterface;
use Config\Aauth as AauthConfig;

/**
 * Perm Model
 *
 * @package CodeIgniter-Aauth
 *
 * @since 3.0.0
 */
class PermModel extends Model
{
	/**
	 * @var AauthConfig
	 */
	private AauthConfig $config;

	/**
	 * The format that the results should be returned as.
	 * Will be overridden if the as* methods are used.
	 *
	 * @var string
	 */
	protected $returnType = 'App\Entities\Aauth\Permission';

	/**
	 * An array of field names that are allowed
	 * to be set by the user in inserts/updates.
	 *
	 * @var array
	 */
	protected $allowedFields = ['name', 'definition'];

	/**
	 * If true, will set created_at, and updated_at
	 * values during insert and update routines.
	 *
	 * @var boolean
	 */
	protected $useTimestamps = true;

	/**
	 * Use soft delete
	 * @var bool $useSoftDeletes
	 */
	protected $useSoftDeletes = true;

	/**
	 * Constructor
	 *
	 * @param ?ConnectionInterface $db Connection Interface
	 * @param ?ValidationInterface $validation Validation Interface
	 */
	public function __construct(?ConnectionInterface &$db = null, ?ValidationInterface $validation = null)
	{

		$this->config  = new AauthConfig();

		parent::__construct($db, $validation);

		$this->table = $this->config->dbTablePerms;

		$this->validationRules['name'] = 'required|is_unique[' . $this->table . '.name,id,{id}]';

		$this->validationMessages = [
			'name' => [
				'required'  => lang('Aauth.requiredPermName'),
				'is_unique' => lang('Aauth.existsAlreadyPerm'),
			],
		];
	}

	/**
	 * Checks if permission exist by perm id
	 *
	 * @param int $permId Permission id
	 *
	 * @return bool
	 */
	public function existsById(int $permId) : bool
	{
		$count = $this->where($this->primaryKey, $permId)
			->countAllResults();

		return ($count > 0);
	}

	/**
	 * Get permission by permission name
	 *
	 * @param string $name Permission name
	 *
	 * @return ?Permission|object
	 */
	public function getByName(string $name): ?Permission
	{
		return $this->where('name', $name)
			->first();
	}
}
