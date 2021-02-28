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

use CodeIgniter\HTTP\Response;
use Config\Aauth as AauthConfig;
use CodeIgniter\Model;
use Config\Database;
use Config\Services;
use CodeIgniter\Database\BaseBuilder;
use CodeIgniter\Database\BaseConnection;
use CodeIgniter\Database\ConnectionInterface;




/**
 * Login Attempt caseModel
 *
 * @package CodeIgniter-Aauth
 *
 * @since 3.0.0
 */
class LoginAttemptModel extends Model
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
	 * The format that the results should be returned as.
	 * Will be overridden if the as* methods are used.
	 *
	 * @var string
	 */
	protected $returnType = 'App\Entities\Aauth\LoginAttempt';

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
	 * @param ?ConnectionInterface $db Database connection
	 * @param ?\Config\Aauth $config Config Object
	 * @param ?Response $response Response Class
	 */
	public function __construct(?ConnectionInterface &$db = null, ?\Config\Aauth $config = null, ?Response $response = null)
	{
		parent::__construct();

		if (!isset($config))
		{
			$config = new AauthConfig();
		}

		if (!isset($response))
		{
			$response = service('response');
		}

		$this->response = $response;
		$this->config   = $config;
		$this->DBGroup  = $this->config->dbProfile;
		$this->table    = $this->config->dbTableLoginAttempts;

		$this->request = Services::request();
	}

	/**
	 * Get Login Attempt
	 *
	 * Get login attempt based on time and ip address
	 *
	 * @return int
	 * @todo: this should return a LoginAttempt Object
	 */
	public function findLogin(): int
	{
		if ($this->config->loginAttemptCookie)
		{
			helper('cookie');
			$cookieName = $this->config->loginAttemptCookie === true ? 'logins' : $this->config->loginAttemptCookie;

			if ($cookie = $this->response->getCookie($cookieName))
			{
				return empty($cookie['value']) ? 0 : $cookie['value'];
			}
		}
		else
		{
			$agent = $this->request->getUserAgent();
			$builder = $this->builder();
			$builder->where('user_agent', md5($agent->getBrowser() . ' - ' . $agent->getVersion() . ' - ' . $agent->getPlatform()));
			$builder->where('ip_address', $this->request->getIPAddress());
			$builder->where('updated_at >=', date('Y-m-d H:i:s', strtotime('-' . $this->config->loginAttemptLimitTimePeriod)));

			if ($builder->countAllResults() !== 0)
			{
				return $builder->get()->getFirstRow()->count;
			}
		}

		return 0;
	}

	/**
	 * Save Login Attempt
	 *
	 * Inserts or Updates Login Attempt
	 *
	 * @return bool
	 * @since 4.0.0
	 */
	public function saveAttempt() : bool
	{
		if ($this->config->loginAttemptCookie)
		{
			helper('cookie');
			$cookieName = $this->config->loginAttemptCookie === true ? 'logins' : $this->config->loginAttemptCookie;
			$expire = strtotime($this->config->loginAttemptLimitTimePeriod) - strtotime('now');

			if ($cookie = $this->response->getCookie($cookieName))
			{
				$this->response->deleteCookie($cookieName);
				$this->response->setCookie($cookieName, ++$cookie['value'], $expire);

				if ($cookie['value'] >= $this->config->loginAttemptLimit)
				{
					return false;
				}
				else
				{
					return true;
				}
			}
			else
			{
				$this->response->setCookie($cookieName, 1, $expire);

				return true;
			}
		}
		else
		{
			$ipAddress = $this->request->getIPAddress();
			$agent     = $this->request->getUserAgent();
			$userAgent = md5($agent->getBrowser() . ' - ' . $agent->getVersion() . ' - ' . $agent->getPlatform());
			$builder   = $this->builder();

			$builder->where('user_agent', $userAgent);
			$builder->where('ip_address', $ipAddress);
			$builder->where('updated_at >=', date('Y-m-d H:i:s', strtotime('-' . $this->config->loginAttemptLimitTimePeriod)));

			if (! $row = $builder->get()->getFirstRow())
			{
				$data['ip_address'] = $ipAddress;
				$data['user_agent'] = $userAgent;
				$data['count']      = 1;
				$data['created_at'] = date('Y-m-d H:i:s');
				$data['updated_at'] = date('Y-m-d H:i:s');

				$builder->insert($data);

				return true;
			}
			else
			{
				$data['count']      = $row->count + 1;
				$data['updated_at'] = date('Y-m-d H:i:s');

				$builder->update($data, ['id' => $row->id]);

				if ($data['count'] >= $this->config->loginAttemptLimit)
				{
					return false;
				}
				else
				{
					return true;
				}
			}
		}
	}

	/**
	 * Delete login attempt.
	 *
	 * Delete login attempt based on time and ip address
	 *
	 * @return bool
	 */
	public function deleteAttempt() : bool
	{
		if ($this->config->loginAttemptCookie)
		{
			helper('cookie');
			$cookieName = $this->config->loginAttemptCookie === true ? 'logins' : $this->config->loginAttemptCookie;
			$this->response->deleteCookie($cookieName);
		}
		else
		{
			$agent   = $this->request->getUserAgent();
			$builder = $this->builder();
			$builder->where('user_agent', md5($agent->getBrowser() . ' - ' . $agent->getVersion() . ' - ' . $agent->getPlatform()));
			$builder->where('ip_address', $this->request->getIPAddress());
			$builder->where('updated_at >=', date('Y-m-d H:i:s', strtotime('-' . $this->config->loginAttemptLimitTimePeriod)));
			$builder->delete();
		}

		return true;
	}

}
