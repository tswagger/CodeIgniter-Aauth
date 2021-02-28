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
 */

namespace App\Controllers\Account;

use CodeIgniter\Controller;
use Config\Aauth as AauthConfig;
use App\Libraries\Aauth;
use Config\Services;

/**
 * Aauth Accont/Register Controller
 *
 * @package CodeIgniter-Aauth
 */
class Register extends Controller
{
	protected $config;
	protected $aauth;

	/**
	 * Constructor
	 */
	public function __construct()
	{
		$this->config  = new AauthConfig();
		$this->aauth   = Services::aauth();
		$this->request = Services::request();
		helper('form');
	}

	/**
	 * Index
	 *
	 * @return void
	 */
	public function index()
	{
		if ($input = $this->request->getPost())
		{
			if ( is_null($this->aauth->createUser($input['email'], $input['password'], $input['username'])))
			{
				log_message('info', 'Account creation failed');
				$data['errors'] = $this->aauth->printErrors('<br />', true);
			}
			else
			{
				log_message('info', 'Account created');
				$data['infos'] = $this->aauth->printInfos('<br />', true);
			}
		}


		if (session('errors'))
		{
			$data['errors'] = isset($data['errors']) ? $data['errors'] . '<br />' . session('errors') : session('errors');
		}

		if (session('infos'))
		{
			$data['infos'] = isset($data['infos']) ? $data['infos'] . '<br />' . session('infos') : session('infos');
		}

		$data['useUsername'] = $this->config->loginUseUsername;
		$data['cssFiles']    = [
			'/assets/css/login.css'
		];

		if ($this->config->socialEnabled)
		{
			$data['providers'] = $this->aauth->getProviders();
		}

		echo view('Account/Register', $data);
	}
}
