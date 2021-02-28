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
use App\Libraries\Aauth;
use Config\Aauth as AauthConfig;
use App\Models\Aauth\UserModel;
use Config\Services;

/**
 * Aauth Accont/Home Controller
 *
 * @package CodeIgniter-Aauth
 */
class Home extends Controller
{
	/**
	 * Constructor
	 */
	public function __construct()
	{
		$this->aauth  = Services::aauth();
		$this->config = new AauthConfig();
		helper('aauth');

		if (! $this->aauth->isLoggedIn())
		{
			return service('response')->redirect('/');
		}
	}

	/**
	 * Index
	 *
	 * @return void
	 */
	public function index()
	{
		$data['user'] = $this->aauth->getUser();

		if ($this->config->socialEnabled)
		{
			$data['providers'] = [];

			foreach ($this->aauth->getProviders() as $provider)
			{
				$data['providers'][$provider] = $this->aauth->getSocialIdentifier($provider, $data['user']['id']);
			}
		}

		echo view('Account/Home', $data);
	}
}
