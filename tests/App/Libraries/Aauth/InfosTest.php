<?php namespace App\Libraries;

use Config\Logger;
use Config\Services;
use CodeIgniter\Test\TestLogger;
use CodeIgniter\Test\Mock\MockSession;
use CodeIgniter\Session\Handlers\FileHandler;
use App\Libraries\Aauth;

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState         disabled
 */
class InfosTest extends \CodeIgniter\Test\CIUnitTestCase
{
	public function setUp(): void
	{
		parent::setUp();

		$this->library = new Aauth(null, null);
		$_COOKIE       = [];
		$_SESSION      = [];
	}

	protected function getInstance($options = [])
	{
		$defaults = [
			'sessionDriver'            => 'CodeIgniter\Session\Handlers\FileHandler',
			'sessionCookieName'        => 'ci_session',
			'sessionExpiration'        => 7200,
			'sessionSavePath'          => 'null',
			'sessionMatchIP'           => false,
			'sessionTimeToUpdate'      => 300,
			'sessionRegenerateDestroy' => false,
			'cookieDomain'             => '',
			'cookiePrefix'             => '',
			'cookiePath'               => '/',
			'cookieSecure'             => false,
		];

		$config = (object)$defaults;

		$session = new MockSession(new FileHandler($config, Services::request()->getIPAddress()), $config);
		$session->setLogger(new TestLogger(new Logger()));
		$session->start();

		return $session;
	}

	//--------------------------------------------------------------------

	public function testInfos()
	{
		$this->assertCount(0, $this->library->getInfosArray());
		$this->library->info('test message 1');
		$this->assertEquals(['test message 1'], $this->library->getInfosArray());
	}

	public function testInfosArray()
	{
		$this->assertCount(0, $this->library->getInfosArray());
		$this->library->info(['test message 1', 'test message 2']);
		$this->assertEquals(['test message 1', 'test message 2'], $this->library->getInfosArray());
	}

	public function testPrintInfos()
	{
		$this->library->info('test message 1');
		$this->assertEquals('test message 1', $this->library->printInfos('<br />', true));
		$this->library->info('test message 2');
		$this->assertEquals('test message 1<br />test message 2', $this->library->printInfos('<br />', true));

		$this->library->printInfos('<br />');
		$this->expectOutputString('test message 1<br />test message 2');
	}

	public function testClearInfos()
	{
		$session       = $this->getInstance();
		$this->library = new Aauth(null, $session);
		$this->library->info('test message 1', true);
		$this->assertEquals(['test message 1'], $session->getFlashdata('infos'));
		$this->library->clearInfos();
		$this->assertEquals([], $this->library->getInfosArray());
		$this->assertNull($session->getFlashdata('infos'));
	}

	public function testInfosFlash()
	{
		$session       = $this->getInstance();
		$this->library = new Aauth(null, $session);
		$this->assertNull($session->getFlashdata('infos'));
		$this->library->info('test message 1', true);
		$session->start();
		$this->assertEquals(['test message 1'], $session->getFlashdata('infos'));

		$this->library = new Aauth(null, $session);
		$this->library->info(['test message 1', 'test message 2'], true);
		$session->start();
		$this->assertEquals(['test message 1', 'test message 2'], $session->getFlashdata('infos'));
	}

	public function testKeepInfos()
	{
		$session       = $this->getInstance();
		$this->library = new Aauth(null, $session);
		$this->assertNull($session->getFlashdata('infos'));
		$this->library->info('test message 1 Flash', true);
		$session->start();
		$this->library->keepInfos();
		$session->start();
		$this->assertEquals(['test message 1 Flash'], $session->getFlashdata('infos'));
		$this->library = new Aauth(null, $session);
		$this->library->info('test message 1 NonFlash');
		$this->library->keepInfos(true);
		$session->start();
		$this->assertEquals(['test message 1 Flash', 'test message 1 NonFlash'], $session->getFlashdata('infos'));
	}
}
