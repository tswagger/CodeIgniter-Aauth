<?php namespace App\Database;

use App\Entities\Aauth\Permission;
use Config\Aauth as AauthConfig;
use CodeIgniter\Test\CIDatabaseTestCase;
use App\Models\Aauth\PermModel;

// updated v4
class PermModelTest extends CIDatabaseTestCase
{
	protected $refresh = true;

	protected $basePath = APPPATH . 'Database/Migrations';

	protected $namespace = 'App';

	public function setUp(): void
	{
		parent::setUp();

		$this->model  = new PermModel($this->db);
		$this->config = new AauthConfig();
	}

	//--------------------------------------------------------------------

	public function testExistsById()
	{
		$this->hasInDatabase($this->config->dbTablePerms, [
			'id'         => 1,
			'name'       => 'testPerm1',
			'definition' => 'Test Perm 1',
		]);
		$this->assertTrue($this->model->existsById(1));
		$this->assertFalse($this->model->existsById(99));
	}

	public function testGetByName()
	{
		$this->hasInDatabase($this->config->dbTablePerms, [
			'id'         => 1,
			'name'       => 'testPerm1',
			'definition' => 'Test Perm 1',
		]);

		$permission = Permission::type($this->model->getByName('testPerm1'));
		$this->assertEquals(1, $permission->id);
		$this->assertNull($this->model->getByName('testPerm99'));
	}
}
