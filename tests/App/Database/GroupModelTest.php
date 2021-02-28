<?php namespace App\Database;

use CodeIgniter\Test\CIDatabaseTestCase;
use App\Models\Aauth\GroupModel;
use App\Entities\Aauth\Group;

// Updated v4
class GroupModelTest extends CIDatabaseTestCase
{
	protected $refresh = true;

	protected $basePath = APPPATH . 'Database/Migrations';

	protected $namespace = 'App';

	public function setUp(): void
	{
		parent::setUp();

		$this->model = new GroupModel($this->db);
	}

	//--------------------------------------------------------------------

	public function testExistsById()
	{
		$this->assertTrue($this->model->existsById(1));
		$this->assertFalse($this->model->existsById(99));
	}

	public function testGetByName()
	{
		$group = Group::type($this->model->getByName('admin'));
		$this->assertEquals(1, $group->id);
		$this->assertNull($this->model->getByName('test_group'));
	}
}
