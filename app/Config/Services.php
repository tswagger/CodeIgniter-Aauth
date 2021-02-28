<?php namespace Config;

use CodeIgniter\Config\Services as CoreServices;

/**
 * Services Configuration file.
 *
 * Services are simply other classes/libraries that the system uses
 * to do its job. This is used by CodeIgniter to allow the core of the
 * framework to be swapped out easily without affecting the usage within
 * the rest of your application.
 *
 * This file holds any application-specific services, or service overrides
 * that you might need. An example has been included with the general
 * method format you should use for your service methods. For more examples,
 * see the core Services file at system/Config/Services.php.
 */
class Services extends CoreServices
{

	//    public static function example($getShared = true)
	//    {
	//        if ($getShared)
	//        {
	//            return static::getSharedInstance('example');
	//        }
	//
	//        return new \CodeIgniter\Example();
	//    }

	/**
	 * Aauth Singleton Instantiation method
	 *
	 * Using a Service Singleton dramatically reduces the DB requests
	 *
	 * @param bool $getShared Return shared (singleton) method [default: true]
	 * @return \App\Libraries\Aauth
	 */
	public static function aauth($getShared = true): \App\Libraries\Aauth
	{
		if ($getShared)
		{
			return static::getSharedInstance('aauth');
		}

		return new \App\Libraries\Aauth();
	}
}
