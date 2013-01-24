<?php
namespace Fwk\Security\Password\Adapters;

use Fwk\Security\Password\SaltedPasswordInterface;
use Zend\Crypt\Password\Bcrypt as ZendBcrypt;

/**
 */
class Bcrypt extends ZendBcrypt implements SaltedPasswordInterface
{
}