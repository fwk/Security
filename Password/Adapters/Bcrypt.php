<?php
namespace Fwk\Security\Password\Adapters;

use Fwk\Security\Password\SaltedPasswordInterface;
use Zend\Crypt\Password\Bcrypt as ZendBcrypt;
use Zend\Math\Rand;

/**
 */
class Bcrypt extends ZendBcrypt implements SaltedPasswordInterface
{
    public function create($password)
    {
        if (empty($this->salt)) {
            $salt = $this->salt = Rand::getBytes(self::MIN_SALT_SIZE);
        } else {
            $salt = $this->salt;
        }
        
        return parent::create($password);
    }
    
    public function clearSalt()
    {
        unset($this->salt);
    }
}