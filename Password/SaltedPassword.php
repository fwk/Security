<?php
namespace Fwk\Security\Password;

use Zend\Crypt\Password\PasswordInterface;

interface SaltedPassword extends PasswordInterface
{
    public function getSalt();

    public function setSalt($salt);
}