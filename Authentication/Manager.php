<?php
namespace Fwk\Security\Authentication;

use Zend\Authentication\Adapter\AdapterInterface;
use Zend\Authentication\AuthenticationService;

use Fwk\Security\Exceptions\InvalidCredentials, 
    Fwk\Security\Exceptions\UserNotFound,
    Fwk\Security\Exceptions\AuthenticationException;

/**
 * Wrapper 
 */
class Manager extends AuthenticationService
{    
    public function authenticate(AdapterInterface $adapter = null)
    {
        $zresult    = parent::authenticate($adapter);
        $result     = new Result(
            $zresult->getCode(), 
            $zresult->getIdentity(), 
            $zresult->getMessages()
        );
        
        return new Result(
            $zresult->getCode(), 
            $zresult->getIdentity(), 
            $zresult->getMessages()
        );
    }
}