<?php
namespace Fwk\Security\Authentication;

use Zend\Authentication\Adapter\AdapterInterface;
use Symfony\Component\HttpFoundation\Request as HttpFoundationRequest;
use Zend\Http\Request as ZendRequest;
use Symfony\Component\HttpFoundation\Response;
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
    
    public static function newZendRequest(HttpFoundationRequest $request = null)
    {
        if (null === $request) {
            $requestStr = HttpFoundationRequest::createFromGlobals()->__toString();
        } else {
            $requestStr = $request->__toString();
        }
        
        $requestStr = preg_replace('/\:(\s{2,}+)/', ': ', $requestStr);

        return ZendRequest::fromString($requestStr);
    }
}