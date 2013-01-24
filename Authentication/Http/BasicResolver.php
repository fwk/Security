<?php
namespace Fwk\Security\Authentication\Http;

use Fwk\Security\Http\UserProviderResolver;
use Fwk\Security\Exceptions\UserProviderException;

class BasicResolver extends UserProviderResolver
{
    /**
     * 
     * @param string $username
     * @param string $realm
     * @param string $password
     * 
     * @return array|false
     */
    public function resolve($username, $realm, $password = null)
    {
        try {
            $user = $this->provider->getByUsername($username, true);
        } catch(UserProviderException $e)  {
            return false;
        }
        
        if ($user->getPasswd() !== $password) {
            return false;
        }
        
        return array(
            'user'          => $user
        );
    }
}