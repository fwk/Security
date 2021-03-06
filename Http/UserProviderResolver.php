<?php
namespace Fwk\Security\Http;

use Fwk\Security\User\Provider;
use Zend\Authentication\Adapter\Http\ResolverInterface;

abstract class UserProviderResolver implements ResolverInterface
{
    /**
     * User Provider to use
     * 
     * @var Provider 
     */
    protected $provider;
    
    /**
     * Constructor 
     * 
     * @param Provider $provider User Provider
     * 
     * @return void
     */
    public function __construct(Provider $provider)
    {
        $this->provider = $provider;
    }
    
    /**
     * 
     * @param string $username
     * @param string $realm
     * @param string $password
     * 
     * @return array|false
     */
    abstract public function resolve($username, $realm, $password = null);
    
    /**
     * Returns the User Provider
     * 
     * @return Provider 
     */
    public function getProvider()
    {
        return $this->provider;
    }

    /**
     * Defines the User Provider
     * 
     * @param Provider $provider User Provider
     * 
     * @return UserProviderResolver 
     */
    public function setProvider(Provider $provider) 
    {
        $this->provider = $provider;
        
        return $this;
    }
}