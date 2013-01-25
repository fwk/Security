<?php
namespace Fwk\Security;

use Fwk\Security\Authentication\Manager as AuthManager;
use Fwk\Security\User\Provider as UserProvider;

class SecurityService
{
    /**
     * The User Entity
     * 
     * @var mixed
     */
    protected $user;
    
    /**
     * User Provider
     * 
     * @var UserProvider 
     */
    protected $userProvider;
    
    /**
     * Authentication Manager
     * 
     * @var AuthManager 
     */
    protected $authenticationManager;
    
    /**
     *
     * @return mixed
     */
    public function getUser()
    {
        if (!isset($this->user)) {
            
        }
        
        return $this->user;
    }

    /**
     * Returns the User Provider
     * 
     * @return UserProvider
     */
    public function getUserProvider()
    {
        return $this->userProvider;
    }

    /**
     * Defines the User Provider
     * 
     * @param UserProvider $userProvider The User Provider
     * 
     * @return SecurityService 
     */
    public function setUserProvider(UserProvider $userProvider)
    {
        $this->userProvider = $userProvider;
        
        return $this;
    }
    
    /**
     * Returns the Authentication Manager
     * 
     * @return AuthManager 
     */
    public function getAuthenticationManager() 
    {
        return $this->authenticationManager;
    }

    /**
     * Defines the Authentication Manager
     * 
     * @param AuthManager $authenticationManager Authentication Manager
     * 
     * @return SecurityService
     */
    public function setAuthenticationManager(AuthManager $authenticationManager)
    {
        $this->authenticationManager = $authenticationManager;
        
        return $this;
    }
}