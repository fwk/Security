<?php
namespace Fwk\Security;

use Fwk\Security\Authentication\Manager as AuthManager;
use Fwk\Security\Acl\Manager as AclManager;
use Fwk\Security\User\Provider as UserProvider;

class SecurityService
{
    /**
     * The User Entity
     * 
     * @var User
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
     * Acl Manager
     * 
     * @var AclManager
     */
    protected $aclManager;
    
    /**
     * Constructor
     * 
     * @param AuthManager  $manager    The Authentification Manager
     * @param UserProvider $provider   The User Provider
     * @param AclManager   $aclManager The Acl Manager (if any)
     * 
     * @return void
     */
    public function __construct(AuthManager $manager, UserProvider $provider,
            AclManager $aclManager = null)
    {
        $this->authenticationManager    = $manager;
        $this->userProvider             = $provider;
        $this->aclManager               = $aclManager;
    }
    
    /**
     *
     * @return User
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
    
    /**
     * Returns the Acl Manager
     * 
     * @return AclManager 
     */
    public function getAclManager() 
    {
        return $this->aclManager;
    }

    /**
     * Defines the Authentication Manager
     * 
     * @param AclManager $aclManager Acl Manager
     * 
     * @return SecurityService
     */
    public function setAclManager(AclManager $aclManager)
    {
        $this->aclManager = $aclManager;
        
        return $this;
    }
}