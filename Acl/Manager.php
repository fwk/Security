<?php
namespace Fwk\Security\Acl;

use Zend\Permissions\Acl\Acl;
use Zend\Permissions\Acl\Role\RoleInterface;

class Manager extends Acl
{
    const DYNAMIC_CHAR = ':';
    
    /**
     * Acl Provider
     * 
     * @var Provider
     */
    protected $provider;
    
    /**
     * Constructor
     * 
     * @param Provider $aclProvider The Acl Provider
     * 
     * @return void
     */
    public function __construct(Provider $aclProvider = null)
    {
        $this->provider = $aclProvider;
        
        if (null !== $aclProvider) {
            $this->load($aclProvider, false);
        }
    }
    
    /**
     * Loads ACLs from the Provider
     * 
     * @return void 
     */ 
    public function load(Provider $provider, $dynamics = false)
    {
        $roles = $provider->getRoles();
        foreach ($roles as $data) {
            if ($this->hasRole($data['role'])) {
                continue;
            }
            
            $this->addRole($data['role'], $data['parents']);
        }
        
        $this->loadResources($provider, null);
        $this->loadPermissions($provider, null, $dynamics);
    }
    
    public function loadResources(Provider $provider, 
        RoleInterface $role = null
    ) {
        if (null === $role) {
            $resources = $provider->getResourcesAll();
        } else {
            $resources = $provider->getResources($role);
        }
        
        foreach ($resources as $data) {
            if ($this->hasResource($data['resource'])) {
                continue;
            }
            
            $this->addResource($data['resource'], $data['parents']);
        }
    }
    
    public function loadPermissions(Provider $provider, 
        RoleInterface $role = null, $dynamics = false
    ) {
        if (null === $role) {
            $perms = $provider->getPermissionsAll();
        } else {
            $perms = $provider->getPermissions($role);
        }
        
        foreach ($perms as $permission) {
            $roleStr = ($permission['role'] instanceof RoleInterface ? 
                $permission['role']->getRoleId() : 
                $permission['role']
            );
            
            if (strpos($roleStr, self::DYNAMIC_CHAR) !== false 
                    && !$dynamics) {
                continue;
            } 
            
            $this->setRule(
                self::OP_ADD, 
                $permission['rule'], 
                $permission['role'], 
                $permission['resource'], 
                $permission['what'], 
                $permission['assert']
            );
        }
    }
    
    public function hasProvider()
    {
        return ($this->provider instanceof Provider);
    }
    
    /**
     * Sets the Acl Provider
     * 
     * @return Provider
     */
    public function getProvider() 
    {
        return $this->provider;
    }

    /**
     * Defines the Acl Provider
     * 
     * @param Provider $aclProvider
     * 
     * @return Manager 
     */
    public function setProvider(Provider $aclProvider) 
    {
        $this->provider = $aclProvider;
        
        return $this;
    }
}