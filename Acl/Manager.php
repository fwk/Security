<?php
namespace Fwk\Security\Acl;

use Zend\Permissions\Acl\Acl;

class Manager extends Acl
{
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
            $this->loadFromProvider();
        }
    }
    
    /**
     * Loads ACLs from the Provider
     * 
     * @return void 
     */ 
    protected function loadFromProvider()
    {
        if (!isset($this->provider)) {
            return;
        }
        
        $roles = $this->provider->getRoles();
        foreach ($roles as $data) {
            $this->addRole($data['role'], $data['parents']);
            
            $resources = $this->provider->getResources($data['role']);
            foreach ($resources as $data) {
                if ($this->hasResource($data['resource'])) {
                    continue;
                }
                
                $this->addResource($data['resource'], $data['parents']);
            }
        }
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