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
    protected $aclProvider;
    
    /**
     * Sets the Acl Provider
     * 
     * @return Provider
     */
    public function getAclProvider() 
    {
        return $this->aclProvider;
    }

    /**
     * Defines the Acl Provider
     * 
     * @param Provider $aclProvider
     * 
     * @return Manager 
     */
    public function setAclProvider(Provider $aclProvider) 
    {
        $this->aclProvider = $aclProvider;
        
        return $this;
    }
}