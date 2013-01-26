<?php
namespace Fwk\Security\Acl\Providers;

use Fwk\Security\Acl\AbstractProvider;
use Fwk\Security\Acl\Provider;
use Zend\Permissions\Acl\Role\RoleInterface;
use Zend\Permissions\Acl\Resource\ResourceInterface;
use Fwk\Security\User;

class Memory implements Provider
{
    protected $roles        = array();
    protected $resources    = array();
    protected $permissions  = array();
    
    public function addRole(RoleInterface $role, $parent = null)
    {
        $this->roles[$role->getRoleId()] = array(
            'role'       => $role,
            'parents'    => $parent
        );
        
        return $this;
    }
    
    public function addRoles(array $roles)
    {
        foreach ($roles as $data) {
            if (is_array($data) && isset($data['role'])) {
                $this->addRole(
                    $data['role'], 
                    (isset($data['parents']) ? $data['parents'] : null)
                );
            } 
            // it's a role with no parent
            elseif ($data instanceof RoleInterface) {
                $this->addRole($data);
            } 
            // since we can't determine which RoleInterface should be used we
            // don't allow other arguments
            else {
                throw new \InvalidArgumentException(
                    'Role should be an array() or an instance of RoleInterface.'
                );
            }
        }
        
        return $this;
    }
    
    public function hasRole(RoleInterface $role)
    {
        return array_key_exists($role->getRoleId(), $this->roles);
    }
    
    public function removeRole(RoleInterface $role)
    {
        unset($this->roles[$role->getRoleId()]);
        
        return $this;
    }
    
    public function removeRoles(array $roles)
    {
        foreach ($roles as $role) {
            $this->removeRole($role);
        }
        
        return $this;
    }
    
    public function getRoles()
    {
        return $this->roles;
    }
    
    public function addResource(ResourceInterface $resource, $parents = null)
    {
        $this->resources[$resource->getResourceId()] = array(
            'resource'  => $resource,
            'parents'   => $parents
        );
        
        return $this;
    }
    
    public function addResources(array $resources)
    {
        foreach ($resources as $data) {
            if (is_array($data) && isset($data['resource'])) {
                $this->addResource(
                        $data['resource'], 
                        (isset($data['parents']) ? $data['parents'] : null)
                );
            } 
            // it's a role with no parent
            elseif ($data instanceof ResourceInterface) {
                $this->addResource($data);
            } 
            // since we can't determine which ResourceInterface should be used we
            // don't allow other arguments
            else {
                throw new \InvalidArgumentException(
                    'Role should be an array() or an instance of ResourceInterface.'
                );
            }
        }
        
        return $this;
    }
    
    public function hasResource(ResourceInterface $resource)
    {
        return array_key_exists($resource->getResourceId(), $this->resources);
    }
    
    public function removeResource(ResourceInterface $resource)
    {
        unset($this->resources[$resource->getResourceId()]);
        
        return $this;
    }
    
    public function getResourcesAll()
    {
        return $this->resources;
    }
    
    public function getResources(RoleInterface $role)
    {
        
        return $this->resources;
    }
    
    public function getUserRoles(User $user)
    {
        return array();
    }
    
    public function getRoleResources($role)
    {
        return array();
    }
}