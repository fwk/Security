<?php
namespace Fwk\Security\Acl;

use Fwk\Security\User;
use Zend\Permissions\Acl\Role\RoleInterface;
use Zend\Permissions\Acl\Acl;

interface Provider
{
    const PERMISSION_ALLOW = Acl::TYPE_ALLOW;
    const PERMISSION_DENY  = Acl::TYPE_DENY;
    
    public function getRoles();
    
    public function getResourcesAll();
    
    public function getResources(RoleInterface $role);
    
    public function getPermissions(RoleInterface $role);
    
    public function getPermissionsAll();
}