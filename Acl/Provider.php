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

    public function getUserRoles(User $user);

    public function getResources(RoleInterface $role);
    
    public function getResourcesAll();

    public function getRoleResources($role);
}