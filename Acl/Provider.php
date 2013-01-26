<?php
namespace Fwk\Security\Acl;

use Fwk\Security\User;
use Zend\Permissions\Acl\Role\RoleInterface;

interface Provider
{
    public function getRoles();

    public function getUserRoles(User $user);

    public function getResources(RoleInterface $role);
    
    public function getResourcesAll();

    public function getRoleResources($role);
}