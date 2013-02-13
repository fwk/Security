<?php
namespace Fwk\Security\User; 

use Zend\Permissions\Acl\Role\RoleInterface;

interface AclAware extends RoleInterface
{
    public function getRoles();
}