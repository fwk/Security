<?php
namespace Fwk\Security\Acl;

use Fwk\Security\User;

interface Provider
{
    public function getAllRoles();

    public function getUserRoles(User $user);

    public function getAllResources();

    public function getUserResources(User $user);
}
