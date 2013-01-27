<?php
namespace Fwk\Security\Acl;

use Fwk\Security\SecurityEvent;
use Fwk\Security\User\AclAware;

class LoadUserAclListener
{
    public function onAuthenticationSuccess(SecurityEvent $event)
    {
        $service    = $event->getService();
        $user       = $event->user;
        
        if (!is_object($user) || !$user instanceof AclAware) {
            return;
        }
        
        $acl        = $service->getAclManager();
        if (!$acl->hasRole($user->getRoleId())) {
            $acl->addRole($user, $user->getRoles());
            if ($acl->hasProvider()) {
                $acl->loadResources($acl->getProvider(), $user, true);
                $acl->loadPermissions($acl->getProvider(), $user, true);
            }
        }
    }
}