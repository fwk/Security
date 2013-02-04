<?php
namespace Fwk\Security;

use Fwk\Security\Authentication\Manager as AuthManager;
use Fwk\Security\Acl\Manager as AclManager;
use Fwk\Security\User\Provider as UserProvider;
use Fwk\Security\Exceptions\AuthenticationException;
use Fwk\Events\Dispatcher;
use Zend\Authentication\Result as ZendResult;
use Symfony\Component\HttpFoundation\Request;
use Fwk\Security\User\AclAware;

class Service extends Dispatcher
{
    /**
     * The User Entity
     *
     * @var User
     */
    protected $user;

    /**
     * User Provider
     *
     * @var UserProvider
     */
    protected $userProvider;

    /**
     * Authentication Manager
     *
     * @var AuthManager
     */
    protected $authenticationManager;

    /**
     * Acl Manager
     *
     * @var AclManager
     */
    protected $aclManager;

    /**
     * Constructor
     *
     * @param AuthManager  $manager    The Authentification Manager
     * @param UserProvider $provider   The User Provider
     * @param AclManager   $aclManager The Acl Manager (if any)
     *
     * @return void
     */
    public function __construct(AuthManager $manager, UserProvider $provider,
        AclManager $aclManager = null
    ) {
        $this->authenticationManager    = $manager;
        $this->userProvider             = $provider;
        $this->aclManager               = $aclManager;
    }

    /**
     *
     * @return User
     */
    public function getUser(Request $request = null)
    {
        if (!isset($this->user)) {
            if (!$identity = $this->authenticationManager->getIdentity()) {
                $result = $this->doAuthentication($request);
                if (!$result) {
                    return null;
                }
                
                $identity = $result->getIdentity();
            } 
            
            if (isset($identity['identifier'])) {
                $user = $this->userProvider->getById($identity['identifier']);
            } elseif (isset($identity['username'])) {
                $user = $this->userProvider->getByUsername(
                    $identity['username'],
                    true
                );
            } else {
                return null;
            }

            $this->user = $user;
            $this->notifyEvent(
                Events::USER_LOADED, array('user' => $user)
            );
        }

        return $this->user;
    }

    /**
     * Returns the User Provider
     *
     * @return UserProvider
     */
    public function getUserProvider()
    {
        return $this->userProvider;
    }

    /**
     * Defines the User Provider
     *
     * @param UserProvider $userProvider The User Provider
     *
     * @return SecurityService
     */
    public function setUserProvider(UserProvider $userProvider)
    {
        $this->userProvider = $userProvider;

        return $this;
    }

    /**
     * Returns the Authentication Manager
     *
     * @return AuthManager
     */
    public function getAuthenticationManager()
    {
        return $this->authenticationManager;
    }

    /**
     * Defines the Authentication Manager
     *
     * @param AuthManager $authenticationManager Authentication Manager
     *
     * @return SecurityService
     */
    public function setAuthenticationManager(AuthManager $authenticationManager)
    {
        $this->authenticationManager = $authenticationManager;

        return $this;
    }

    /**
     * Returns the Acl Manager
     *
     * @return AclManager
     */
    public function getAclManager()
    {
        return $this->aclManager;
    }

    /**
     * Defines the Authentication Manager
     *
     * @param AclManager $aclManager Acl Manager
     *
     * @return SecurityService
     */
    public function setAclManager(AclManager $aclManager)
    {
        $this->aclManager = $aclManager;

        return $this;
    }

    /**
     * Notifies a SecurityEvent
     *
     * @param string $eventName
     * @param array  $data
     *
     * @return void
     */
    protected function notifyEvent($eventName, array $data = array())
    {
        $this->notify(SecurityEvent::factory($eventName, $this, $data));
    }
    
    protected function doAuthentication(Request $request = null)
    {
        $this->notifyEvent(
            Events::BEFORE_AUTHENTICATION, array('request' => $request)
        );

        $result = $this->authenticationManager->authenticate();
        $this->notifyEvent(Events::AFTER_AUTHENTICATION, array(
            'request'   => $request,
            'result'    => $result
        ));

        if (!$result->isValid() || $result->getCode() !== ZendResult::SUCCESS) {
            $this->notifyEvent(Events::AUTHENTICATION_ERROR, array(
                'request'   => $request,
                'result'    => $result,
                'messages'  => $result->getMessages()
            ));
            return null;
        }
        
        $this->notifyEvent(Events::AUTHENTICATION_SUCCESS, array(
            'request'   => $request,
            'result'    => $result
        ));
        
        return $result;
    }
}