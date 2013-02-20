<?php
namespace Fwk\Security;

abstract class Events
{
    const BEFORE_AUTHENTICATION     = 'beforeAuthentication';
    const AFTER_AUTHENTICATION      = 'afterAuthentication';
    
    const AUTHENTICATION_ERROR      = 'authenticationError';
    const AUTHENTICATION_SUCCESS    = 'authenticationSuccess';
    
    const BEFORE_DEAUTHENTICATION   = 'beforeDeauthentication';
    const DEAUTHENTICATION_ERROR      = 'deauthenticationError';
    const DEAUTHENTICATION_SUCCESS    = 'deauthenticationSuccess';
    
    const USER_LOADED               = 'userLoaded';
}