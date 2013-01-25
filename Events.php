<?php
namespace Fwk\Security;

abstract class Events
{
    const BEFORE_AUTHENTICATION     = 'beforeAuthentication';
    const AFTER_AUTHENTICATION      = 'afterAuthentication';
    
    const AUTHENTICATION_ERROR      = 'authenticationError';
    const AUTHENTICATION_SUCCESS    = 'authenticationSuccess';
}