<?php
namespace Fwk\Security\User;

use Fwk\Security\User;

interface Provider
{
    /**
     * Returns a User by its unique Identifier
     * 
     * @param mixed $identifier User unique identifier
     * 
     * @return User 
     * @throws UserNotFound if no user exists under this identifier
     */
    public function getById($identifier);
    
    /**
     * Returns a User by its Username 
     * 
     * @param string  $userName Username 
     * @param boolean $strict   Case sensitive check?
     * 
     * @return User 
     * @throws UserNotFound if no user exists with this username
     */
    public function getByUsername($userName, $strict = true);
    
    /**
     * Refreshs the User data
     * 
     * @param User $user To-be-refreshed user
     * 
     * @return User 
     * @throws UserHasExpired if user is no longer registered
     */
    public function refresh(User $user);
    
    public function supports(User $user);
}
