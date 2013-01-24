<?php
namespace Fwk\Security\User\Providers;

use Fwk\Security\User\Provider;
use Fwk\Security\Exceptions\UserNotFound;
use Fwk\Security\Exceptions\UserIsExpired;
use Fwk\Security\User;

/**
 * In memory user storage
 */
class Memory implements Provider, \IteratorAggregate, \Countable
{
    /**
     * List of "registered" users
     * 
     * @var array
     */
    protected $users = array();
    
    /**
     * Registers a User
     * 
     * @param User $user To-be-added user
     * 
     * @return Memory 
     */
    public function add(User $user)
    {
        $this->users[$user->getIdentifier()] = $user;
        
        return $this;
    }
    
    /**
     *
     * @param User $user To-be-removed user
     * 
     * @return Memory 
     */
    public function remove(User $user)
    {
        unset($this->users[$user->getIdentifier()]);
        
        return $this;
    }
    
    /**
     * Returns a User by its unique Identifier
     * 
     * @param mixed $identifier User unique identifier
     * 
     * @return User 
     * @throws UserNotFound if no user exists under this identifier
     */
    public function getById($identifier)
    {
        if (!array_key_exists($identifier, $this->users)) {
            throw new UserNotFound(
                sprintf('User id:%s does not exists in memory.', $identifier)
            );
        }
        
        return $this->users[$identifier];
    }
    
    /**
     * Returns a User by its Username 
     * 
     * @param string  $userName Username 
     * @param boolean $strict   Case sensitive check?
     * 
     * @return User 
     * @throws UserNotFound if no user exists with this username
     */
    public function getByUsername($userName, $strict = true)
    {
        $return = null;
        foreach ($this->users as $user) {
            if ($strict && $user->getUsername() === $userName
            || (!$strict &&  $user->getUsername() == $userName)) {
                $return = $user;
                break;
            } 
        }
        
        if (!$return instanceof User) {
            throw new UserNotFound(
                sprintf('User username:%s does not exists in memory.', $userName)
            );
        }
        
        return $return;
    }
    
    /**
     * Tells if the user exists 
     * 
     * @param User $user 
     * 
     * @return boolean
     */
    public function has(User $user)
    {
        return array_key_exists($user->getIdentifier(), $this->users);
    }
    
    /**
     *
     * @param array $users List of User instances to be added
     * 
     * @return Memory 
     */
    public function addAll(array $users)
    {
        foreach ($users as $user) {
            $this->add($user);
        }
        
        return $this;
    }
    
    /**
     * Delete all users
     * 
     * @return Memory
     */
    public function removeAll()
    {
        $this->users = array();
        
        return $this;
    }
    
    /**
     * 
     * @return \ArrayIterator 
     */
    public function getIterator()
    {
        return new \ArrayIterator($this->users);
    }
    
    /**
     * Tells how many users are registered
     * 
     * @return integer
     */
    public function count()
    {
        return count($this->users);
    }
    
    /**
     * Refreshs the User data
     * 
     * @param User $user To-be-refreshed user
     * 
     * @return User 
     * @throws UserHasExpired if user is no longer registered
     */
    public function refresh(User $user)
    {
        if (!$this->has($user)) {
            throw new UserIsExpired();
        }
        
        return $user;
    }
    
    /**
     * Tells if this Provider can handle the User object
     * 
     * @param User $user User instance to be supported
     * 
     * @return boolean
     */
    public function supports(User $user)
    {
        return true;
    }
}