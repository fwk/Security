<?php
namespace Fwk\Security\Http;

use Zend\Authentication\Storage\StorageInterface;
use Symfony\Component\HttpFoundation\Session\Session;

class SessionStorage implements StorageInterface
{
    const SESSION_STO_KEY = '_fwk.security.store';
    
    /**
     * HttpFoundation Session Object
     * 
     * @var Session
     */
    protected $session;
    
    /**
     * Strategy when it comes to clearing the session.
     * Possibles values are: invalidate or migrate
     * 
     * @var string
     */
    protected $strategy = 'migrate';
    
    /**
     * Constructor 
     * 
     * @param Session $session  HttpFoundation Session Object
     * @param string  $strategy Migration strategy when clearing credentials
     * 
     * @return void
     */
    public function __construct(Session $session, $strategy = 'migrate')
    {
        $this->session = $session;
    }
    
    /**
     * Writes contents into storage/session
     * 
     * @param mixed $contents 
     * 
     * @return void
     */
    public function write($contents)
    {
        if (!$this->session->isStarted()) {
            $this->session->start();
        }
        
        $this->session->set(self::SESSION_STO_KEY, $contents);
    }
    
    /**
     * Clears the storage
     * 
     * @return void
     */
    public function clear()
    {
        if ($this->session->isStarted()) {
            $this->session->remove(self::SESSION_STO_KEY);
        }
        
        $this->applySessionStrategy();
    }
    
    /**
     * Tells if the storage is empty
     * 
     * @return boolean
     */
    public function isEmpty()
    {
        if (!$this->session->isStarted()) {
            $this->session->start();
        }
        
        return $this->session->has(self::SESSION_STO_KEY);
    }
    
    /**
     * Reads the storage content
     * 
     * @return mixed
     */
    public function read()
    {
        if (!$this->session->isStarted()) {
            $this->session->start();
        }
        
        return $this->session->get(self::SESSION_STO_KEY, false);
    }
    
    /**
     * Returns the Session Object
     * 
     * @return Session
     */
    public function getSession()
    {
        return $this->session;
    }
    
    /**
     * Returns session migration strategy
     * 
     * @return string
     */
    public function getStrategy()
    {
        return $this->strategy;
    }
    
    /**
     * Defines the session strategy when invalidating credentials.
     * Possibles values are: migrate or invalidate
     * 
     * @param string $strategy
     * 
     * @return SessionStorage 
     */
    public function setStrategy($strategy)
    {
        $this->strategy = $strategy;
        
        return $this;
    }
    
    /**
     * Apply the Session Strategy
     * 
     * @return void
     */
    protected function applySessionStrategy()
    {
        if (!$this->session->isStarted()) {
            return $this->session->start();
        }
        
        switch($this->strategy)
        {
            case 'migrate':
                $this->session->migrate(true);
                break;
            
            case 'invalidate':
                $this->session->invalidate();
                break;
            
            default:
                 throw new \RuntimeException(
                     'Session strategy should be "migrate" or "invalidate"'
                 );
        }
    }
}