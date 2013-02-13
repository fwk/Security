<?php
namespace Fwk\Security\Http;

use Zend\Authentication\Storage\StorageInterface;
use Symfony\Component\HttpFoundation\Session\Session;

class SessionStorage implements StorageInterface
{
    const SESSION_STO_KEY = '_fwk.security.store';
    const STRATEGY_MIGRATE = 'migrate';
    const STRATEGY_INVALIDATES = 'invalidate';
    const DEFAULT_NAMESPACE = 'default';

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
     * Tells if we should use the migration strategy or not.
     * When using multiple auth managers, it's recommended to turn it off
     * because it would remove ALL identities at once.
     *
     * @var boolean
     */
    protected $applyStrategy;

    /**
     * Storage Namespace
     *
     * @var string
     */
    protected $namespace = self::DEFAULT_NAMESPACE;

    /**
     * Constructor
     *
     * @param Session $session       HttpFoundation Session Object
     * @param string  $strategy      Migration strategy when clearing credentials
     * @param string  $namespace     Storage namespace
     * @param boolean $applyStrategy Should we apply strategy on clear() ?
     * 
     * @return void
     */
    public function __construct(Session $session,
        $strategy = self::STRATEGY_MIGRATE, $namespace = self::DEFAULT_NAMESPACE,
        $applyStrategy = true
    ) {
        $this->session          = $session;
        $this->strategy         = $strategy;
        $this->namespace        = $namespace;
        $this->applyStrategy    = $applyStrategy;
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

        $this->session->set(self::SESSION_STO_KEY . '-'. $this->namespace, $contents);
    }

    /**
     * Clears the storage
     *
     * @return void
     */
    public function clear()
    {
        if ($this->session->isStarted()) {
            $this->session->remove(self::SESSION_STO_KEY . '-'. $this->namespace);
        }

        if ($this->isApplyStrategy()) {
            $this->applySessionStrategy();
        }
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

        return !$this->session->has(self::SESSION_STO_KEY . '-'. $this->namespace);
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

        return $this->session->get(self::SESSION_STO_KEY . '-'. $this->namespace, false);
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
            case self::STRATEGY_MIGRATE:
                $this->session->migrate();
                break;

            case self::STRATEGY_INVALIDATES:
                $this->session->invalidate();
                break;

            default:
                 throw new \RuntimeException(
                     'Session strategy should be "migrate" or "invalidate"'
                 );
        }
    }

    /**
     * Returns the Storage namespace
     *
     * @return string
     */
    public function getNamespace()
    {
        return $this->namespace;
    }

    /**
     * Defines the Storage namespace
     *
     * @param string $namespace Storage namespace
     *
     * @return SessionStorage
     */
    public function setNamespace($namespace)
    {
        $this->namespace = $namespace;

        return $this;
    }

    /**
     * Tells if the strategy is enabled
     *
     * @return boolean
     */
    public function isApplyStrategy()
    {
        return $this->applyStrategy;
    }

    /**
     * Should we use the Session strategy or not?
     *
     * @param boolean $applyStrategy
     *
     * @return SessionStorage
     */
    public function setApplyStrategy($applyStrategy)
    {
        $this->applyStrategy = (bool)$applyStrategy;

        return $this;
    }
}