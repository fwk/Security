<?php
namespace Fwk\Security\Password;

class Generator implements SaltedPassword
{
    /**
     * The Password Adapter name
     *
     * @var string
     */
    protected $adapterName;

    /**
     * Adapter constructor options
     *
     * @var array
     */
    protected $adapterOptions = array();

    /**
     * The Password Adapter
     *
     * @var PasswordInterface
     */
    protected $adapter;

    /**
     * Constructor
     *
     * @param string|PasswordInterface $adapter Adapter or Adapter name
     * @param array                    $options Adapter constructor options
     * (if any)
     *
     * @return void
     */
    public function __construct($adapter, array $options = array())
    {
        if (is_string($adapter)) {
            $this->adapterName = $adapter;
            $this->adapterOptions = $options;
        } elseif ($adapter instanceof PasswordInterface) {
            $this->adapter = $adapter;
        } else {
            throw new \InvalidArgumentException(
                'The $adapter parameter should be a string or an instance of ' .
                'Zend\Crypt\Password\PasswordInterface'
            );
        }
    }

    /**
     * Crypts a password
     *
     * @param string $password
     *
     * @return string
     */
    public function create($password)
    {
        return $this->getAdapter()->create($password);
    }

    /**
     * (Build if needed) and return the Password Adapter
     * {@see PasswordInterface}
     *
     * @return PasswordInterface
     */
    public function getAdapter()
    {
        if (!isset($this->adapter)) {
            $factory = new AdapterFactoryStrategy($this->adapterName);
            $this->adapter = $factory->factory($this->adapterOptions);
        }

        return $this->adapter;
    }

    /**
     * Verifies a password.
     *
     * @param string $password The password to verify
     * @param string $hash     The already crypted password to compare
     *
     * @return boolean
     */
    public function verify($password, $hash)
    {
        return $this->getAdapter()->verify($password, $hash);
    }

    /**
     * Returns the actual salt of the Adapter or null if not present/supported
     *
     * @return string|null
     */
    public function getSalt()
    {
        $adapter = $this->getAdapter();
        if ($adapter instanceof SaltedPassword) {
            return $adapter->getSalt();
        }

        return null;
    }

    /**
     * Defines a Salt for a SaltedPasswordInterface Adapter
     *
     * @param string $salt
     *
     * @return Generator
     */
    public function setSalt($salt)
    {
        $adapter = $this->getAdapter();
        if ($adapter instanceof SaltedPassword) {
            $adapter->setSalt($salt);
        }

        return $this;
    }

    public function clearSalt()
    {
        $adapter = $this->getAdapter();
        if ($adapter instanceof SaltedPassword) {
            $adapter->clearSalt();
        }

        return $this;
    }
}