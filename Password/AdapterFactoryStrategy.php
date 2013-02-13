<?php
namespace Fwk\Security\Password;

use Zend\Crypt\Password\PasswordInterface;

class AdapterFactoryStrategy
{
    /**
     * Adapter's short name
     *
     * @var string
     */
    protected $adapterName;

    /**
     * List of supported Adapters and their default options
     *
     * @var array
     */
    protected $adapters = array(
        'bcrypt' => array(
            'class'     => 'Fwk\\Security\\Password\\Adapters\\Bcrypt',
            'options'   => array()
        ),
        'hash' => array(
            'class'     => 'Fwk\\Security\\Password\\Adapters\\Hash',
            'options'   => array(
                'algo'  => 'md5'
            )
        ),
        'clear' => array(
            'class'     => 'Fwk\\Security\\Password\\Adapters\\Clear',
            'options'   => array()
        ),
        // shortcut
        'md5' => array(
            'class'     => 'Fwk\\Security\\Password\\Adapters\\Hash',
            'options'   => array(
                'algo'  => 'md5'
            )
        ),
        // shortcut
        'sha1' => array(
            'class'     => 'Fwk\\Security\\Password\\Adapters\\Hash',
            'options'   => array(
                'algo'  => 'sha1'
            )
        ),
        // shortcut
        'sha256' => array(
            'class'     => 'Fwk\\Security\\Password\\Adapters\\Hash',
            'options'   => array(
                'algo'  => 'sha256'
            )
        ),
        'pbkdf2' => array(
            'class'     => 'Fwk\\Security\\Password\\Adapters\\Pbkdf2',
            'options'   => array()
        )
    );

    /**
     * Constructor
     *
     * @param string $adapterName Adapter's short name
     *
     * @return void
     */
    public function __construct($adapterName)
    {
        $this->adapterName = $adapterName;
    }

    /**
     *
     * @param array $options
     * @return PasswordInterface
     *
     * @throws \RuntimeException
     */
    public function factory(array $options = array())
    {
        if (!array_key_exists($this->adapterName, $this->adapters)) {
            throw new \RuntimeException(
                "Adapter not found: '$this->adapterName'"
            );
        }

        $opts = array_merge(
            $this->adapters[$this->adapterName]['options'],
            $options
        );

        return new $this->adapters[$this->adapterName]['class']($opts);
    }

    /**
     * Returns the Adapter name
     *
     * @return string
     */
    public function getAdapterName()
    {
        return $this->adapterName;
    }

    /**
     * Defines the Adapter name
     *
     * @param string $adapterName Adapter's short name
     *
     * @return AdapterFactoryStrategy
     */
    public function setAdapterName($adapterName)
    {
        $this->adapterName = $adapterName;

        return $this;
    }
}