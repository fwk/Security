<?php
namespace Fwk\Security\Password\Adapters;

use Zend\Crypt\Password\PasswordInterface;

/**
 * This Adapter is a wrapper around the hash() function.
 *
 * Hashes are deprecated to use as password algorythms but sometimes they are
 * useful when too much security isn't required.
 */
class Hash implements PasswordInterface
{
    protected $algo;

    public function __construct(array $options = array())
    {
        $this->algo = (isset($options['algo']) ? $options['algo'] : 'md5');
    }

    public function create($password)
    {
        return hash($this->algo, $password);
    }

    public function verify($password, $hash)
    {
        return hash($this->algo, $password) === $hash;
    }

    public function getAlgo()
    {
        return $this->algo;
    }

    public function setAlgo($algo)
    {
        $this->algo = $algo;
    }
}