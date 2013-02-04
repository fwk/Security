<?php
namespace Fwk\Security\Password\Adapters;

use Zend\Crypt\Key\Derivation\Pbkdf2 as ZendPbkdf2;
use Zend\Math\Rand;
use Fwk\Security\Password\SaltedPassword;

/**
 */
class Pbkdf2 implements SaltedPassword
{
    protected $salt;
    protected $hash         = 'sha256';
    protected $iterations   = 10000;
    protected $outputSize   = 32;
    protected $rawOutput    = false;

    public function __construct(array $options = array())
    {
        if (isset($options['salt']) && !empty($options['salt'])) {
            $this->salt = $options['salt'];
        } else {
            $this->salt = Rand::getBytes(32, true);
        }

        if (isset($options['hash']) && !empty($options['hash'])) {
            $this->hash = (string)$options['hash'];
        }

        if (isset($options['iterations']) && !empty($options['iterations'])) {
            $this->iterations = (int)$options['iterations'];
        }

        if (isset($options['outputSize']) && is_int($options['outputSize']) && $options['outputSize'] > 0) {
            $this->outputSize = (int)$options['outputSize'];
        }

        if (isset($options['rawOutput'])) {
            $this->rawOutput = (bool)$options['rawOutput'];
        }
    }

    public function create($password)
    {
        return ZendPbkdf2::calc(
            $this->hash,
            $password,
            $this->salt,
            $this->iterations,
            $this->outputSize,
            $this->rawOutput
        );
    }

    public function verify($password, $hash)
    {
        $res = ZendPbkdf2::calc(
            $this->hash,
            $password,
            $this->salt,
            $this->iterations,
            $this->outputSize,
            $this->rawOutput
        );

        return $this->_secureStringCompare($res, $hash);
    }

    public function getSalt()
    {
        return $this->salt;
    }

    public function setSalt($salt)
    {
        $this->salt = $salt;

        return $this;
    }

    public function getHash()
    {
        return $this->hash;
    }

    public function setHash($hash)
    {
        $this->hash = $hash;
    }

    public function getIterations()
    {
        return $this->iterations;
    }

    public function setIterations($iterations)
    {
        $this->iterations = (int)$iterations;

        return $this;
    }

    public function getOutputSize()
    {
        return $this->outputSize;
    }

    public function setOutputSize($outputSize)
    {
        $this->outputSize = (int)$outputSize;

        return $this;
    }

    public function getRawOutput()
    {
        return $this->rawOutput;
    }

    public function setRawOutput($rawOutput)
    {
        $this->rawOutput = (bool)$rawOutput;

        return $this;
    }

    /**
     * Securely compare two strings for equality while avoided C level memcmp()
     * optimisations capable of leaking timing information useful to an attacker
     * attempting to iteratively guess the unknown string (e.g. password) being
     * compared against.
     *
     * @param string $a
     * @param string $b
     * @return bool
     */
    protected function _secureStringCompare($a, $b)
    {
        if (strlen($a) !== strlen($b)) {
            return false;
        }
        $result = 0;
        for ($i = 0; $i < strlen($a); $i++) {
            $result |= ord($a[$i]) ^ ord($b[$i]);
        }
        return $result == 0;
    }
    
    public function clearSalt()
    {
        unset($this->salt);
        return $this;
    }
}