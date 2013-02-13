<?php
namespace Fwk\Security\Password\Adapters;

use Zend\Crypt\Password\PasswordInterface;

/**
 * DEPRECATED: This Adapter doesn't crypt anything.
 */
class Clear implements PasswordInterface
{
    public function create($password)
    {
        return $password;
    }

    public function verify($password, $hash)
    {
        return $this->_secureStringCompare($password, $hash);
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
}