<?php
namespace Fwk\Security\Authentication\Adapters;

use Fwk\Security\User\Provider;
use Fwk\Security\Password\Generator;
use Zend\Authentication\Adapter\AdapterInterface;
use Fwk\Security\Exceptions\UserNotFound;
use Fwk\Security\Exceptions\UserProviderException;
use Zend\Authentication\Result;
use Fwk\Security\Accessor;

class PasswordAdapter implements AdapterInterface
{
    /**
     * Submitted username
     *
     * @var string
     */
    protected $username;

    /**
     * Submitted password
     *
     * @var string
     */
    protected $password;

    /**
     * Password Generator
     *
     * @var Generator
     */
    protected $generator;

    /**
     * User Provider
     *
     * @var Provider
     */
    protected $provider;

    /**
     * Property of the User object where is stored the crypted password
     *
     * @var string
     */
    protected $passwordProperty;

    /**
     * Closure function to calculate the password's salt
     *
     * @var \Closure
     */
    protected $saltClosure;

    /**
     * Constructor
     *
     * @param string    $username         Submitted username
     * @param string    $password         Submitted password
     * @param Generator $generator        Password generator
     * @param Provider  $userProvider     User Provider
     * @param string    $passwordProperty Property of the User object where is
     * stored the crypted password
     * @param \Closure  $saltClosure      A closure or callable that returns the
     * salt. Takes an User as the only argument. Only works with SaltedPassword.
     *
     * @return void
     */
    public function __construct($username, $password, Generator $generator,
        Provider $userProvider, $passwordProperty, \Closure $saltClosure = null
    ) {
        $this->username         = $username;
        $this->password         = $password;
        $this->generator        = $generator;
        $this->provider         = $userProvider;
        $this->passwordProperty = $passwordProperty;
        $this->saltClosure      = $saltClosure;
    }

    /**
     * Try to auth the User
     *
     * @return Result
     */
    public function authenticate()
    {
        try {
            $user = $this->provider->getByUsername($this->username);
        } catch(UserNotFound $e) {
            return new Result(
                Result::FAILURE_IDENTITY_NOT_FOUND,
                null,
                array('identity not found in the specified User Provider')
            );
        } catch(UserProviderException $e) {
            return new Result(
                Result::FAILURE_UNCATEGORIZED,
                null,
                array($e->getMessage())
            );
        }

        $accessor = new Accessor($user);
        $crypted  = $accessor->get($this->passwordProperty);
        if (false === $crypted) {
            return new Result(
                Result::FAILURE_UNCATEGORIZED,
                null,
                array('invalid $passwordProperty defined')
            );
        }

        if (is_callable($this->saltClosure)) {
            $computedSalt = true;
            $this->generator->setSalt(
                call_user_func_array($this->saltClosure, array($user))
            );
        }
        $verify = $this->generator->verify($this->password, $crypted);
        if (isset($computedSalt)) {
            $this->generator->clearSalt();
        }

        if ($verify === true) {
            return new Result(
                Result::SUCCESS,
                array(
                    'identifier' => $user->getIdentifier(),
                    'username'   => $user->getUsername()
                ),
                array()
            );
        }

        return new Result(
            Result::FAILURE_CREDENTIAL_INVALID,
            null,
            array('invalid credentials')
        );
    }

    /**
     * Factory utility
     *
     * @param string    $username         Submitted username
     * @param string    $password         Submitted password
     * @param Generator $generator        Password generator
     * @param Provider  $userProvider     User Provider
     * @param string    $passwordProperty Property of the User object where is
     * stored the crypted password
     * @param \Closure  $saltClosure      A closure or callable that returns the
     * salt. Takes an User as the only argument. Only works with SaltedPassword.
     *
     * @return PasswordAdapter
     */
    public static function factory($username, $password, Generator $generator,
        Provider $userProvider, $passwordProperty, \Closure $saltClosure = null
    ) {
        return new self(
            $username,
            $password,
            $generator,
            $userProvider,
            $passwordProperty,
            $saltClosure
        );
    }

    /**
     * Returns the submitted username
     *
     * @return string
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * Returns the submitted password
     *
     * @return string
     */
    public function getPassword()
    {
        return $this->password;
    }

    /**
     * Returns the Password Generator
     *
     * @return Generator
     */
    public function getGenerator()
    {
        return $this->generator;
    }

    /**
     * Defines the Password Generator
     *
     * @param Generator $generator The Password Generator
     *
     * @return PasswordAdapter
     */
    public function setGenerator(Generator $generator)
    {
        $this->generator = $generator;

        return $this;
    }

    /**
     * Returns the User Provider
     *
     * @return Provider
     */
    public function getProvider()
    {
        return $this->provider;
    }

    /**
     * Defines the User Provider
     *
     * @param Provider $provider The User Provider
     *
     * @return PasswordAdapter
     */
    public function setProvider(Provider $provider)
    {
        $this->provider = $provider;

        return $this;
    }

    /**
     * Returns the password Property of the User object used to retrieve the
     * crypted password for comparision
     *
     * @return string
     */
    public function getPasswordProperty()
    {
        return $this->passwordProperty;
    }

    /**
     * Defines the Password property of the User object where is stored the
     * crypted password
     *
     * @param string $passwordProperty Property of the User object
     *
     * @return PasswordAdapter
     */
    public function setPasswordProperty($passwordProperty)
    {
        $this->passwordProperty = $passwordProperty;

        return $this;
    }
}