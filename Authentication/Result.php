<?php
namespace Fwk\Security\Authentication;

use Zend\Authentication\Result as ResultBase;

/**
 * Wrapper for Zend Authentication Result
 */
class Result extends ResultBase
{
    /**
     *
     * @param ResultBase $zendResult
     * @return Result
     */
    public static function factory(ResultBase $zendResult)
    {
        $class = new self($zendResult->getCode(), $zendResult->getIdentity(), $zendResult->getMessages());

        return $class;
    }
}