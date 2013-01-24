<?php
namespace Fwk\Security\Authentication\Adapters;

use Zend\Authentication\Adapter\AdapterInterface;
use Fwk\Security\Authentication\Adapter;
use Fwk\Security\Authentication\Result;

/**
 * Wrapper for Zend Authentication Adapters
 */
class ZendAdapter implements Adapter
{
    /**
     * Zend Authentication Adapter
     * 
     * @var AdapterInterface
     */
    protected $zendAdapter;
    
    /**
     * Constructor
     * 
     * @param AdapterInterface $zendAdapter Zend Authentication Adapter
     * 
     * @return void
     */
    public function __construct(AdapterInterface $zendAdapter)
    {
        $this->zendAdapter = $zendAdapter;
    }
    
    public function authenticate()
    {
        
    }
    
    /**
     * Returns the Zend Adapter
     * 
     * @return AdapterInterface
     */
    public function getZendAdapter()
    {
        return $this->zendAdapter;
    }

    /**
     * Defines the Zend Adapter
     * 
     * @param AdapterInterface $zendAdapter 
     * 
     * @return ZendAdapter
     */
    public function setZendAdapter(AdapterInterface $zendAdapter)
    {
        $this->zendAdapter = $zendAdapter;
        
        return $this;
    }
}