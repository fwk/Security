<?php
namespace Fwk\Security;



use Fwk\Events\Event;

class SecurityEvent extends Event
{
    /**
     * @var Service
     */
    protected $service;

    /**
     * @param string  $event
     * @param Service $securityService
     * @param array   $data
     *
     * @return SecurityEvent
     */
    public static function factory($event, Service $securityService,
        array $data = array()
    ) {
        $instance = new self($event, $data);
        $instance->setService($securityService);

        return $instance;
    }

    /**
     * Returns the Security Service
     *
     * @return Service
     */
    public function getService()
    {
        return $this->service;
    }

    /**
     * Defines the Security Service
     *
     * @param Service $service
     *
     * @return SecurityEvent
     */
    public function setService(Service $service)
    {
        $this->service = $service;

        return $this;
    }
}