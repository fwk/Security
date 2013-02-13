<?php
namespace Fwk\Security\Http;

use Fwk\Security\SecurityEvent;
use Zend\Authentication\Adapter\Http;
use Zend\Http\Response;

class HttpAuthListener
{
    protected $response;

    public function onBeforeAuthentication(SecurityEvent $event)
    {
        $service    = $event->getService();
        $adapter    = $service->getAuthenticationManager()->getAdapter();

        if (!$adapter instanceof Http) {
            return;
        }

        $request            = $event->request;
        $adapterRequest     = $adapter->getRequest();
        $adapterResponse    = $this->response = $adapter->getResponse();

        if ($adapterRequest === null) {
            $adapter->setRequest(RequestBridge::toZendRequest($request));
        }

        if ($adapterResponse === null) {
            $adapter->setResponse(
                $this->response = RequestBridge::zendResponseFactory()
            );
        }
    }

    public function onAfterAuthentication(SecurityEvent $event)
    {
        $service    = $event->getService();
        $adapter    = $service->getAuthenticationManager()->getAdapter();

        if (!$adapter instanceof Http || !$this->response instanceof Response) {
            return;
        }

        RequestBridge::sendHeaders($this->response);
    }
}