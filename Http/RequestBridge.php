<?php
namespace Fwk\Security\Http;

use Symfony\Component\HttpFoundation\Request as HttpFoundationRequest;
use Symfony\Component\HttpFoundation\Response as HttpFoundationResponse;
use Zend\Http\Request as ZendRequest;
use Zend\Http\Response as ZendResponse;

final class RequestBridge
{
    /**
     * Transforms an HttpFoundation Request object into a Zend\Http\Request one.
     * 
     * @param HttpFoundationRequest $request HttpFoundation Request
     * 
     * @return ZendRequest 
     */
    public static function toZendRequest(HttpFoundationRequest $request = null)
    {
        if (null === $request) {
            $requestStr = HttpFoundationRequest::createFromGlobals()->__toString();
        } else {
            $requestStr = $request->__toString();
        }
        
        $requestStr = preg_replace('/\:(\s{2,}+)/', ': ', $requestStr);

        return ZendRequest::fromString($requestStr);
    }
    
    /**
     * Factory helper for Zend\Http\Response
     * 
     * @return ZendResponse 
     */
    public static function zendResponseFactory()
    {
        return new ZendResponse();
    }
    
    /**
     * Transforms a Zend\Http\Response into an HttpFoundation one.
     * 
     * @param ZendResponse $zresponse The Zend\Http\Response
     * 
     * @return HttpFoundationResponse
     */
    public static function toHttpFoundationResponse(ZendResponse $zresponse) 
    {
        return HttpFoundationResponse::create(
            $zresponse->getContent(), 
            $zresponse->getStatusCode(), 
            $zresponse->getHeaders()->toArray()
        );
    }
    
    /**
     * Immediately send headers from a Zend\Http\Response
     * 
     * @param ZendResponse $zresponse Zend\Http\Response
     * 
     * @return void
     */
    public static function sendHeaders(ZendResponse $zresponse)
    {
        $headers    = $zresponse->getHeaders()->toArray();
        foreach ($headers as $key => $value) {
            header(sprintf('%s: %s', $key, $value));
        }
    }
}