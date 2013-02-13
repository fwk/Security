<?php
namespace Fwk\Security;

interface User
{
    public function getIdentifier();
    
    public function getUsername();
}
