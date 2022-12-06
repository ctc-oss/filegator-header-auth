<?php

/*
 * This file is part of the FileGator package.
 *
 * (c) Adriano Hänggli <https://github.com/ahaenggli>
 *
 */

namespace Filegator\Services\Auth\Adapters;

use Filegator\Services\Auth\Adapters\JsonFile;
use Filegator\Services\Auth\AuthInterface;
use Filegator\Services\Auth\User;
use Filegator\Services\Auth\UsersCollection;
use Filegator\Services\Service;
use Filegator\Services\Session\SessionStorageInterface as Session;

/**
 * @codeCoverageIgnore
 */
class Header extends JsonFile
{
    protected $session;
    protected $username_header_key;
    protected $fullname_header_key;
    protected $email_header_key;
    
    public function __construct(Session $session)
    {
        $this->session = $session;
    }

    public function init(array $config = [])
    {
        parent::init($config);
        $this->username_header_key = strtolower($config['username_header_key']);
        $this->fullname_header_key = strtolower($config['fullname_header_key']);
        $this->email_header_key = strtolower($config['email_header_key']);
    }

    public function authenticate($username, $password): bool
    {
        $headers = array_change_key_case(getallheaders(), CASE_LOWER);

        $username_header = $headers[$this->username_header_key];
        $fullname_header = $headers[$this->fullname_header_key];

        if(!isset($username_header) || empty($username_header)) return false;
        if(!isset($fullname_header) || empty($fullname_header)) return false;

        $existing_user = $this->find($username_header);
        if (isset($existing_user)) return true;

        $new_user = new User();
        $user->setUsername($username_header);
        $user->setName($fullname_header);
        $existing_user = $this->add($user, ""); // Password isn't used
        $this->store($existing_user);
        // $this->session->set(self::SESSION_HASH, $existing_user['password'].$u['permissions'].$u['homedir'].$u['role']);
        
        return true;
    }

    protected function mapToUserObject(array $user): User
    {
        $new = new User();

        $new->setUsername($user['username']);
        $new->setName($user['name']);

        return $new;
    }
}