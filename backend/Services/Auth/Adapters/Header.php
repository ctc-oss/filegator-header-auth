<?php

/*
 * This is a custom auth handler that will receive headers for the username and fullname
 * If the headers are missing, the user will be presented with the login
 * If the headers are present, login will be done automatically, and the user will be added to the system
 */
namespace Filegator\Services\Auth\Adapters;

use Filegator\Services\Auth\Adapters\JsonFile;
use Filegator\Services\Auth\User;
use Filegator\Services\Logger\LoggerInterface;
use Filegator\Services\Session\SessionStorageInterface as Session;

class Header extends JsonFile
{
    protected $username_header_key;
    protected $fullname_header_key;
    protected $non_header_users;
    protected $user_defaults;
    protected $cookie_key;

    public function __construct(Session $session, LoggerInterface $logger)
    {
        parent::__construct($session);
        $this->logger = $logger;
    }

    public function init(array $config = [])
    {
        parent::init($config);
        $this->username_header_key = $config["username_header_key"];
        $this->fullname_header_key = $config["fullname_header_key"];
        $this->cookie_key = $config["cookie_key"] ?? "Cookie";
        $this->ignore_users = $config["ignore_users"] ?? [];
        $this->user_defaults = $config["user_defaults"] ?? [];
    }

    private function useNormalAuth($username): bool
    {
        return in_array($username, $this->ignore_users);
    }

    private function cookieHeaders($headers) {
        $all_headers = $headers;
        if (!array_key_exists(strtolower($this->cookie_key), $all_headers)) {
            return [];
        }

        $headers_from_cookie = explode('; ', $all_headers["cookie"]);
        $headers = [];

        foreach ($headers_from_cookie as $cookie) {
            list($key, $value) = explode('=', $cookie, 2);
            $headers[$key] = $value;
        }

        return $headers;
    }

    private function headerUser(): array
    {
        $headers = array_change_key_case(getallheaders(), CASE_LOWER);
        $cookie_headers = array_change_key_case($this->cookieHeaders($headers), CASE_LOWER);
        $username_header_key = strtolower($this->username_header_key);
        $fullname_header_key = strtolower($this->fullname_header_key);
        // $this->logger->log("HEADERS:");
        // $this->logger->log(json_encode($headers));
        // $this->logger->log("COOKIEHEADERS:");
        // $this->logger->log(json_encode($cookie_headers));
        $header_username_exists = (array_key_exists($username_header_key, $headers) or array_key_exists($username_header_key, $cookie_headers));
        $header_fullname_exists = (array_key_exists($fullname_header_key, $headers) or array_key_exists($fullname_header_key, $cookie_headers));

        if (!$header_username_exists) {
            $this->logger->log($this->username_header_key." username header is not set");
        }
        if (!$header_fullname_exists) {
            $this->logger->log($this->fullname_header_key." full name header is not set");
        }
        if (!$header_username_exists || !$header_fullname_exists) return null;

        $username_header = $headers[$username_header_key] ?? $cookie_headers[$username_header_key];
        $fullname_header = $headers[$fullname_header_key] ?? $cookie_headers[$fullname_header_key];

        if(!isset($username_header) || empty($username_header)) return null;
        if(!isset($fullname_header) || empty($fullname_header)) return null;

        return [
            "username" => $username_header,
            "name" => $fullname_header,
            "role" => $this->user_defaults["role"] ?? "user",
            "homedir" => $this->user_defaults["homedir"] ?? "/share",
            "permissions" => $this->user_defaults["permissions"] ?? "read",
        ];
    }

    private function userHash($user): string
    {
        return $user->getHomedir().$user->getRole().$user->getUsername();
    }

    public function authenticate($username, $password): bool
    {
        if ($this->useNormalAuth($username)) {
            $this->logger->log("** ".$username." user is configured to use normal authentication, skipping header auth");
            return parent::authenticate($username, $password);
        }

        $header_user = $this->headerUser();
        if (!isset($header_user)) return false;

        // $this->logger->log("HEADERUSER:");
        // $this->logger->log(json_encode($header_user));

        $existing_user = $this->find($header_user["username"]);
        // $this->logger->log("EXISTINGUSER:");
        // $this->logger->log(json_encode($existing_user));
        if (!isset($existing_user)) {
            // $this->logger->log("CREATENEWUSER");
            $new_user = $this->mapToUserObject($header_user);
            $existing_user = $this->add($new_user, ""); // Password isn't used
        }

        // $this->logger->log("EXISTINGUSER2:");
        // $this->logger->log(json_encode($existing_user));
        $this->store($existing_user);
        $this->session->set(self::SESSION_HASH, $this->userHash($existing_user));
        return true;
    }

    protected function sessionUser() {
        return $this->session->get(self::SESSION_KEY, null);
    }

    public function user(): ?User
    {
        // $this->logger->log("USER:1");
        if (! $this->session) return null;
        // $this->logger->log("USER:2");

        $session_user = $this->sessionUser();
        // $this->logger->log("USER:3");
        if ($session_user) {
            // $this->logger->log("USER:4");
            $hash = $this->session->get(self::SESSION_HASH, null);
            return ($hash == $this->userHash($session_user)) ? $session_user : null;
        }

        // $this->logger->log("USER:5");
        $header_user = $this->headerUser();
        if ($header_user) {
            // $this->logger->log("USER:6");
            $header_username = $header_user["username"];
            $authenticated = $this->authenticate($header_username, "");
            // $this->logger->log("USER:7");
            if ($authenticated) {
                $authenticated_user = $this->sessionUser();
                // $this->logger->log("USER:8");
                $this->logger->log("Authenticated user [".$authenticated_user->getUsername()."] with F5 header");
                return $authenticated_user;
            }
        }

        $this->logger->log("USER:7");
        return null;

        // if ($this->useNormalAuth($user->getUsername())) return parent::user();
        // $this->logger->log("USER:3");
        // if (! $user) return null;
        // $this->logger->log("USER:4");

        // if ($this->useNormalAuth($user->getUsername())) return parent::user();
        // $this->logger->log("USER:5");

        // $existing_user = $this->find($user->getUsername());
        // $this->logger->log("USER:6");
        // if (! $existing_user) return null;
        // $this->logger->log("USER:7");

        // $hash = $this->session->get(self::SESSION_HASH, null);
        // $this->logger->log("USER:8");
        // return ($hash == $this->userHash($existing_user)) ? $user : null;
    }
}
