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

    private function trimQuotes($value): string
    {
        if (! isset($value)) return $value;
        return trim($value, '\'"');
    }

    private function headerUser(): ?array
    {
        $headers = array_change_key_case(getallheaders(), CASE_LOWER);
        $cookie_headers = array_change_key_case($this->cookieHeaders($headers), CASE_LOWER);
        $username_header_key = strtolower($this->username_header_key);
        $fullname_header_key = strtolower($this->fullname_header_key);
        $header_username_exists = (array_key_exists($username_header_key, $headers) or array_key_exists($username_header_key, $cookie_headers));
        $header_fullname_exists = (array_key_exists($fullname_header_key, $headers) or array_key_exists($fullname_header_key, $cookie_headers));

        if (!$header_username_exists) {
            $this->logger->log($this->username_header_key." username header is not set");
            return null;
        }
        if (!$header_fullname_exists) {
            $this->logger->log($this->fullname_header_key." full name header is not set, falling back to username header");
        }

        $username_header = $headers[$username_header_key] ?? $cookie_headers[$username_header_key];
        $fullname_header = $headers[$fullname_header_key] ?? $cookie_headers[$fullname_header_key] ?? $username_header;

        if(!isset($username_header) || empty($username_header)) return null;
        if(!isset($fullname_header) || empty($fullname_header)) return null;

        return [
            "username" => $this->trimQuotes($username_header),
            "name" => $this->trimQuotes($fullname_header),
            "role" => $this->user_defaults["role"] ?? "user",
            "homedir" => $this->user_defaults["homedir"] ?? "/share",
            "permissions" => $this->user_defaults["permissions"] ?? "read",
        ];
    }

    private function userHash($user): string
    {
        return $user->getHomedir().$user->getRole().$user->getUsername();
    }

    private function setSessionHash($user) {
        $this->session->set(self::SESSION_HASH, $this->userHash($user));
    }

    public function authenticate($username, $password): bool
    {
        if ($this->useNormalAuth($username)) {
            $this->logger->log("** [".$username."] user is configured to use normal authentication, skipping header auth");
            $authenticated = parent::authenticate($username, $password);
            if ($authenticated) {
                $authenticated_user = parent::user();
                if (isset($authenticated_user)) {
                    $this->setSessionHash($authenticated_user);
                }
            }
            return $authenticated;
        }

        $header_user = $this->headerUser();
        if (!isset($header_user)) return false;

        $existing_user = $this->find($header_user["username"]);
        if (!isset($existing_user)) {
            $new_user = $this->mapToUserObject($header_user);
            $existing_user = $this->add($new_user, ""); // Password isn't used
        }

        $this->store($existing_user);
        $this->setSessionHash($existing_user);
        return true;
    }

    protected function sessionUser() {
        return $this->session->get(self::SESSION_KEY, null);
    }

    public function user(): ?User
    {
        if (! $this->session) return null;

        $session_user = $this->sessionUser();
        if (isset($session_user)) {
            $hash = $this->session->get(self::SESSION_HASH, null);
            return ($hash == $this->userHash($session_user)) ? $session_user : null;
        }

        $header_user = $this->headerUser();
        if (isset($header_user)) {
            $header_username = $header_user["username"];
            $authenticated = $this->authenticate($header_username, "");
            if ($authenticated) {
                $authenticated_user = $this->sessionUser();
                $this->logger->log("Authenticated user [".$authenticated_user->getUsername()."] with ".$this->username_header_key." header");
                return $authenticated_user;
            }
        }

        return null;
    }
}
