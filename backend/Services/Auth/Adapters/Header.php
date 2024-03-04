<?php

/*
 * This is a custom auth handler that will receive headers for the username and fullname
 * If the headers are missing, login will fail.
 * If the headers are present, login will succeed, and user will be added.
 */
namespace Filegator\Services\Auth\Adapters;

use Filegator\Services\Auth\Adapters\JsonFile;
use Filegator\Services\Auth\User;
use Filegator\Services\Logger\LoggerInterface;

class Header extends JsonFile
{
    protected $username_header_key;
    protected $fullname_header_key;
    protected $non_header_users;
    protected $user_defaults;

    public function __construct(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }

    public function init(array $config = [])
    {
        parent::init($config);
        $this->logger->log("INIT THE HEADER AUTH: ".$config["username_header_key"]);
        $this->username_header_key = strtolower($config["username_header_key"]);
        $this->fullname_header_key = strtolower($config["fullname_header_key"]);
        $this->ignore_users = $config["ignore_users"] ?? [];
        $this->user_defaults = $config["user_defaults"] ?? [];

    }

    private function useNormalAuth($username): bool
    {
        return in_array($username, $this->ignore_users);
    }

    private function headerUser(): array
    {
        $headers = array_change_key_case(getallheaders(), CASE_LOWER);
        $header_username_exists = array_key_exists($this->username_header_key, $headers);
        $header_fullname_exists = array_key_exists($this->fullname_header_key, $headers);

        if (!$header_username_exists) {
            error_log(print_r($this->username_header_key." header is not set", true));
        }
        if (!$header_fullname_exists) {
            error_log(print_r($this->fullname_header_key." header is not set", true));
        }
        if (!$header_username_exists || !$header_fullname_exists) return null;

        $username_header = $headers[$this->username_header_key];
        $fullname_header = $headers[$this->fullname_header_key];

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
            error_log(print_r("** ".$username." user is configured to use normal authentication, skipping header auth", true));
            return parent::authenticate($username, $password);
        }

        $header_user = $this->headerUser();
        if (!isset($header_user)) return false;

        $existing_user = $this->find($header_user["username"]);
        if (!isset($existing_user)) {
            $new_user = $this->mapToUserObject($header_user);
            $existing_user = $this->add($new_user, ""); // Password isn't used
        }

        $this->store($existing_user);
        $this->session->set(self::SESSION_HASH, $this->userHash($existing_user));
        return true;
    }

    public function user(): ?User
    {
        if (! $this->session) return null;

        $user = $this->session->get(self::SESSION_KEY, null);
        if (! $user) return null;

        if ($this->useNormalAuth($user->getUsername())) return parent::user();

        $existing_user = $this->find($user->getUsername());
        if (! $existing_user) return null;

        $hash = $this->session->get(self::SESSION_HASH, null);
        return ($hash == $this->userHash($existing_user)) ? $user : null;
    }
}
