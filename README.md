FileGator Header Auth Plugin
============================

Auth extension to the JsonFile Auth

This code will allow you to authenticate via HTTP headers instead of a username/password.
It also has the ability to be configured to allow some users to authenticate via username/password,
such as an admin user.

Setup Instructions
------------------

Copy the `backend/Services/Auth/Adapters/Header.php` to the `$FILEGATOR_HOME`.  There
should be other files in that folder, including `JsonFile.php`, which `Header.php` extends.

You will also need to modify the `$FILEGATOR_HOME/configuration.php` file to point to the
`Header.php` to facilitate the authentication:

- Locate the `Filegator\Services\Auth\AuthInterface` section
- Change the contents to the following:

```php
      'Filegator\Services\Auth\AuthInterface' => [
        'handler' => '\Filegator\Services\Auth\Adapters\Header',
        'config' => [
            'file' => __DIR__.'/private/users.json',
            'username_header_key' => 'FILEGATOR-USERNAME',
            'fullname_header_key' => 'FILEGATOR-FULLNAME',
            'ignore_users' => ['admin'],
        ],
      ],
```

Properties
----------

| Property            | Description          |
|---------------------|----------------------|
|`file`               |Leave this as is, this is the same property that the `JsonFile` auth uses|
|`username_header_key`|HTTP Header Key that will contain the username value|
|`fullname_header_key`|HTTP Header Key that will contain the full name value|
|`ignore_users`       |Array of usernames that should not use the header auth, but fallback to the JsonFile auth|
