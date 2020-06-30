<?php

namespace Braumye\PassportSocialite\Bridge;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Repositories\RepositoryInterface;

interface UserRepositoryInterface extends RepositoryInterface
{
    /**
     * Get a user entity.
     *
     * @param  string  $provider
     * @param  string  $id
     * @param  \League\OAuth2\Server\Entities\ClientEntityInterface  $clientEntity
     * @return \League\OAuth2\Server\Entities\UserEntityInterface|null
     */
    public function getUserEntity(string $provider, string $id, ClientEntityInterface $clientEntity);
}
