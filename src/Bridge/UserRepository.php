<?php

namespace Braumye\PassportSocialite\Bridge;

use Laravel\Passport\Bridge\User;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use RuntimeException;

class UserRepository implements UserRepositoryInterface
{
    /**
     * Get a user entity.
     *
     * @param  string  $provider
     * @param  string  $id
     * @param  \League\OAuth2\Server\Entities\ClientEntityInterface  $clientEntity
     * @return \League\OAuth2\Server\Entities\UserEntityInterface|null
     */
    public function getUserEntity(string $provider, string $id, ClientEntityInterface $clientEntity)
    {
        $userProvider = $clientEntity->provider ?? config('auth.guards.api.provider');

        if (is_null($model = config('auth.providers.'.$userProvider.'.model'))) {
            throw new RuntimeException('Unable to determine authentication model from configuration.');
        }

        if (method_exists($model, 'findForPassportSocialite') === false) {
            return;
        }

        $user = (new $model)->findForPassportSocialite($provider, $id);

        if (! $user) {
            return;
        }

        return new User($user->getAuthIdentifier());
    }
}
