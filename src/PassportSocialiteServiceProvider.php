<?php

namespace Braumye\PassportSocialite;

use Braumye\PassportSocialite\Bridge\PassportSocialiteGrant;
use Illuminate\Support\ServiceProvider;
use Laravel\Passport\Bridge\RefreshTokenRepository;
use Laravel\Passport\Passport;
use League\OAuth2\Server\AuthorizationServer;

class PassportSocialiteServiceProvider extends ServiceProvider
{
    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $this->app->afterResolving(AuthorizationServer::class, function ($server) {
            $server->enableGrantType(
                $this->makePassportSocialiteGrant(), Passport::tokensExpireIn()
            );
        });
    }

    /**
     * Create and configure an instance of the Passport Socialite grant.
     *
     * @return \Braumye\PassportSocialite\Bridge\PassportSocialiteGrant
     */
    protected function makePassportSocialiteGrant()
    {
        return tap($this->buildPassportSocialiteGrant(), function ($grant) {
            $grant->setRefreshTokenTTL(Passport::refreshTokensExpireIn());
        });
    }

    /**
     * Build the Passport Socialite grant instance.
     *
     * @return \Braumye\PassportSocialite\Bridge\PassportSocialiteGrant
     */
    protected function buildPassportSocialiteGrant()
    {
        return new PassportSocialiteGrant(
            $this->app->make(Bridge\UserRepository::class),
            $this->app->make(RefreshTokenRepository::class)
        );
    }
}
