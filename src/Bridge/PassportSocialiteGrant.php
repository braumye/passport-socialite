<?php

namespace Braumye\PassportSocialite\Bridge;

use Braumye\PassportSocialite\Bridge\UserRepositoryInterface;
use DateInterval;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;

class PassportSocialiteGrant extends AbstractGrant
{
    /**
     * @param  \Braumye\PassportSocialite\Bridge\UserRepositoryInterface  $userRepository
     * @param  \League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface  $refreshTokenRepository
     */
    public function __construct(
        UserRepositoryInterface $userRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository
    ) {
        $this->userRepository = $userRepository;
        $this->setRefreshTokenRepository($refreshTokenRepository);

        $this->refreshTokenTTL = new DateInterval('P1M');
    }

    /**
     * {@inheritdoc}
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL
    ) {
        // Validate request
        $client = $this->validateClient($request);
        $scopes = $this->validateScopes($this->getRequestParameter('scope', $request, $this->defaultScope));
        $user = $this->validateUser($request, $client);

        // Finalize the requested scopes
        $finalizedScopes = $this->scopeRepository->finalizeScopes($scopes, $this->getIdentifier(), $client, $user->getIdentifier());

        // Issue and persist new access token
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $user->getIdentifier(), $finalizedScopes);
        $this->getEmitter()->emit(new RequestEvent(RequestEvent::ACCESS_TOKEN_ISSUED, $request));
        $responseType->setAccessToken($accessToken);

        // Issue and persist new refresh token if given
        $refreshToken = $this->issueRefreshToken($accessToken);

        if ($refreshToken !== null) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::REFRESH_TOKEN_ISSUED, $request));
            $responseType->setRefreshToken($refreshToken);
        }

        return $responseType;
    }

    /**
     * @param  \Psr\Http\Message\ServerRequestInterface  $request
     * @param  \League\OAuth2\Server\Entities\ClientEntityInterface. $client
     * @return \League\OAuth2\Server\Entities\UserEntityInterface
     */
    protected function validateUser(ServerRequestInterface $request, ClientEntityInterface $client)
    {
        $provider = $this->getRequestParameter('provider', $request);

        if (is_null($provider)) {
            throw OAuthServerException::invalidRequest('provider');
        }

        $id = $this->getRequestParameter('socialite_user_id', $request);

        if (is_null($id)) {
            throw OAuthServerException::invalidRequest('socialite_user_id');
        }

        $user = $this->userRepository->getUserEntity($provider, $id, $client);

        if ($user instanceof UserEntityInterface === false) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::USER_AUTHENTICATION_FAILED, $request));

            throw OAuthServerException::invalidGrant();
        }

        return $user;
    }

    /**
     * {@inheritdoc}
     */
    public function getIdentifier()
    {
        return 'socialite';
    }
}
