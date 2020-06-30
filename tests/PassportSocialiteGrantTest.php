<?php

namespace Braumye\PassportSocialite\Tests;

use Braumye\PassportSocialite\PassportSocialiteServiceProvider;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Laravel\Passport\Client;
use Laravel\Passport\Http\Controllers\AccessTokenController;
use Laravel\Passport\Passport;
use Laravel\Passport\PassportServiceProvider;
use Laravel\Passport\TokenRepository;
use Lcobucci\JWT\Parser;
use League\OAuth2\Server\AuthorizationServer;
use Mockery as m;
use Orchestra\Testbench\TestCase;
use Psr\Http\Message\ServerRequestInterface;

class PassportSocialiteGrantTest extends TestCase
{
    use RefreshDatabase;

    const KEYS = __DIR__.'/keys';
    const PUBLIC_KEY = self::KEYS.'/oauth-public.key';
    const PRIVATE_KEY = self::KEYS.'/oauth-private.key';

    protected function setUp(): void
    {
        parent::setUp();

        $this->withFactories(__DIR__.'/../vendor/laravel/passport/database/factories');
        $this->loadMigrationsFrom(__DIR__.'/../vendor/laravel/passport/database/migrations');

        @unlink(self::PUBLIC_KEY);
        @unlink(self::PRIVATE_KEY);

        $this->artisan('passport:keys');
    }

    protected function tearDown(): void
    {
        m::close();

        parent::tearDown();
    }

    /** @test */
    public function it_can_resolve_a_user_by_passport_socialite_grant()
    {
        $server = $this->app->make(AuthorizationServer::class);
        $request = m::mock(ServerRequestInterface::class);
        $tokens = m::mock(TokenRepository::class);
        $jwt = m::mock(Parser::class);

        $request->shouldReceive('getParsedBody')->andReturn([
            'grant_type' => 'socialite',
            'client_id' => 1,
            'client_secret' => 'client_secret',
            'provider' => 'test',
            'socialite_user_id' => 'foo',
        ]);

        $request->shouldReceive('hasHeader')->with('Authorization')->andReturn(null);

        \DB::table('oauth_clients')->insert([
            'secret' => 'client_secret',
            'name' => 'foo',
            'redirect' => 'http://localhost',
            'personal_access_client' => false,
            'password_client' => false,
            'revoked' => false,
        ]);

        $controller = new AccessTokenController($server, $tokens, $jwt);
        $response = $controller->issueToken($request);
        $content = json_decode($response->getContent(), true);

        $this->assertArrayHasKey('access_token', (array) $content);
        $this->assertEquals('Bearer', $content['token_type']);
    }

    protected function getEnvironmentSetUp($app)
    {
        $config = $app->make(Repository::class);
        $config->set('auth.defaults.provider', 'users');
        $config->set('auth.providers.users.model', User::class);

        $app['config']->set('database.default', 'testbench');
        $app['config']->set('passport.storage.database.connection', 'testbench');
        $app['config']->set('database.connections.testbench', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);
    }

    protected function getPackageProviders($app)
    {
        return [
            PassportSocialiteServiceProvider::class,
            PassportServiceProvider::class,
        ];
    }
}

class User extends \Illuminate\Foundation\Auth\User
{
    protected $guarded = [];

    public function findForPassportSocialite(string $provider, string $id)
    {
        if ($provider === 'test' && $id === 'foo') {
            return $this;
        }

        return null;
    }

    public function getAuthIdentifier()
    {
        return 'bar';
    }
}
