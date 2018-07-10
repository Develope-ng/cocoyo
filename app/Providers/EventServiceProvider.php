<?php

namespace App\Providers;

use Illuminate\Support\Facades\Event;
use Illuminate\Foundation\Support\Providers\EventServiceProvider as ServiceProvider;

class EventServiceProvider extends ServiceProvider
{
    /**
     * The event listener mappings for the application.
     *
     * @var array
     */
    protected $listen = [
        \SocialiteProviders\Manager\SocialiteWasCalled::class => [
            'SocialiteProviders\\QQ\\QqExtendSocialite@handle',
            'SocialiteProviders\\Weibo\\WeiboExtendSocialite@handle',
        ],
        'Laravel\Passport\Events\AccessTokenCreated' => [
            'App\Listeners\Auth\RevokeOldTokens'
        ],
        'Laravel\Passport\Events\RefreshTokenCreated' => [
            'App\Listeners\Auth\PruneOldTokens',
        ]
    ];

    /**
     * Register any events for your application.
     *
     * @return void
     */
    public function boot()
    {
        parent::boot();

        //
    }
}
