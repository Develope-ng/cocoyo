<?php

namespace App\Listeners\Auth;

use Illuminate\Support\Facades\DB;
use Laravel\Passport\Events\RefreshTokenCreated;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Contracts\Queue\ShouldQueue;

class PruneOldTokens
{
    /**
     * Handle the event.
     *
     * @param  RefreshTokenCreated  $event
     * @return void
     */
    public function handle(RefreshTokenCreated $event)
    {
        DB::table('oauth_refresh_tokens')
            ->where('access_token_id', '!=', $event->accessTokenId)
            ->where('revoked', true)
            ->delete();
    }
}
