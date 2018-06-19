<?php

namespace App\Http\Controllers\Auth;

use App\Http\Requests\SocialAuthorizationRequest;
use App\Http\Requests\WeappAuthorizationRequest;
use App\Http\Resources\UserResource;
use App\Models\User;
use App\Notifications\UserRegisterVerficationCode;
use App\Traits\PassportToken;
use GuzzleHttp\Client;
use function GuzzleHttp\Psr7\uri_for;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use \Auth;
use Illuminate\Support\Facades\Storage;
use Laravel\Socialite\Facades\Socialite;

class AuthorizationsController extends Controller
{
    use PassportToken;

    /**
     * 重定向到第三方登陆
     *
     * @param $driver
     * @return mixed
     */
    public function redirectToProvider($driver)
    {
        if (!in_array($driver, ['qq', 'weibo'])) {
            abort(404);
        }

        return Socialite::driver($driver)->redirect();
    }

    /**
     * 第三方登录回调
     *
     * @param $type
     * @param SocialAuthorizationRequest $request
     * @return \App\Traits\json|mixed
     */
    public function socialStore($type, SocialAuthorizationRequest $request)
    {
        if (! in_array($type, ['qq', 'weibo'])) {
            return $this->failed();
        }

        $driver = Socialite::driver($type);

        try {
            if ($code = $request->input('code')) {
                $response = $driver->getAccessTokenResponse($request->input('code'));
                $token = array_get($response, 'access_token');
            } else {
                $token = $request->input('access_token');
            }
            $oauthUser = $driver->userFromToken($token);
        } catch (\Exception $exception) {

            return $this->errorUnauthorized('参数错误，未获取用户信息');
        }

        $socialMapping = $type == 'qq' ? 'qq_id' : 'weibo_id';

        $user = User::where($socialMapping, $oauthUser->getId())->first();

        return $this->handleResponse($user, $oauthUser, $socialMapping);
    }

    /**
     * 小程序绑定登录
     *
     * @param WeappAuthorizationRequest $request
     * @return \App\Traits\json|mixed
     */
    public function weappStore(WeappAuthorizationRequest $request)
    {
        $code = $request->input('code');

        // 根据 code 获得微信 openid 和 session_key
        $miniProgram = \EasyWeChat::miniProgram();
        $data = $miniProgram->auth->session($code);

        // 获取错误 说明 code 已过期或正确  返回401
        if (isset($data['errcode'])) {
            return $this->errorUnauthorized('用户不存在');
        }

        // 找到 openid 对应的用户
        $user = User::where('weapp_openid', $data['openid'])->first();

        $attributes['weixin_session_key'] = $data['session_key'];

        // 未找到对应用户则需要提交用户名密码进行用户绑定
        if (! $user) {
            // 如果未提交用户名密码, 403 错误提示
            if (! $credentials['email'] = $request->input('email')) {
                return $this->notAccess('用户不存在');
            }

            $credentials['password'] = $request->input('password');

            // 验证用户名和密码是否正确
            if (! Auth::attempt($credentials)) {
                return $this->errorUnauthorized('用户名或密码错误');
            }

            // 获取对应的用户
            $user = User::where('email', $request->input('email'))->first();
            $attributes['weapp_openid'] = $data['openid'];
        }

        // 更新用户信息
        $user->update($attributes);

        return $this->respond([
            'token' => $this->getBearerTokenByUser($user, 1, false)
        ]);
    }

    /**
     * 处理响应
     *
     * @param $user
     * @param $oauthUser
     * @param $socialMapping
     * @return mixed
     */
    protected function handleResponse($user, $oauthUser, $socialMapping)
    {
        if (! $user) {
            // 创建目录 拉取远程头像
            $path = 'qq/' . date('Y') . date('m') . '/' . date('d');
            $filename = str_random();
            $suffix = '.jpeg';
            Storage::disk(config('filesystems.default'))->makeDirectory($path);

            // 拉取远程头像
            $client = new Client(['verify' => false]);

            $client->get($oauthUser->getAvatar(), ['save_to' => storage_path('app/public/' . $path . '/' . $filename . $suffix)]);

            return $this->respond([
                'data' => [
                    'code' => 1001,
                    'social_user' => [ //未注册
                        $socialMapping => $oauthUser->getId(),
                        'name' => $oauthUser->getNickname(),
                        'avatar' => '/storage/' . $path . '/' . $filename . $suffix
                    ]
                ]
            ]);
        }

        if (! $user->status) {
            //发送验证码
            $user->notify(new UserRegisterVerficationCode($user));

            return $this->respond([
                'data' => [
                    'code' => 1002, //未验证邮箱
                    'user' => new UserResource($user)
                ]
            ]);
        }

        return $this->respond([
            'data' => [
                'code' => 1003, //授权成功
                'user' => new UserResource($user),
                'token' => $this->getBearerTokenByUser($user, 1, false)
            ]
        ]);
    }
}
