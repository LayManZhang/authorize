<?php

namespace app\controller;

use think\facade\{Session, View, Db, Request};
use app\model\User;

class Index
{
    //登录
    private $assistant;

    public function login()
    {
        $username = Request::param('username');
        $password = Request::param('password');
        if ('' != $username || '' != Session::get('user')) {
            if ('' != Session::get('user')) {
                $this->redirect('index');
            } else {
                $user = User::where('username',$username)->find();
                if (password_verify($password, $user->password_hash)){
                    $this->assistant = new \mylib\Assistant();
                    $time = date('Y-m-d H:i:s');
                    Session::set('id', $user->id);
                    Session::set('user', $user->name);
                    Session::set('username', $user->username);
                    Session::set('tel', $user->tel);
                    $data = ['userid' => $user->username, 'operation' => 'login', 'create_time' => $time];
                    Db::name('log')->insert($data);
                    $intensity = $this->assistant->checkPassword(input('password'));
                    if (0 == $intensity['code']) {
                        Session::set('intensity', 0);

                        $result = ['code' => 0, 'data' => $_SERVER['HTTP_REFERER'], 'msg' => '登录成功，正在跳转...'];
                    } else {
                        Session::set('intensity', 1);

                        $result = ['code' => 0, 'data' => '/authorize/personal', 'msg' => '密码强度不足，即将跳转到密码修改页...'];
                    }
                }else{
                    $result = ['code' => -1, 'data' => '', 'msg' => '账号或密码错误,请重试'];
                }
                return json($result);
            }
        } else {
            return View::fetch('/login');
        }
    }

    //首页
    public function index()
    {
        if ('' != Session::get('id')) {
            return View::fetch('/header/index');
        } else {
            return View::fetch('/login');
        }
    }

    //注销登录
    public function logOut()
    {
        $time = date('Y-m-d H:i:s');
        $username = Session::get('username');
        if ('' != $username) {
            $data = ['userid' => $username, 'operation' => 'logout', 'create_time' => $time];
            Db::name('log')->insert($data);
        }
        Session::clear();

        return json(['code' => 0, 'msg' => '您已安全退出', 'data' => '']);
    }
}
