<?php

namespace app\controller;

use think\facade\{Session, Request, View};
use app\model\{AuthGroup, AuthRule, User, AuthGroupAccess};
use think\auth\Auth;

class Authorize
{
    private $assistant;
    private $auth;

    //检查是否登录
    public function __construct()
    {
        if ('' == Session::get('id')) {
            echo View::fetch('/login');
            exit;
        } else {
            $this->auth = Auth::instance();
        }
    }

    //用户管理
    public function User()
    {
        if ($this->auth->check('user_list', Session::get('id'))) {
            return View::fetch('/authorize/user');
        }
    }

    //个人信息
    public function personal()
    {
        return View::fetch('/authorize/personal');
    }

    //添加用户
    public function addUser()
    {
        if ($this->auth->check('user_list', Session::get('id'))) {
            return View::fetch('/authorize/add_user');
        }
    }

    //角色管理
    public function group()
    {
        if ($this->auth->check('group_list', Session::get('id'))) {
            return View::fetch('/authorize/group');
        }
    }

    //菜单（规则）管理
    public function rules()
    {
        if ($this->auth->check('menu_list', Session::get('id'))) {
            return View::fetch('/authorize/rules');
        }
    }

    //修改个人信息
    public function updatePersonal()
    {
        $id = Request::param('id');
        $field = Request::param('field');
        $value = Request::param('value');
        $opassword = Request::param('opassword');
        $this->assistant = new \mylib\Assistant();
        //更改密码时验证旧密码
        if ('password_hash' == $field) {
            $intensity = $this->assistant->checkPassword($value);  //检查密码强度
            if (1 == $intensity['code']) {
                $result = $intensity;
            } else {
                $password_hash = password_hash($value, PASSWORD_ARGON2I);
                $user = User::where('id',$id)->find();
                if (password_verify($opassword, $user->password_hash)){
                    $user->$field = $password_hash;
                    if ($user->save()) {
                        Session::set('intensity', 0);
                        $result = ['code' => 0, 'data' => '/authorize/personal', 'msg' => '密码更新成功,即将刷新页面...'];
                    } else {
                        $result = ['code' => -2, 'data' => '', 'msg' => '密码更新失败'];
                    }
                }else{
                    $result = ['code' => -1, 'data' => '', 'msg' => '旧密码错误，请检查'];
                }
            }
        } else {
            $personalInfo = User::find($id);
            $personalInfo->$field = $value;

            $result = $personalInfo->save() ? '更新成功' : '更新失败';
        }

        return json($result);
    }

    //读取个人数据
    public function getPersonal()
    {
        $result = array();
        $result[] = User::find(Session::get('id'))->toArray();

        return json(['code' => 0, 'msg' => '', 'count' => 1, 'data' => $result]);
    }

    // 新增用户数据
    public function saveUser()
    {
        if ($this->auth->check('user_list', Session::get('id'))) {
            $username = input('username');
            $row = User::where('username', $username)->count();
            if ($row > 0) {
                return '添加失败，用户[ '.$username.' ]已存在';
            } else {
                $user = [
                  'name' => input('name'),
                  'username' => $username,
                  'password' => md5(input('password')),
                  'email' => input('email'),
                  'tel' => input('tel'),
                  'position' => input('position'),
                  'department' => input('department'),
                ];
                if ($result = User::create($user)) {
                    $access['group_id'] = input('group');
                    $access['uid'] = $result->id;
                    if ('' != $access['group_id']) {
                        AuthGroupAccess::create($access);
                    }

                    return '用户[ '.$result->name.' ]新增成功';
                } else {
                    return '新增出错';
                }
            }
        }
    }

    //读取所有用户数据
    public function getUsers()
    {
        if ($this->auth->check('user_list', Session::get('id'))) {
            $rows = input('limit') ?? 10;
            $page = input('page') ?? 1;
            $page -= 1;
            $offset = ($page) * $rows;
            $result = array();
            $result['code'] = 0;
            $result['msg'] = '';
            $result['count'] = User::where('name', 'like', '%'.input('name').'%')->where('tel', 'like', '%'.input('tel').'%')->count();
            $result_temp = User::field('id,name,username,email,tel,department,position,status,update_time,create_time')->where('name', 'like', '%'.input('name').'%')->where('tel', 'like', '%'.input('tel').'%')->limit($offset, $rows)->select()->toArray();
            $i = 0;
            foreach ($result_temp as $value) {
                $group_ids = AuthGroupAccess::where('uid', $value['id'])->select();
                $group_title = '';
                if ($group_ids) {
                    foreach ($group_ids as $group_id) {
                        $group_titles = AuthGroup::field('title')->where('id', $group_id['group_id'])->select()->toArray();
                        $group_title .= $group_titles[0]['title'].',';
                    }
                    $group_title = substr($group_title, 0, strlen($group_title) - 1);
                    $result_temp[$i]['group'] = $group_title;
                }
                ++$i;
            }
            $result['data'] = $result_temp;

            return json($result);
        }
    }

    //删除用户
    public function delUser()
    {
        $id = Request::param('id');
        if ($this->auth->check('user_list', Session::get('id'))) {
            if (1 == $id) {
                $info = ['code' => -1, 'msg' => '用户【系统管理员】禁止删除', 'data' => ''];
            } else {
                $user = User::find($id);
                if (null != $user) {
                    AuthGroupAccess::where('uid', $id)->delete(); //删除用户与角色关系
                    $user->delete();
                    $info = ['code' => 0, 'msg' => '删除成功', 'data' => ''];
                } else {
                    $info = ['code' => -2, 'msg' => '删除的用户不存在', 'data' => ''];
                }
            }

            return json($info);
        }
    }

    //修改用户数据
    public function updateUser()
    {
        $id = Request::param('id');
        $field = Request::param('field');
        $value = Request::param('value');
        if ($this->auth->check('user_list', Session::get('id'))) {
            if ('password_hash' == $field) {
                $value = password_hash($password, PASSWORD_ARGON2I);
            }
            if (1 == $id && 'status' == $field && 1 != $value) {
                return '系统管理员无法禁用';
            }
            $user = User::find($id);
            $user->$field = $value;

            return $user->save() ? '更新成功' : '更新失败';
        }
    }

    // 新增用户组数据
    public function saveGroup()
    {
        $title = Request::param('title');
        if ($this->auth->check('group_list', Session::get('id'))) {
            if ('' == $title) {
                $result = ['code' => -1, 'msg' => '请输入角色名'];
            } else {
                $group = array();
                $group['title'] = $title;
                $row = AuthGroup::where('title', $title)->count();
                if ($row > 0) {
                    $result = ['code' => -2, 'msg' => '添加失败，角色【'.$title.'】已存在'];
                } else {
                    if ($result = AuthGroup::create($group)) {
                        $result = ['code' => 0, 'msg' => '角色【'.$result->title.'】添加成功'];
                    } else {
                        $result = ['code' => -3, 'msg' => '角色【'.$title.'】添加出错'];
                    }
                }
            }

            return json($result);
        }
    }

    //读取用户组数据
    public function getGroup()
    {
        if ($this->auth->check('group_list', Session::get('id'))) {
            $rows = input('limit') ?? 10;
            $page = input('page') ?? 1;
            $page -= 1;
            $offset = ($page) * $rows;
            $result['code'] = 0;
            $result['msg'] = '';
            $result['count'] = AuthGroup::where('title', 'like', '%'.input('title').'%')->count();
            $result['data'] = AuthGroup::where('title', 'like', '%'.input('title').'%')->limit($offset, $rows)->select();

            return json($result);
        }
    }

    public function updateGroup()
    {
        $id = Request::param('id');
        $field = Request::param('field');
        $value = Request::param('value');
        if ($this->auth->check('group_list', Session::get('id'))) {
            $updateGroup = AuthGroup::find($id);
            $updateGroup->$field = $value;
            $result = $updateGroup->save();
            return $user->save() ? '更新成功' : '更新失败';
        }
    }

    public function delGroup()
    {
        $id = Request::param('id');
        if ($this->auth->check('group_list', Session::get('id'))) {
            if (1 == $id) {
                $result = ['code' => -1, 'msg' => '角色【系统管理员】禁止删除'];
            } else {
                $group = AuthGroup::find($id);
                if ($group) {
                    AuthGroupAccess::where('group_id', $id)->delete();  //删除角色与用户关系
                    $group->delete();
                    $result = ['code' => 0, 'msg' => '删除成功'];
                } else {
                    $result = ['code' => -1, 'msg' => '删除的角色不存在'];
                }
            }
        }

        return json($result);
    }

    // 读取用户组规则
    public function getUserRules()
    {
        $id = Request::param('id');
        if ($this->auth->check('group_list', Session::get('id'))) {
            $userRules = AuthGroup::where('id', $id)->field('title,rules')->select()->toArray();
            $rules = explode(',', $userRules[0]['rules']);
            //获取根节点
            $result = AuthRule::where('id', 1)->field('title,id')->select()->toArray();
            //获取一级节点
            $children = AuthRule::where('pid', $result[0]['id'])->field('title,id')->order('navid')->select()->toArray();
            //获取二级节点
            $y = 0;
            foreach ($children as $value) {
                $children1 = AuthRule::where('pid', $value['id'])->field('title,id')->order('navid')->select()->toArray();
                if (empty($children1)) {
                    $children[$y]['children'] = array();  //二节节点不存在时将children设置为空数组
                    if (in_array($value['id'], $rules)) {
                        $children[$y]['checked'] = true;  //一节节点为末节点且有权限时设置选择状态
                    }
                } else {
                    //二节节点存在时设置为展开状态
                    $children[$y]['spread'] = true;
                    $i = 0;
                    //向二级节点数组增加checked状态并设置children为空
                    foreach ($children1 as $ch) {
                        if (in_array($ch['id'], $rules)) {
                            $children1[$i]['checked'] = true;
                        }
                        $children1[$i]['children'] = array();
                        ++$i;
                    }
                    $children[$y]['children'] = $children1;
                }
                ++$y;
            }
            //设置根节点为展开状态，并添加children
            $result[0]['spread'] = true;
            $result[0]['children'] = $children;

            return json($result);
        }
    }

    // 读取组所包含用户
    public function getUserGroup($id = '')
    {
        if ($this->auth->check('group_list', Session::get('id'))) {
            $groupUser = AuthGroupAccess::where('group_id', $id)->field('uid')->select()->toArray();
            $users = array();
            if ($groupUser != array()) {
                foreach ($groupUser as $value) {
                    $users[] = $value['uid'];
                }
            }
            //根节点
            $row[0]['title'] = '全选';
            $row[0]['id'] = 0;
            $result = User::field('name,username,id')->where('status', 1)->select()->toArray();
            $y = 0;
            //向一级节点数组增加title、checked状态并设置children为空
            foreach ($result as $value) {
                $result[$y]['title'] = $result[$y]['name'].' ['.$result[$y]['username'].']';
                if (in_array($value['id'], $users)) {
                    $result[$y]['checked'] = true;
                }
                $result[$y]['children'] = array();
                ++$y;
            }
            $row[0]['spread'] = true;
            $row[0]['children'] = $result;

            return json($row);
        }
    }

    public function updateGroupUser()
    {
        $id = Request::param('id');
        $users = Request::param('users');
        if ($this->auth->check('group_list', Session::get('id'))) {
            //取出数据库中当前角色与组关系，后续若写入失败便于恢复
            $oldInfo = AuthGroupAccess::where('group_id', $id)->select()->toArray();
            //清空该用户组与人员的对应关系
            AuthGroupAccess::where('group_id', $id)->delete();
            $AuthGroupAccess = new AuthGroupAccess();
            //重新写入对应关系
            if ('' != $users) {
                $users = explode(',', $users);  //角色列表字符串转换为数组
                if (!in_array('1', $users) && 1 == $id) {
                    $AuthGroupAccess->saveAll($oldInfo);

                    return json(['code' => -2, 'msg' => '系统管理员组必须包含管理员（admin）']);
                }
                $data = array();  //创建空数组用于保存用户组对应关系
                foreach ($users as $user) {
                    $data[] = ['uid' => $user, 'group_id' => $id];
                }
                if ($AuthGroupAccess->saveAll($data)) {
                    $rows = ['code' => 0, 'msg' => '角色成员更新成功'];
                } else {
                    $AuthGroupAccess->saveAll($oldInfo);
                    $rows = ['code' => -1, 'msg' => '角色成员更新出错'];
                }
            } else {
                if (1 == $id) {
                    $AuthGroupAccess->saveAll($oldInfo);
                    $rows = ['code' => '-2', 'msg' => '系统管理员组必须包含管理员（admin）'];
                } else {
                    $rows = ['code' => 0, 'msg' => '角色成员已全部清除'];
                }
            }

            return json($rows);
        }
    }

    // 读取规则
    public function getRules()
    {
        $id = Request::param('id');
        if ($this->auth->check('menu_list', Session::get('id'))) {
            if ('' == $id) {
                $result = AuthRule::field('id,title as name,pid,navid,name as title,type,status,condition,remarks')->order('navid')->select()->toArray();
            } else {
                //修改规则的二次读取
                $result = AuthRule::where('id', $id)->field('id,title as name,pid,navid,name as title,type,status,condition,remarks')->select()->toArray();
            }

            return json($result);
        }
    }

    //更新规则单个字段（状态字段）
    public function updateRulesState()
    {
        $id = Request::param('id');
        $field = Request::param('field');
        $value = Request::param('value');
        if ($this->auth->check('menu_list', Session::get('id'))) {
            $AuthRule = AuthRule::find($id);
            $AuthRule->$field = $value;
            $result = $AuthRule->save();

            return $result ? '更新成功' : '更新失败';
        }
    }

    public function delRules()
    {
        $id = Request::param('id');
        if ($this->auth->check('menu_list', Session::get('id'))) {
            if (1 === $id) {
                $result = ['code' => -1, 'msg' => '根节点禁止删除'];
            } else {
                $children = AuthRule::where('pid', $id)->count();
                if ($children > 0) {
                    $result = ['code' => -2, 'msg' => '此节点存在子规则，需先删除子规则'];
                } else {
                    if ($row = AuthRule::where('id', $id)->delete()) {
                        $result = ['code' => 0, 'msg' => '删除成功'];
                    } else {
                        $result = ['code' => -3, 'msg' => '规则不存在'];
                    }
                }
            }

            return json($result);
        }
    }

    // 新增规则
    public function saveRules()
    {
        $pid = Request::param('pid');
        $name = Request::param('name');
        $title = Request::param('title');
        if ($this->auth->check('menu_list', Session::get('id'))) {
            if ('' == $pid || '' == $name || '' == $title) {
                $rows = ['code' => -1, 'msg' => '缺少必要字段，请检查'];
            } else {
                $menu = ['name' => $name, 'title' => $title];
                $row = AuthRule::whereOr($menu)->count();
                if ($row > 0) {
                    $rows = ['code' => -2, 'msg' => '添加失败，名称或控制器已存在'];
                } else {
                    $menu['pid'] = $pid;
                    $menu['condition'] = Request::param('condition');
                    $menu['remarks'] = Request::param('remarks');
                    if ($result = AuthRule::create($menu)) {
                        $rows = ['code' => 0, 'msg' => '规则[ '.$result->title.' ]添加成功'];
                    } else {
                        $rows = ['code' => -3, 'msg' => '规则[ '.$result->title.' ]添加出错'];
                    }
                }
            }

            return json($rows);
        }
    }

    //更新规则
    public function updateRules()
    {
        $id = Request::param('id');
        $pid = Request::param('pid');
        $name = Request::param('name');
        $title = Request::param('title');
        if ($this->auth->check('menu_list', Session::get('id'))) {
            if ('' == $id || '' == $name || '' == $title || '' == $pid) {
                $rows = ['code' => -1, 'msg' => '缺少必要字段，请检查'];
            } else {
                $row = AuthRule::where("id <> $id AND (title = '$title' OR name = '$name')")->count();
                if ($row > 0) {
                    $rows = ['code' => -2, 'msg' => '更新失败，名称或控制器已存在'];
                } else {
                    $AuthRule = AuthRule::find($id);
                    $AuthRule->name = $name;
                    $AuthRule->title = $title;
                    $AuthRule->pid = $pid;
                    $AuthRule->navid = Request::param('navid');
                    $AuthRule->condition = Request::param('condition');
                    $AuthRule->remarks = Request::param('remarks');
                    $result = $AuthRule->save();
                    if ($result) {
                        $rows = ['code' => 0, 'msg' => '规则[ '.$title.' ]更新成功'];
                    } else {
                        $rows = ['code' => -3, 'msg' => '规则[ '.$title.' ]更新出错'];
                    }
                }
            }

            return json($rows);
        }
    }
}
