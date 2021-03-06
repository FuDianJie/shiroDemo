package com.fu.config;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.context.annotation.Bean;

import java.util.HashSet;
import java.util.Set;

/**
 * 描述：
 *
 * @author caojing
 * @create 2019-01-27-13:57
 */
public class CustomRealm extends AuthorizingRealm {

    //权限校验
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        String username = (String) SecurityUtils.getSubject().getPrincipal();
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        Set<String> stringSet = new HashSet<>();
        stringSet.add("user:show");
        stringSet.add("user:admin");
        info.setStringPermissions(stringSet);
        return info;
    }
    /**
     * 授权
     */
//    @Override
//    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
//        String userName=(String) SecurityUtils.getSubject().getPrincipal();
//        SimpleAuthorizationInfo info=new SimpleAuthorizationInfo();
//        Set<String> roles=new HashSet<String>();
//        List<Role> rolesByUserName = roleDao.getRolesByUserName(userName);
//        for(Role role:rolesByUserName) {
//            roles.add(role.getRoleName());
//        }
//        List<Permission> permissionsByUserName = permissionDao.getPermissionsByUserName(userName);
//        for(Permission permission:permissionsByUserName) {
//            info.addStringPermission(permission.getPermissionName());
//        }
//        info.setRoles(roles);
//        return info;
//    }

    /**
     * 这里可以注入userService,为了方便演示，我就写死了帐号了密码
     * private UserService userService;
     * <p>
     * 获取即将需要认证的信息
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        System.out.println("-------身份认证方法--------");
        //登录页面的用户名
        String userName = (String) authenticationToken.getPrincipal();
        //登录页面的密码
        String userPwd = new String((char[]) authenticationToken.getCredentials());

        //String s1 = MD5Pwd("123", "123");

        //根据用户名从数据库获取密码
        String password = "f5a7977a18cabb413b540b9166435f26";

        if (userName == null) {
            throw new AccountException("用户名不正确");
        }
        return new SimpleAuthenticationInfo(userName, password,ByteSource.Util.bytes(userName + "salt"),getName());
    }

    public static String MD5Pwd(String username, String pwd) {
        // 加密算法MD5
        // salt盐 username + salt
        // 迭代次数
        String md5Pwd = new SimpleHash("MD5", pwd,
                ByteSource.Util.bytes(username + "salt"), 2).toHex();
        return md5Pwd;
    }

    public static void main(String[] args) {
        String s = MD5Pwd("123", "123");
        System.out.println("s = " + s);
    }

}