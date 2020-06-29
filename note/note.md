# Shiro

## 一、权限框架介绍

### 1. 什么是权限管理

权限管理属于系统安全的范畴，权限管理实现对用户访问系统的控制，按照安全规则或者安全策略控制用户可以访问而且只能访问自己被授权的资源。
  权限管理包括用户身份认证和授权两部分，简称认证授权。对于需要访问控制的资源用户首先经过身份认证，认证通过后用户具有该资源的访问权限方可访问。

#### 1.1 用户身份认证

  身份认证，就是判断一个用户是否为合法用户的处理过程。最常用的简单身份认证方式是系统通过核对用户输入的用户名和口令，看其是否与系统中存储的该用户的用户名和口令一致，来判断用户身份是否正确。对于采用指纹等系统，则出示指纹；对于硬件Key等刷卡系统，则需要刷卡。

用户名密码身份认证流程：

![img](https://upload-images.jianshu.io/upload_images/16598307-e69524dc1b2a7478.png)

#### 1.2 授权流程

  授权，即访问控制，控制谁能访问哪些资源。主体进行身份认证后需要分配权限方可访问系统的资源，对于某些资源没有权限是无法访问的。

![img](https://upload-images.jianshu.io/upload_images/16598307-fbb265c89b760333.png)

### 2. 常见权限框架

#### 2.1 Shiro简介

  Apache  Shiro是Java的一个安全框架。目前，使用Apache Shiro的人越来越多，因为它相当简单，对比Spring  Security，可能没有Spring  Security做的功能强大，但是在实际工作时可能并不需要那么复杂的东西，所以使用小而简单的Shiro就足够了。对于它俩到底哪个好，这个不必纠结，能更简单的解决项目问题就好了

#### 2.2 Spring Security

  Spring  Security是一个能够为基于Spring的企业应用系统提供声明式的安全访问控制解决方案的安全框架。它提供了一组可以在Spring应用上下文中配置的Bean，充分利用了Spring IoC，DI（控制反转Inversion of Control ,DI:Dependency Injection  依赖注入）和AOP（面向切面编程）功能，为应用系统提供声明式的安全访问控制功能，减少了为企业系统安全控制编写大量重复代码的工作。它是一个轻量级的安全框架，它确保基于Spring的应用程序提供身份验证和授权支持。它与Spring  MVC有很好地集成，并配备了流行的安全算法实现捆绑在一起。安全主要包括两个操作“认证”与“验证”（有时候也会叫做权限控制）。“认证”是为用户建立一个其声明的角色的过程，这个角色可以一个用户、一个设备或者一个系统。“验证”指的是一个用户在你的应用中能够执行某个操作。在到达授权判断之前，角色已经在身份认证过程中建立了。

#### 2.3 Shiro和Spring Security比较

- Shiro比Spring更容易使用，实现和最重要的理解
- Spring Security更加知名的唯一原因是因为品牌名称
- Spring以简单而闻名，但讽刺的是很多人发现安装Spring Security很难
- Spring Security却有更好的社区支持
- Apache Shiro在Spring Security处理密码学方面有一个额外的模块
- Spring-security 对spring 结合较好，如果项目用的springmvc ，使用起来很方便。但是如果项目中没有用到spring，那就不要考虑它了
- Shiro 功能强大、且 简单、灵活。是Apache 下的项目比较可靠，且不跟任何的框架或者容器绑定，可以独立运行

## 二、Shiro基础介绍

### 1. Shiro三个核心组件

![img](https://upload-images.jianshu.io/upload_images/17985603-12d2f4641a9debf8.png?imageMogr2/auto-orient/strip|imageView2/2/w/414)

#### 1.1 Subject

  Subject：即“当前操作用发户”。但是，在Shiro中，Subject这一概念并不仅仅指人，也可以是第三方进程、后台帐户（Daemon  Account）或其他类似事物。它仅仅意味着“当前跟软件交互的东西”。但考虑到大多数目的和用途，你可以把它认为是Shiro的“用户”概念。Subject代表了当前用户的安全操作，SecurityManager则管理所有用户的安全操作。

#### 1.2 SecurityManager

  SecurityManager：它是Shiro框架的核心，典型的Facade模式，Shiro通过SecurityManager来管理内部组件实例，并通过它来提供安全管理的各种服务。

#### 1.3 Realm

  Realm充当了Shiro与应用安全数据间的“桥梁”或者“连接器”。也就是说，当对用户执行认证（登录）和授权（访问控制）验证时，Shiro会从应用配置的Realm中查找用户及其权限信息。
  从这个意义上讲，Realm实质上是一个安全相关的DAO：它封装了数据源的连接细节，并在需要时将相关数据提供给Shiro。当配置Shiro时，你必须至少指定一个Realm，用于认证和（或）授权。配置多个Realm是可以的，但是至少需要一个。
  Shiro内置了可以连接大量安全数据源（又名目录）的Realm，如LDAP、关系数据库（JDBC）、类似INI的文本配置资源以及属性文件等。如果缺省的Realm不能满足需求，你还可以插入代表自定义数据源的自己的Realm实现。

![img](https://upload-images.jianshu.io/upload_images/17985603-a1ed790437a874f2.png?imageMogr2/auto-orient/strip|imageView2/2/w/414)

#### 1.4 Authenticator

认证器，负责主体认证的，这是一个扩展点，如果用户觉得 Shiro 默认的不好，可以自定义实现；需要自定义认证策略（Authentication Strategy），即什么情况下算用户认证通过了

#### 1.5 Authrizer

授权器，或者访问控制器，用来决定主体是否有权限进行相应的操作；即控制着用户能访问应用中的哪些功能

#### 1.6 SessionManager

如果写过 Servlet 就应该知道 Session 的概念，Session 需要有人去管理它的生命周期，这个组件就是 SessionManager；而Shiro 并不仅仅可以用在 Web 环境，也可以用在如普通的 JavaSE 环境、EJB等环境；所以，Shiro 就抽象了一个自己的Session 来管理主体与应用之间交互的数据；这样的话，比如我们在 Web 环境用，刚开始是一台Web服务器；接着又上了台EJB 服务器；这时又想把两台服务器的会话数据放到一个地方，我们就可以实现自己的分布式会话（如把数据放到Memcached 服务器）

#### 1.7 SessionDAO

DAO大家都用过，数据访问对象，用于会话的 CRUD，比如我们想把 Session 保存到数据库，那么可以实现自己的SessionDAO，通过如JDBC写到数据库；比如想把 Session 放到 Memcached 中，可以实现自己的 Memcached SessionDAO；另外 SessionDAO 中可以使用 Cache 进行缓存，以提高性能；

#### 1.8 CacheManager

缓存控制器，来管理如用户、角色、权限等的缓存的；因为这些数据基本上很少去改变，放到缓存中后可以提高访问的性能

#### 1.9 Cryptography

密码模块，Shiro提高了一些常见的加密组件用于如密码「加密/解密」的。

### 2. Shiro相关类介绍

1. Authentication 认证 ---- 用户登录
2. Authorization 授权 --- 用户具有哪些权限
3. Cryptography 安全数据加密
4. Session Management 会话管理
5. Web Integration web系统集成
6. Interations 集成其它应用，spring、缓存框架

### 3. Shiro 特点

- 易于理解的 Java Security API；
- 简单的身份认证（登录），支持多种数据源；
- 对角色的简单的签权（访问控制），支持细粒度的签权；
- 支持一级缓存，以提升应用程序的性能；
- 内置的基于 POJO 企业会话管理，适用于 Web 以及非 Web 的环境；
- 异构客户端会话访问；
- 非常简单的加密 API；
- 不跟任何的框架或者容器捆绑，可以独立运行

## 三、Shiro的内置过滤器

#### 常用的过滤器

###### 认证过滤器：

- anon: 无需认证（登录）可以访问
- authc: 必须认证才可以访问
- user: 如果使用rememberMe的功能可以直接访问

###### 授权过滤器：

-  perms： 该资源必须得到资源权限才可以访问
-  role: 该资源必须得到角色权限才可以访问



###### 自定义过滤器：

**配置类：**

```java
package com.smy.Realm;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
 
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authz.AuthorizationFilter;       // 角色验证
//import org.apache.shiro.web.filter.authc.AuthenticatingFilter;    //权限认证
/**
 * @author shi_meng_yong
 * @date 2020/6/27 20:45
 * 自定义shiro过滤器
 */
public class Authorizatonfilter extends  AuthorizationFilter {
 
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
			throws Exception {		
		Subject subject= getSubject(request, response);              // 获得主体
		
		String[]  roles = (String[]) mappedValue;                    //角色数组
		if(roles == null || roles.length == 0) {
			return true;
		}
		
		for(String role:roles) {
			if(subject.hasRole(role)) {                          //是否有角色
				return true;
			}
		}
		
		return false;
	}
 
}
```

**配置文件：**

```xml
	  <!--注入URL拦截规则 -->  
	  <property name="filterChainDefinitions">  
	      <value>  
	      /login.html = anon
	      /login33 = anon 
	   	  /login2 = perms["user:update","user:delect"]
	   	  /login2 = rolesOr["user","user11"]     //使用自定义
	      /page/base/staff* = perms["staffList"]  
	     </value>  
	  </property > 
	  <property name="filters">                                                            /配置Filters
	  		<util:map>
	  			<entry  key="rolesOr" value-ref="rolesOrfilter"></entry>
	  		</util:map>
	  </property> 
	</bean>
	<bean class="com.springshirodemo.Realm.Authorizatonfilter" id="rolesOrfilter"></bean>   //将自定义过滤器注入
```

## 四、分析shiro框架登录认证

#### 4.1 登录流程：

Subject 执行 login 方法，传入登录的「用户名」和「密码」，然后 SecurityManager 将这个 login 操作委托给内部的登录模块，登录模块就调用 Realm 去获取安全的「用户名」和「密码」，然后对比，一致则登录，不一致则登录失败

##### 4.1.1 Controller层：

```java
@RequestMapping("/login")
	public String login(String name,String password,Model model){
		System.out.println("name="+name);
		/**
		 * 使用Shiro编写认证操作
		 */
		//1.获取Subject  -- 获取当前登录用户
		Subject subject = SecurityUtils.getSubject();
		
		//2.封装用户数据  创建用户名/密码验证Token（Web 应用中即为前台获取的用户名/密码
		UsernamePasswordToken token = new UsernamePasswordToken(name,password);
		
		//3.执行登录方法
		try {
			subject.login(token);
			
			//登录成功
			//跳转到首页
			return "redirect:/index";
		} catch (UnknownAccountException e) {
			//e.printStackTrace();
			//登录失败:用户名不存在，UnknownAccountException是Shiro抛出的找不到用户异常
			model.addAttribute("msg", "用户名不存在");
			return "login";
		}catch (IncorrectCredentialsException e) {
			//e.printStackTrace();
			//登录失败:密码错误，IncorrectCredentialsException是Shiro抛出的密码错误异常
			model.addAttribute("msg", "密码错误");
			return "login";
		}
	}
```

#### 4.2 分析登录流程：

##### 4.2.1 创建token

比如例子中的UsernamePasswordToken，包含登录的用户名和密码以及是否记住我

```java
package org.apache.shiro.authc;

public class UsernamePasswordToken implements HostAuthenticationToken, RememberMeAuthenticationToken {
    private String username;//用户名
    private char[] password;//密码
    private boolean rememberMe;//是否记住我
    private String host;//当前主机

    public UsernamePasswordToken() {
        this.rememberMe = false;
    }

    public UsernamePasswordToken(String username, char[] password) {
        this(username, (char[])password, false, (String)null);
    }

    public UsernamePasswordToken(String username, String password) {
        this(username, (char[])(password != null ? password.toCharArray() : null), false, (String)null);
    }

    public UsernamePasswordToken(String username, char[] password, String host) {
        this(username, password, false, host);
    }

    public UsernamePasswordToken(String username, String password, String host) {
        this(username, password != null ? password.toCharArray() : null, false, host);
    }

    public UsernamePasswordToken(String username, char[] password, boolean rememberMe) {
        this(username, (char[])password, rememberMe, (String)null);
    }

    public UsernamePasswordToken(String username, String password, boolean rememberMe) {
        this(username, (char[])(password != null ? password.toCharArray() : null), rememberMe, (String)null);
    }

    public UsernamePasswordToken(String username, char[] password, boolean rememberMe, String host) {
        this.rememberMe = false;
        this.username = username;
        this.password = password;
        this.rememberMe = rememberMe;
        this.host = host;
    }

    public UsernamePasswordToken(String username, String password, boolean rememberMe, String host) {
        this(username, password != null ? password.toCharArray() : null, rememberMe, host);
    }

    public String getUsername() {
        return this.username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public char[] getPassword() {
        return this.password;
    }

    public void setPassword(char[] password) {
        this.password = password;
    }

    public Object getPrincipal() {
        return this.getUsername();
    }

    public Object getCredentials() {
        return this.getPassword();
    }

    public String getHost() {
        return this.host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public boolean isRememberMe() {
        return this.rememberMe;
    }

    public void setRememberMe(boolean rememberMe) {
        this.rememberMe = rememberMe;
    }

    public void clear() {
        this.username = null;
        this.host = null;
        this.rememberMe = false;
        if (this.password != null) {
            for(int i = 0; i < this.password.length; ++i) {
                this.password[i] = 0;
            }

            this.password = null;
        }

    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.getClass().getName());
        sb.append(" - ");
        sb.append(this.username);
        sb.append(", rememberMe=").append(this.rememberMe);
        if (this.host != null) {
            sb.append(" (").append(this.host).append(")");
        }

        return sb.toString();
    }
}

```

##### 4.2.2获取Subject

**执行subject.login(token) 方法：**

```java
package org.apache.shiro.subject;

public interface Subject {
		....(此处省略源码一万字)
        void login(AuthenticationToken var1) throws AuthenticationException;
    ......(此处省略源码一万字)

}
```

**subject.login()方法实现类DelegatingSubject中的login()方法：**

```java
  public void login(AuthenticationToken token) throws AuthenticationException {
        this.clearRunAsIdentitiesInternal();
        Subject subject = this.securityManager.login(this, token);//重点
        String host = null;
        PrincipalCollection principals;
        if (subject instanceof DelegatingSubject) {
            DelegatingSubject delegating = (DelegatingSubject)subject;
            principals = delegating.principals;
            host = delegating.host;
        } else {
            principals = subject.getPrincipals();
        }

        if (principals != null && !principals.isEmpty()) {
            this.principals = principals;
            this.authenticated = true;
            if (token instanceof HostAuthenticationToken) {
                host = ((HostAuthenticationToken)token).getHost();
            }

            if (host != null) {
                this.host = host;
            }

            Session session = subject.getSession(false);
            if (session != null) {
                this.session = this.decorate(session);
            } else {
                this.session = null;
            }

        } else {
            String msg = "Principals returned from securityManager.login( token ) returned a null or empty value.  This value must be non null and populated with one or more elements.";
            //英文翻译:从securityManager.login（token）返回的主体返回空值或空值。 此值必须为非null并填充一个或多个元素
            throw new IllegalStateException(msg);
        }
    }

```

##### 4.2.3 SecurityManager

可以看到在实现类login()方法中代理给securityManager.login()接口方法，源码如下：

```java
package org.apache.shiro.mgt;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.Authenticator;
import org.apache.shiro.authz.Authorizer;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;

public interface SecurityManager extends Authenticator, Authorizer, SessionManager {
//注意SecurityManager实现的接口 Authenticator 认证、Authorizer 授权、SessionManager 会话管理
    //登录
    Subject login(Subject var1, AuthenticationToken var2) throws AuthenticationException;
	//退出
    void logout(Subject var1);

    Subject createSubject(SubjectContext var1);
}

```

**SecurityManager的login()方法：**

```java
public Subject login(Subject subject, AuthenticationToken token) throws AuthenticationException {
        AuthenticationInfo info;
        try {
            info = this.authenticate(token);//重点
        } catch (AuthenticationException var7) {
            AuthenticationException ae = var7;

            try {
                this.onFailedLogin(token, ae, subject);
            } catch (Exception var6) {
                if (log.isInfoEnabled()) {
                    log.info("onFailedLogin method threw an exception.  Logging and propagating original AuthenticationException.", var6);
                }
            }

            throw var7;
        }

        Subject loggedIn = this.createSubject(token, info, subject);
        this.onSuccessfulLogin(token, info, loggedIn);
        return loggedIn;
    }
```

调用自己的 authenticate 方法执行登录，在 authenticate 方法中代理给 Authenticator 接口类型的属性去真正执行 `authenticate(token)` 方法

SecurityManager接口继承了Authenticator登录认证，Authenticator接口源代码如下：

```java
package org.apache.shiro.authc;

public interface Authenticator {
    AuthenticationInfo authenticate(AuthenticationToken var1) throws AuthenticationException;
}

```

**Authenticator接口的实现类AbstractAuthenticator中的 authenticate 方法：**

​	在这方法中对token进行全面校验

```java
public final AuthenticationInfo authenticate(AuthenticationToken token) throws AuthenticationException {
        if (token == null) {
            throw new IllegalArgumentException("Method argument (authentication token) cannot be null.");
            //方法参数（身份验证令牌）不能为空
        } else {
            log.trace("Authentication attempt received for token [{}]", token);
			//日志打印关于令牌信息
            AuthenticationInfo info;
            try {
                info = this.doAuthenticate(token);//重点，执行doAuthenticate方法
                if (info == null) {
                    String msg = "No account information found for authentication token [" + token + "] by this " + "Authenticator instance.  Please check that it is configured correctly.";//没有在令牌中找到验证身份的信息，请检查
                    throw new AuthenticationException(msg);
                }
            } catch (Throwable var8) {
                AuthenticationException ae = null;
                if (var8 instanceof AuthenticationException) {
                    ae = (AuthenticationException)var8;
                }

                if (ae == null) {
                    String msg = "Authentication failed for token submission [" + token + "].  Possible unexpected " + "error? (Typical or expected login exceptions should extend from AuthenticationException).";//提交的令牌验证失败
                    ae = new AuthenticationException(msg, var8);
                    if (log.isWarnEnabled()) {
                        log.warn(msg, var8);
                    }
                }

                try {
                    this.notifyFailure(token, ae);
                } catch (Throwable var7) {
                    if (log.isWarnEnabled()) {
                        String msg = "Unable to send notification for failed authentication attempt - listener error?.  Please check your AuthenticationListener implementation(s).  Logging sending exception and propagating original AuthenticationException instead...";//无法发送有关身份验证尝试失败的通知,或许是监听器错误，请检查
                        log.warn(msg, var7);
                    }
                }

                throw ae;
            }

            log.debug("Authentication successful for token [{}].  Returned account [{}]", token, info);//令牌验证成功，返回用户信息
            this.notifySuccess(token, info);
            return info;
        }
    }
```

从代码中可以看到执行`doAuthenticate`接口，下面是源代码

```java
    protected abstract AuthenticationInfo doAuthenticate(AuthenticationToken var1) throws AuthenticationException;

```

**doAuthenticate接口的实现类ModularRealmAuthenticator**

```java
package org.apache.shiro.authc.pam;

import java.util.Collection;
import java.util.Iterator;
import org.apache.shiro.authc.AbstractAuthenticator;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.LogoutAware;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ModularRealmAuthenticator extends AbstractAuthenticator {
    private static final Logger log = LoggerFactory.getLogger(ModularRealmAuthenticator.class);
    private Collection<Realm> realms;
    private AuthenticationStrategy authenticationStrategy = new AtLeastOneSuccessfulStrategy();

    public ModularRealmAuthenticator() {
    }

    public void setRealms(Collection<Realm> realms) {
        this.realms = realms;
    }

    protected Collection<Realm> getRealms() {
        return this.realms;
    }

    public AuthenticationStrategy getAuthenticationStrategy() {
        return this.authenticationStrategy;
    }

    public void setAuthenticationStrategy(AuthenticationStrategy authenticationStrategy) {
        this.authenticationStrategy = authenticationStrategy;
    }

    protected void assertRealmsConfigured() throws IllegalStateException {
        Collection<Realm> realms = this.getRealms();
        if (CollectionUtils.isEmpty(realms)) {
            String msg = "Configuration error:  No realms have been configured!  One or more realms must be present to execute an authentication attempt.";
            throw new IllegalStateException(msg);
        }
    }
    
    protected AuthenticationInfo doSingleRealmAuthentication(Realm realm, AuthenticationToken token) {
        //验证Realm是否支持身份验证令牌
        if (!realm.supports(token)) {//不支持
            String msg = "Realm [" + realm + "] does not support authentication token [" + token + "].  Please ensure that the appropriate Realm implementation is " + "configured correctly or that the realm accepts AuthenticationTokens of this type.";
            throw new UnsupportedTokenException(msg);
        } else {//支持
            //把认证信息包装去执行Realm接口中的getAuthenticationInfo----重点！！！
            AuthenticationInfo info = realm.getAuthenticationInfo(token);
            if (info == null) {//信息为空，提示无法找到数据
                String msg = "Realm [" + realm + "] was unable to find account data for the " + "submitted AuthenticationToken [" + token + "].";
                throw new UnknownAccountException(msg);
            } else {
                return info;
            }
        }
    }

    protected AuthenticationInfo doMultiRealmAuthentication(Collection<Realm> realms, AuthenticationToken token) {
        //拿到认证策略
        AuthenticationStrategy strategy = this.getAuthenticationStrategy();
        AuthenticationInfo aggregate = strategy.beforeAllAttempts(realms, token);
        if (log.isTraceEnabled()) {
            log.trace("Iterating through {} realms for PAM authentication", realms.size());
        }

        Iterator var5 = realms.iterator();

        while(var5.hasNext()) {
            Realm realm = (Realm)var5.next();
            aggregate = strategy.beforeAttempt(realm, token, aggregate);
            if (realm.supports(token)) {
                log.trace("Attempting to authenticate token [{}] using realm [{}]", token, realm);
                AuthenticationInfo info = null;
                Throwable t = null;

                try {
                    info = realm.getAuthenticationInfo(token);
                } catch (Throwable var11) {
                    t = var11;
                    if (log.isDebugEnabled()) {
                        String msg = "Realm [" + realm + "] threw an exception during a multi-realm authentication attempt:";
                        log.debug(msg, var11);
                    }
                }

                aggregate = strategy.afterAttempt(realm, token, info, aggregate, t);
            } else {
                log.debug("Realm [{}] does not support token {}.  Skipping realm.", realm, token);
            }
        }

        aggregate = strategy.afterAllAttempts(token, aggregate);
        return aggregate;
    }
	//实现AbstractAuthenticator抽象类的doAuthenticate方法
    protected AuthenticationInfo doAuthenticate(AuthenticationToken authenticationToken) throws AuthenticationException {
        this.assertRealmsConfigured();
        Collection<Realm> realms = this.getRealms();
        return realms.size() == 1 ? this.doSingleRealmAuthentication((Realm)realms.iterator().next(), authenticationToken) : this.doMultiRealmAuthentication(realms, authenticationToken);
        //在这注意调用doSingleRealmAuthentication和doMultiRealmAuthentication方法
    }

    public void onLogout(PrincipalCollection principals) {
        super.onLogout(principals);
        Collection<Realm> realms = this.getRealms();
        if (!CollectionUtils.isEmpty(realms)) {
            Iterator var3 = realms.iterator();

            while(var3.hasNext()) {
                Realm realm = (Realm)var3.next();
                if (realm instanceof LogoutAware) {
                    ((LogoutAware)realm).onLogout(principals);
                }
            }
        }

    }
}

```

可以在源代码中发现最后会调用 Realm 的 `getAuthenticationInfo(AuthenticationToken)` 方法

##### 4.2.4 Realm接口

```java
package org.apache.shiro.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;

public interface Realm {
    String getName();//获取用户名

    boolean supports(AuthenticationToken var1);//是否提供支持

    AuthenticationInfo getAuthenticationInfo(AuthenticationToken var1) throws AuthenticationException;//重点
}

```

**getAuthenticationInfo方法的实现类**

重点在getAuthenticationInfo方法

```java
package org.apache.shiro.realm;

import java.util.concurrent.atomic.AtomicInteger;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authc.credential.SimpleCredentialsMatcher;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.Initializable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AuthenticatingRealm extends CachingRealm implements Initializable {
    private static final Logger log = LoggerFactory.getLogger(AuthenticatingRealm.class);
    private static final AtomicInteger INSTANCE_COUNT = new AtomicInteger();
    private static final String DEFAULT_AUTHORIZATION_CACHE_SUFFIX = ".authenticationCache";
    private CredentialsMatcher credentialsMatcher;
    private Cache<Object, AuthenticationInfo> authenticationCache;
    private boolean authenticationCachingEnabled;
    private String authenticationCacheName;
    private Class<? extends AuthenticationToken> authenticationTokenClass;

    public AuthenticatingRealm() {
        this((CacheManager)null, new SimpleCredentialsMatcher());
    }

    public AuthenticatingRealm(CacheManager cacheManager) {
        this(cacheManager, new SimpleCredentialsMatcher());
    }

    public AuthenticatingRealm(CredentialsMatcher matcher) {
        this((CacheManager)null, matcher);
    }

    public AuthenticatingRealm(CacheManager cacheManager, CredentialsMatcher matcher) {
        this.authenticationTokenClass = UsernamePasswordToken.class;
        this.authenticationCachingEnabled = false;
        int instanceNumber = INSTANCE_COUNT.getAndIncrement();
        this.authenticationCacheName = this.getClass().getName() + ".authenticationCache";
        if (instanceNumber > 0) {
            this.authenticationCacheName = this.authenticationCacheName + "." + instanceNumber;
        }

        if (cacheManager != null) {
            this.setCacheManager(cacheManager);
        }

        if (matcher != null) {
            this.setCredentialsMatcher(matcher);
        }

    }

    public CredentialsMatcher getCredentialsMatcher() {
        return this.credentialsMatcher;
    }

    public void setCredentialsMatcher(CredentialsMatcher credentialsMatcher) {
        this.credentialsMatcher = credentialsMatcher;
    }

    public Class getAuthenticationTokenClass() {
        return this.authenticationTokenClass;
    }

    public void setAuthenticationTokenClass(Class<? extends AuthenticationToken> authenticationTokenClass) {
        this.authenticationTokenClass = authenticationTokenClass;
    }

    public void setAuthenticationCache(Cache<Object, AuthenticationInfo> authenticationCache) {
        this.authenticationCache = authenticationCache;
    }

    public Cache<Object, AuthenticationInfo> getAuthenticationCache() {
        return this.authenticationCache;
    }

    public String getAuthenticationCacheName() {
        return this.authenticationCacheName;
    }

    public void setAuthenticationCacheName(String authenticationCacheName) {
        this.authenticationCacheName = authenticationCacheName;
    }

    public boolean isAuthenticationCachingEnabled() {
        return this.authenticationCachingEnabled && this.isCachingEnabled();
    }

    public void setAuthenticationCachingEnabled(boolean authenticationCachingEnabled) {
        this.authenticationCachingEnabled = authenticationCachingEnabled;
        if (authenticationCachingEnabled) {
            this.setCachingEnabled(true);
        }

    }

    public void setName(String name) {
        super.setName(name);
        String authcCacheName = this.authenticationCacheName;
        if (authcCacheName != null && authcCacheName.startsWith(this.getClass().getName())) {
            this.authenticationCacheName = name + ".authenticationCache";
        }

    }

    public boolean supports(AuthenticationToken token) {
        return token != null && this.getAuthenticationTokenClass().isAssignableFrom(token.getClass());
    }

    public final void init() {
        this.getAvailableAuthenticationCache();
        this.onInit();
    }

    protected void onInit() {
    }

    protected void afterCacheManagerSet() {
        this.getAvailableAuthenticationCache();
    }

    private Cache<Object, AuthenticationInfo> getAvailableAuthenticationCache() {
        Cache<Object, AuthenticationInfo> cache = this.getAuthenticationCache();
        boolean authcCachingEnabled = this.isAuthenticationCachingEnabled();
        if (cache == null && authcCachingEnabled) {
            cache = this.getAuthenticationCacheLazy();
        }

        return cache;
    }

    private Cache<Object, AuthenticationInfo> getAuthenticationCacheLazy() {
        if (this.authenticationCache == null) {
            log.trace("No authenticationCache instance set.  Checking for a cacheManager...");
            CacheManager cacheManager = this.getCacheManager();
            if (cacheManager != null) {
                String cacheName = this.getAuthenticationCacheName();
                log.debug("CacheManager [{}] configured.  Building authentication cache '{}'", cacheManager, cacheName);
                this.authenticationCache = cacheManager.getCache(cacheName);
            }
        }

        return this.authenticationCache;
    }
    private AuthenticationInfo getCachedAuthenticationInfo(AuthenticationToken token) {
        AuthenticationInfo info = null;
        //拿到可用的身份验证信息
        Cache<Object, AuthenticationInfo> cache = this.getAvailableAuthenticationCache();
        if (cache != null && token != null) {
            //尝试从缓存中检索AuthenticationInfo
            log.trace("Attempting to retrieve the AuthenticationInfo from cache.");
            //拿到令牌中的K
            Object key = this.getAuthenticationCacheKey(token);
            //把key放入认证信息中
            info = (AuthenticationInfo)cache.get(key);
            if (info == null) {
                log.trace("No AuthorizationInfo found in cache for key [{}]", key);
            } else {
                log.trace("Found cached AuthorizationInfo for key [{}]", key);
            }
        }

        return info;
    }
	//判断拿过来的认证信息是否可用
    private void cacheAuthenticationInfoIfPossible(AuthenticationToken token, AuthenticationInfo info) {
        if (!this.isAuthenticationCachingEnabled(token, info)) {
            //不可用提示信息AuthenticationInfo缓存已禁用。
            log.debug("AuthenticationInfo caching is disabled for info [{}].  Submitted token: [{}].", info, token);
        } else {
            //如果可用获取认证信息
            Cache<Object, AuthenticationInfo> cache = this.getAvailableAuthenticationCache();
            if (cache != null) {
                //信息不为空，拿到token中的key返回
                Object key = this.getAuthenticationCacheKey(token);
                cache.put(key, info);
                //缓存的AuthenticationInfo用于继续验证
                log.trace("Cached AuthenticationInfo for continued authentication.  key=[{}], value=[{}].", key, info);
            }

        }
    }
	//判断认证方式是否启用
    protected boolean isAuthenticationCachingEnabled(AuthenticationToken token, AuthenticationInfo info) {
        return this.isAuthenticationCachingEnabled();
    }

    public final AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
    	//通过token拿到所需要的认证信息
        AuthenticationInfo info = this.getCachedAuthenticationInfo(token);
        if (info == null) {
            //认证信息时候为空交给doGetAuthenticationInfo执行，通过queryForAuthenticationInfo()方法重新获取Token信息去尝试重新获取信息
            info = this.doGetAuthenticationInfo(token);
            log.debug("Looked up AuthenticationInfo [{}] from doGetAuthenticationInfo", info);		//如果都不为空执行cacheAuthenticationInfoIfPossible
            if (token != null && info != null) {
                this.cacheAuthenticationInfoIfPossible(token, info);
            }
        } else {
            log.debug("Using cached authentication info [{}] to perform credentials matching.", info);
        }
		//如果信息为空执行assertCredentialsMatch
        if (info != null) {
            this.assertCredentialsMatch(token, info);
        } else {//未找到提交的信息，返回token
            log.debug("No AuthenticationInfo found for submitted AuthenticationToken [{}].  Returning null.", token);
        }

        return info;
    }
	
    protected void assertCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) throws AuthenticationException {
        //获得凭证匹配器 验证凭据
        CredentialsMatcher cm = this.getCredentialsMatcher();
        if (cm != null) {
            if (!cm.doCredentialsMatch(token, info)) {//验证凭据，不匹配
                String msg = "Submitted credentials for token [" + token + "] did not match the expected credentials.";
                //令牌[“ +令牌+”]的提交凭据与期望的凭据不匹配。
                throw new IncorrectCredentialsException(msg);
            }
        } else {
            //没有配置CredentialsMatcher，无法在身份验证期间验证凭据。
            throw new AuthenticationException("A CredentialsMatcher must be configured in order to verify credentials during authentication.  If you do not wish for credentials to be examined, you can configure an " + AllowAllCredentialsMatcher.class.getName() + " instance.");
        }
    }

    protected Object getAuthenticationCacheKey(AuthenticationToken token) {
        return token != null ? token.getPrincipal() : null;
    }

    protected Object getAuthenticationCacheKey(PrincipalCollection principals) {
        return this.getAvailablePrincipal(principals);
    }

    protected void doClearCache(PrincipalCollection principals) {
        super.doClearCache(principals);
        this.clearCachedAuthenticationInfo(principals);
    }

    private static boolean isEmpty(PrincipalCollection pc) {
        return pc == null || pc.isEmpty();
    }

    protected void clearCachedAuthenticationInfo(PrincipalCollection principals) {
        if (!isEmpty(principals)) {
            Cache<Object, AuthenticationInfo> cache = this.getAvailableAuthenticationCache();
            if (cache != null) {
                Object key = this.getAuthenticationCacheKey(principals);
                cache.remove(key);
            }
        }

    }

    protected abstract AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken var1) throws AuthenticationException;
}

```

**doGetAuthenticationInfo方法：**

通过queryForAuthenticationInfo中的token去重新获取认证信息

```
protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        try {
            AuthenticationInfo info = this.queryForAuthenticationInfo(token, this.ensureContextFactory());
            return info;
        } catch (javax.naming.AuthenticationException var5) {
            throw new AuthenticationException("LDAP authentication failed.", var5);
        } catch (NamingException var6) {
            String msg = "LDAP naming error while attempting to authenticate user.";
            throw new AuthenticationException(msg, var6);
        }
    }
```

**queryForAuthenticationInfo()方法：**

```java
 protected AuthenticationInfo queryForAuthenticationInfo(AuthenticationToken token, LdapContextFactory ldapContextFactory) throws NamingException {
        UsernamePasswordToken upToken = (UsernamePasswordToken)token;
        LdapContext ctx = null;

        try {
            ctx = ldapContextFactory.getLdapContext(upToken.getUsername(), String.valueOf(upToken.getPassword()));
        } finally {
            LdapUtils.closeContext(ctx);
        }

        return this.buildAuthenticationInfo(upToken.getUsername(), upToken.getPassword());
    }
```



##### 4.2.5 执行认证逻辑

Realm 相当于数据源，功能是通过token获取数据源中的安全数据，然后与数据库中存储的信息比对，这个过程中可以抛出异常，告诉 shiro 登录失败，如果认证成功，则登录成功！

```java
/**
	 * 执行认证逻辑
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken arg0) throws AuthenticationException {
		System.out.println("执行认证逻辑");

		//编写shiro判断逻辑，判断用户名和密码
		//1.判断用户名  token中的用户信息是登录时候传进来的
		UsernamePasswordToken token = (UsernamePasswordToken)arg0;

		User user = userSerivce.findByName(token.getUsername());

		if(user==null){
			//用户名不存在
			return null;//shiro底层会抛出UnKnowAccountException
		}

		//2.判断密码
		//第二个字段是user.getPassword()，注意这里是指从数据库中获取的password。第三个字段是realm，即当前realm的名称。
		//这块对比逻辑是先对比username，但是username肯定是相等的，所以真正对比的是password。
		//从这里传入的password（这里是从数据库获取的）和token（filter中登录时生成的）中的password做对比，如果相同就允许登录，
		// 不相同就抛出IncorrectCredentialsException异常。
		//如果认证不通过，就不会执行下面的授权方法了
		return new SimpleAuthenticationInfo(user,user.getPassword(),"");
	}
```



##### 4.2.6 总结：

```tex
1、创建 AuthenticationToken，然后调用 Subject.login 方法进行登录认证
2、Subject 委托给 SecurityManager
3、SecurityManager 委托给 Authenticator 接口
4、Authenticator 接口调用 Realm 获取登录信息比对
```

## 五、Shiro的缓存问题

shiro中提供了认证信息和授权信息的缓存，值得注意的是shiro 默认关闭认证信息缓存, 因为每次登陆一次查询一次数据库比对一下用户名密码，做缓存的必要几乎是没有的。但是对于授权信息的缓存默认是开启的，用户认证通过后该用户第一次授权则调用 realm 查询数据库，在该用户第二次授权时不会调用 realm 查询数据库, 直接从缓存中取出授权信息(权限标识符)

##### 5.1 使用 ehcache整合Shiro缓存

###### 5.1.1 在 spring-shiro.xim 中配置 cacheManager

```xml
<!-- securityManager安全管理器 -->
<bean id="securityManager" class="org.apache.shiro.web.mgt.DefaultWebSecurityManager">
    <property name="realm" ref="customRealm" />
    <!-- 注入缓存管理器 -->
    <property name="cacheManager" ref="cacheManager"/>
</bean>

<!-- 缓存管理器 -->
<bean id="cacheManager" class="org.apache.shiro.cache.ehcache.EhCacheManager">
    <property name="cacheManagerConfigFile" value="classpath:shiro-ehcache.xml"/>
</bean>

```

###### 5.1.2 创建shiro-ehcache.xml

```xml
<ehcache xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:noNamespaceSchemaLocation="../config/ehcache.xsd">
    <!--diskStore：缓存数据持久化的目录 地址  -->
    <diskStore path="F:\develop\ehcache" />
    <defaultCache 
        <!-- 缓存最大个数 -->
        maxElementsInMemory="1000" 
        <!-- 硬盘最大缓存个数 -->
        maxElementsOnDisk="10000000"
        <!-- 对象是否永久有效，一但设置了，timeout将不起作用 -->
        eternal="false" 
        <!-- 当内存中对象数量达到maxElementsInMemory时，Ehcache将会对象写到磁盘中 -->
        overflowToDisk="false" 
        <!-- 是否缓存虚拟机重启期数据 -->
        diskPersistent="false"
        <!--
            设置对象在失效前的允许闲置时间（单位：秒）。
            仅当eternal=false对象不是永久有效时使用，可选属性，默认值是0，也就是可闲置时间无穷大 
        -->
        timeToIdleSeconds="120"
        <!--
            设置对象在失效前允许存活时间（单位：秒）。
            最大时间介于创建时间和失效时间之间。仅当eternal=false对象不是永久有效时使用，默认是0.，也就是对象存活时间无穷大。
        -->
        timeToLiveSeconds="120" 
        <!-- 磁盘失效线程运行时间间隔，默认是120秒。 -->
        diskExpiryThreadIntervalSeconds="120"
        <!--
            当达到maxElementsInMemory限制时，Ehcache将会根据指定的策略去清理内存。默认策略是LRU（最近最少使用）
            你可以设置为FIFO（先进先出）或是LFU（较少使用）
        -->
        memoryStoreEvictionPolicy="LRU">
    </defaultCache>
</ehcache>

```

##### 5.2缓存清空

如果用户正常退出，缓存自动清空。如果用户非正常退出,，缓存自动清空。如果我们修改了权限, 而且用户不退出系统, 修改的权限无法立即生效。那么如何在修改了权限之后立即生效呢?
 	实现思路: 在权限修改后调用realm中的方法，realm已经由spring管理，所以从spring中获取realm实例,调用realm 的 clearCached() 方法进行清除缓存.

```java
//清除缓存
public void clearCached() {
    PrincipalCollection principals = SecurityUtils.getSubject().getPrincipals();
    super.clearCache(principals);
}

```

## 六、Shiro十分钟的快速开始

打开apache-shiro的官网我们可以看到shiro十分钟使用(10 Minute Tutorial)，根据提示可以下载相关资料，进入shiro官网提供的简单案例，下面分析这个案例

shiro官网：http://shiro.apache.org/

github下载地址：https://github.com/apache/shiro

案例完整地址：https://github.com/apache/shiro/tree/master/samples/quickstart/src/main/java

##### 6.1 创建Maven项目

构建成功后修改pom.xml文件，把所需依赖导入，官网提供pom没有指定版本号需要自身查找，并删掉<scope>runtime</scope>，防止日志未打印，指定日志使用log4j

##### 6.2 修改后的pom.xml：

```xml
<?xml version="1.0" encoding="UTF-8"?>

<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>

  <groupId>com.smy</groupId>
  <artifactId>shiro-demo</artifactId>
  <version>1.0-SNAPSHOT</version>

  <properties>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    <maven.compiler.source>1.8</maven.compiler.source>
    <maven.compiler.target>1.8</maven.compiler.target>
  </properties>

  <dependencies>
    <dependency>
      <groupId>org.apache.shiro</groupId>
      <artifactId>shiro-core</artifactId>
      <version>1.4.1</version>
    </dependency>

    <!-- configure logging -->
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>jcl-over-slf4j</artifactId>
      <version>1.7.25</version>
    </dependency>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-log4j12</artifactId>
      <version>1.7.29</version>
    </dependency>
    <dependency>
      <groupId>log4j</groupId>
      <artifactId>log4j</artifactId>
      <version>1.2.17</version>
    </dependency>
  </dependencies>
</project>

```

##### 6.3 在main下创建resources

###### 6.3.1 添加官网指定log4j.properties：

```properties
log4j.rootLogger=INFO, stdout

log4j.appender.stdout=org.apache.log4j.ConsoleAppender
log4j.appender.stdout.layout=org.apache.log4j.PatternLayout
log4j.appender.stdout.layout.ConversionPattern=%d %p [%c] - %m %n

# General Apache libraries
log4j.logger.org.apache=WARN

# Spring
log4j.logger.org.springframework=WARN

# Default Shiro logging
log4j.logger.org.apache.shiro=INFO

# Disable verbose logging
log4j.logger.org.apache.shiro.util.ThreadContext=WARN
log4j.logger.org.apache.shiro.cache.ehcache.EhCache=WARN

```

###### 6.3.2 添加shiro.ini：

注意[users]和[roles]

```ini
#下面注释是官网提供，可翻译理解其含义
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
# =============================================================================
# Quickstart INI Realm configuration
#
# For those that might not understand the references in this file, the
# definitions are all based on the classic Mel Brooks' film "Spaceballs". ;)
# =============================================================================

# -----------------------------------------------------------------------------
# Users and their assigned roles
#
# Each line conforms to the format defined in the
# org.apache.shiro.realm.text.TextConfigurationRealm#setUserDefinitions JavaDoc
# -----------------------------------------------------------------------------
[users]
# user 'root' with password 'secret' and the 'admin' role
root = secret, admin
# user 'guest' with the password 'guest' and the 'guest' role
guest = guest, guest
# user 'presidentskroob' with password '12345' ("That's the same combination on
# my luggage!!!" ;)), and role 'president'
presidentskroob = 12345, president
# user 'darkhelmet' with password 'ludicrousspeed' and roles 'darklord' and 'schwartz'
darkhelmet = ludicrousspeed, darklord, schwartz
# user 'lonestarr' with password 'vespa' and roles 'goodguy' and 'schwartz'重点后面会遇到
lonestarr = vespa, goodguy, schwartz

# -----------------------------------------------------------------------------
# Roles with assigned permissions
# 
# Each line conforms to the format defined in the
# org.apache.shiro.realm.text.TextConfigurationRealm#setRoleDefinitions JavaDoc
# -----------------------------------------------------------------------------
[roles]
# 'admin' role has all permissions, indicated by the wildcard '*'
admin = *
# The 'schwartz' role can do anything (*) with any lightsaber:
schwartz = lightsaber:*
# The 'goodguy' role is allowed to 'drive' (action) the winnebago (type) with
# license plate 'eagle5' (instance specific id)
goodguy = winnebago:drive:eagle5

```

##### 6.4 添加Quickstart.java

复制官网提供的Quickstart.java到本项目java包下，值得注意有两个包会报错，我打了注释重新导入，并在代码中写入大量注释，基本是对官网文档翻译，还有个人对代码的理解。另外~~IniSecurityManagerFactory~~方法过时

```java
package com.smy;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
//import org.apache.shiro.ini.IniSecurityManagerFactory;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
//import org.apache.shiro.lang.util.Factory;
import org.apache.shiro.util.Factory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
/**
 * Simple Quickstart application showing how to use Shiro's API.
 * 简单的快速入门应用程序，显示了如何使用Shiro的API。
 * @since 0.9 RC2
 */

    public class Quickstart {

        //使用日志文件
        private static final transient Logger log = LoggerFactory.getLogger(Quickstart.class);


        public static void main(String[] args) {

            //使用工厂模式创建带有配置的Shiro SecurityManager
            //提取.ini文件并返回一个SecurityManager实例：
            //在类路径的根目录下使用shiro.ini文件
            Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");

            SecurityManager securityManager = factory.getInstance();
  
            SecurityUtils.setSecurityManager(securityManager);

            //获取当前执行的用户 subject
            Subject currentUser = SecurityUtils.getSubject();

            //通过当前用户拿到session不是http的session是shiro 使用Session
            Session session = currentUser.getSession();
            //设置一个session 存值
            session.setAttribute("someKey", "aValue");
            //取值value
            String value = (String) session.getAttribute("someKey");
            //打印获取的value，自行更改打印信息
            if (value.equals("aValue")) {
                log.info("Subject-->session [" + value + "]");
            }

            //测试当前用户是否被认证
            if (!currentUser.isAuthenticated()) {
                 //根据账号密码设置令牌Token，这里设置与shiro.ini相互呼应，一旦不一致就会提示无权限 
                UsernamePasswordToken token = new UsernamePasswordToken("lonestarr", "vespa");
                token.setRememberMe(true);//设置记住我
                try {
                    currentUser.login(token);//执行登录操作
                } catch (UnknownAccountException uae) { //用户名不存在
                    log.info("There is no user with username of " + token.getPrincipal());
                } catch (IncorrectCredentialsException ice) {//密码错误
                    log.info("Password for account " + token.getPrincipal() + " was incorrect!");
                } catch (LockedAccountException lae) {// 用户被锁定 -- 超过x次密码错误
                    log.info("The account for username " + token.getPrincipal() + " is locked.  " +
                            "Please contact your administrator to unlock it.");
                }
                // ...在这里捕获更多异常（也许是针对您的应用程序的自定义异常？
                catch (AuthenticationException ae) {
                    //意外状况？ 错误？
                }
            }

            //说明他们是谁：
            //打印当前用户的认证信息
            log.info("User [" + currentUser.getPrincipal() + "] logged in successfully.");

            //测试当前用户是否拥有什么角色：
            if (currentUser.hasRole("schwartz")) {
                log.info("May the Schwartz be with you!");
            } else {
                log.info("Hello, mere mortal.");
            }

            //测试类型化的权限（不是实例级别） 检测是有什么权限 粗粒度的
            if (currentUser.isPermitted("lightsaber:wield")) {
                log.info("You may use a lightsaber ring.  Use it wisely.");
            } else {
                log.info("Sorry, lightsaber rings are for schwartz masters only.");
            }

            //（非常强大的）实例级别权限： 细粒度的
            if (currentUser.isPermitted("winnebago:drive:eagle5")) {
                log.info("You are permitted to 'drive' the winnebago with license plate (id) 'eagle5'.  " +
                        "Here are the keys - have fun!");
            } else {
                log.info("Sorry, you aren't allowed to drive the 'eagle5' winnebago!");
            }

            //全部完成-登出！注销
            currentUser.logout();

            System.exit(0);
        }

    }

```

###### 6.4.1 运行后的日志：

```
2020-06-28 16:33:22,007 INFO [org.apache.shiro.session.mgt.AbstractValidatingSessionManager] - Enabling session validation scheduler... 
2020-06-28 16:33:22,442 INFO [com.smy.Quickstart] - Subject-->session [aValue] 
2020-06-28 16:33:22,443 INFO [com.smy.Quickstart] - User [lonestarr] logged in successfully. 
2020-06-28 16:33:22,443 INFO [com.smy.Quickstart] - May the Schwartz be with you! 
2020-06-28 16:33:22,444 INFO [com.smy.Quickstart] - You may use a lightsaber ring.  Use it wisely. 
2020-06-28 16:33:22,444 INFO [com.smy.Quickstart] - You are permitted to 'drive' the winnebago with license plate (id) 'eagle5'.  Here are the keys - have fun! 

```



## 七、Shiro整合Spring boot

#### 7.1 建立Maven项目

在pom.xml导入Spring boot父工程使项目成为springboot项目

```xml
<!-- 继承Spring Boot的默认父工程 -->
	<!-- Spring Boot 父工程 -->
	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>2.3.1.RELEASE</version>
	</parent>
```

#### 7.2 修改pom.xml

添加项目所需的依赖，关于什么依赖什么作用代码中有注释

```xml
 <dependencies>
      <!-- 导入web支持：SpringMVC开发支持，Servlet相关的程序 -->
      <!-- web支持，SpringMVC， Servlet支持等 -->
      <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
      </dependency>
      <!-- 导入thymeleaf依赖 -->
      <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-thymeleaf</artifactId>
        <version>2.3.1.RELEASE</version>
      </dependency>
      <!-- shiro与spring整合依赖 -->
      <dependency>
        <groupId>org.apache.shiro</groupId>
        <artifactId>shiro-spring</artifactId>
        <version>1.4.0</version>
      </dependency>
      <!-- 导入mybatis相关的依赖 -->
      <dependency>
        <groupId>com.alibaba</groupId>
        <artifactId>druid</artifactId>
        <version>1.1.20</version>
      </dependency>
      <dependency>
        <groupId>com.mchange</groupId>
        <artifactId>c3p0</artifactId>
        <version>0.9.5.5</version>
      </dependency>
      <!-- mysql -->
      <dependency>
        <groupId>mysql</groupId>
        <artifactId>mysql-connector-java</artifactId>
      </dependency>
      <!-- SpringBoot的Mybatis启动器 -->
      <dependency>
        <groupId>org.mybatis.spring.boot</groupId>
        <artifactId>mybatis-spring-boot-starter</artifactId>
        <version>2.1.1</version>
      </dependency>
      <dependency>
        <groupId>org.thymeleaf</groupId>
        <artifactId>thymeleaf-spring5</artifactId>
        <version>3.0.11.RELEASE</version>
      </dependency>
      <!-- thymel对shiro的扩展坐标 -->
      <dependency>
        <groupId>com.github.theborakompanioni</groupId>
        <artifactId>thymeleaf-extras-shiro</artifactId>
        <version>2.0.0</version>
      </dependency>
  </dependencies>

  <build>
      <!--解决项目运行后mapper.xml文件找不到情况-->
      <resources>
          <resource>
              <directory>src/main/java</directory>
              <includes>
                  <include>**/*.xml</include>
              </includes>
          </resource>
      </resources>
  </build>
```

#### 7.3 编写application.yml

在resources文件下创建application.yml配置文件，添加访问路径以及Mybatis框架需要的数据源信息

```yml
## 端口号  上下文路径
server:
  port: 9999
  servlet:
    context-path: /shiro

## 数据源配置
spring:
  datasource:
    type: com.mchange.v2.c3p0.ComboPooledDataSource
    driver-class-name: com.mysql.cj.jdbc.Driver
    url: jdbc:mysql://127.0.0.1:3306/数据库名称?useUnicode=true&characterEncoding=utf8&serverTimezone=GMT%2B8
    username: 数据库用户名
    password: 数据库密码
```

#### 7.4 测试项目

##### 7.4.1  编写Controller层

```java
package com.test.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * @author shi_meng_yong
 * @date 2020/6/28 18:13
 */
@Controller
public class UserController {

    /**
     * 测试方法
     */
    @RequestMapping("/hello")
    @ResponseBody
    public String test(){
        System.out.println("UserController.test()--项目测试成功");
        return "ok";
    }
    /**
     * 测试thymeleaf
     */
    @RequestMapping("/testThymeleaf")
    public String testThymeleaf(Model model){
        //把数据存入model
        model.addAttribute("name", "测试testThymeleaf");
        //返回test.html
        return "test";
    }
}
```



##### 7.4.2  编写spring boot启动类

```java
package com.test;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * SpringBoot启动类
 * @author shi_meng_yong
 * @date 2020/6/28 18:18
 *
 */
@SpringBootApplication
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
```



##### 7.4.3  创建test.html页面

```html
<!DOCTYPE html>
<html xmlns:th="http://www.w3.org/1999/xhtml">
<head>
    <meta charset="UTF-8">
    <title>测试Thymeleaf的使用</title>
</head>
<body>
<h3 th:text="${name}"></h3>
</body>
</html>
```

##### 7.4.4 测试

###### 测试Thymleaf：

![image-20200628182716429](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20200628182716429.png)

###### 测试Controller接口：

![image-20200628182732668](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20200628182732668.png)

![image-20200628182755161](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20200628182755161.png)

#### 7.5 创建User类

用于封装登录用户信息，对应数据库中的user表所建

```java
package com.test.vo;

/**
 * @author shi_meng_yong
 * @date 2020/6/28 18:32
 */
public class User {
    private Integer id;//用户ID
    private String name;//用户名
    private String password;//用户密码
    private String perms;//用户权限值

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getPerms() {
        return perms;
    }

    public void setPerms(String perms) {
        this.perms = perms;
    }
}

```

#### 7.6  Service层

##### 7.6.1 UserService接口：

定义两个方法，用于shiro认证

```java
package com.test.service;

import com.test.vo.User;

/**
 * @author shi_meng_yong
 * @date 2020/6/28 18:34
 */
public interface UserService {

     User findByName(String name);//根据用户查询User对象

     User findById(Integer id);//根据用户ID查询User对象
}

```

##### 7.6.2 UserMapper接口

使用Mybatis框架，提供操作DB方法供Service层调用，在启动类中添加@MapperScan("com.test.mapper")

```java
package com.test.mapper;

import com.test.vo.User;

/**
 * @author shi_meng_yong
 * @date 2020/6/28 18:41
 */
public interface UserService {
    //用户名查询User
     User findByName(String name);
    //ID查询User
     User findById(Integer id);
}

```

##### 7.6.3 UserServiceImpl 类

实现UserService接口，实现其方法

```JAVA
package com.test.service.impl;

import com.test.mapper.UserMapper;
import com.test.service.UserService;
import com.test.vo.User;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * @author shi_meng_yong
 * @date 2020/6/28 18:35
 */
public class UserServiceImpl implements UserService {

    @Autowired
    private UserMapper userMapper;

    /**
     * 用户名查询User
     * @param name
     * @return
     */
    @Override
    public User findByName(String name) {
        return userMapper.findByName(name);
    }

    /**
     * 用户ID查询User
     * @param id
     * @return
     */
    @Override
    public User findById(Integer id) {
        return userMapper.findById(id);
    }
}

```

##### 7.6.4 UserMapper.xml

在resources下创建mappers文件夹创建UserMapper.xml与UserMapper接口配对

注意文件内关于路径信息，正确使用Mybatis

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
        PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
        "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<!-- 该文件存放CRUD的sql语句 -->
<mapper namespace="com.test.mapper.UserMapper">

    <select id="findByName" parameterType="string" resultType="com.test.vo.User">
        SELECT 	id,
        NAME,
        PASSWORD
        FROM
        user where name = #{value}
    </select>

    <select id="findById" parameterType="int" resultType="com.test.vo.User">
        SELECT 	id,
        NAME,
        PASSWORD,
        perms
        FROM
        user where id = #{value}
    </select>
</mapper>
```

在application.yml添加Mybatis配置信息

```yml
## mybatis 配置
mybatis:
  mapper-locations: classpath:/mappers/*.xml
  type-aliases-package: com.test.vo;com.test.mapper
  configuration:
    map-underscore-to-camel-case: true
```



#### 7.7 自定义Realm

创建UserRealm类供SecurityManager连接

```java
package com.smy.shiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;

import com.smy.vo.User;
import com.smy.service.UserService;

/**
 * 自定义Realm
 * （1）AuthenticatingRealm：shiro中的用于进行认证的领域，实现doGetAuthentcationInfo方法实现用户登录时的认证逻辑；
 * （2）AuthorizingRealm：shiro中用于授权的领域，实现doGetAuthrozitionInfo方法实现用户的授权逻辑，AuthorizingRealm继承了AuthenticatingRealm，
 * 所以在实际使用中主要用到的就是这个AuthenticatingRealm类；
 * （3）AuthenticatingRealm、AuthorizingRealm这两个类都是shiro中提供了一些线程的realm接口
 * （4）在与spring整合项目中，shiro的SecurityManager会自动调用这两个方法，从而实现认证和授权，可以结  合shiro的CacheManager将认证和授权信息保存在缓存中，这样可以提高系统的处理效率。    
 *
 */
public class UserRealm extends AuthorizingRealm{

	@Autowired
	private UserService userSerivce;

	public UserRealm() {
	}

	/**
	 * 执行认证逻辑
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken arg0) throws AuthenticationException {
		System.out.println("执行认证逻辑");

		//编写shiro判断逻辑，判断用户名和密码
		//1.判断用户名  token中的用户信息是登录时候传进来的
		UsernamePasswordToken token = (UsernamePasswordToken)arg0;

		User user = userSerivce.findByName(token.getUsername());

		if(user==null){
			//用户名不存在
			return null;//shiro底层会抛出UnKnowAccountException
		}

		//2.判断密码
		//第二个字段是user.getPassword()，注意这里是指从数据库中获取的password。第三个字段是realm，即当前realm的名称。
		//这块对比逻辑是先对比username，但是username肯定是相等的，所以真正对比的是password。
		//从这里传入的password（这里是从数据库获取的）和token（filter中登录时生成的）中的password做对比，如果相同就允许登录，
		// 不相同就抛出IncorrectCredentialsException异常。
		//如果认证不通过，就不会执行下面的授权方法了
		return new SimpleAuthenticationInfo(user,user.getPassword(),"");
	}

	/**
	 * 执行授权逻辑
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection arg0) {

	    //doGetAuthorizationInfo方法可能会执行多次，权限判断次数多少，就会执行多少次
		System.out.println("执行授权逻辑");
		
		//给资源进行授权
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		
		//到数据库查询当前登录用户的授权字符串
		//获取当前登录用户
		Subject subject = SecurityUtils.getSubject();
		User user = (User)subject.getPrincipal();
		User dbUser = userSerivce.findById(user.getId());
		
		info.addStringPermission(dbUser.getPerms());
		
		return info;
	}
}

```

#### 7.8 自定义Shiro的配置类

 Shiro的配置类总共四个方法，注入Bean容器，提供项目使用

##### 7.8.1 创建ShiroFilterFactoryBean

shiro的权限管理主要是通过内置过滤进行配置处理

```java
/**
	 * 创建ShiroFilterFactoryBean
	 */
	@Bean
	public ShiroFilterFactoryBean getShiroFilterFactoryBean(@Qualifier("securityManager")DefaultWebSecurityManager securityManager){

		ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();

		//设置安全管理器
		shiroFilterFactoryBean.setSecurityManager(securityManager);

		//添加Shiro内置过滤器
		/**
		 * Shiro内置过滤器，可以实现权限相关的拦截器
		 *    常用的过滤器：
		 *       anon: 无需认证（登录）可以访问
		 *       authc: 必须认证才可以访问
		 *       user: 如果使用rememberMe的功能可以直接访问
		 *       perms： 该资源必须得到资源权限才可以访问
		 *       role: 该资源必须得到角色权限才可以访问
		 */
		Map<String,String> filterMap = new LinkedHashMap<String,String>();
	
		filterMap.put("/testThymeleaf", "anon");
		//放行login.html页面
		filterMap.put("/login", "anon");

		//授权过滤器
		//注意：当前授权拦截后，shiro会自动跳转到未授权页面
		//perms括号中的内容是权限的值
		filterMap.put("/add", "perms[user:add]");
		filterMap.put("/update", "perms[user:update]");
		filterMap.put("/*","perms[user:*]");
		filterMap.put("/*", "authc");

		//修改调整的登录页面
		shiroFilterFactoryBean.setLoginUrl("/toLogin");
		//设置未授权提示页面
		shiroFilterFactoryBean.setUnauthorizedUrl("/noAuth");
		
		shiroFilterFactoryBean.setFilterChainDefinitionMap(filterMap);

		return shiroFilterFactoryBean;
	}
```

##### 7.8.2 创建DefaultWebSecurityManager

创建SecurityManager安全管理器，关联Realm

```java
/**
	 * 创建DefaultWebSecurityManager
	 *
	 * 里面主要定义了登录，创建subject，登出等操作
	 */
	@Bean(name="securityManager")
	public DefaultWebSecurityManager getDefaultWebSecurityManager(@Qualifier("userRealm")UserRealm userRealm){
		DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
		//关联realm
		securityManager.setRealm(userRealm);
		return securityManager;
	}
```

##### 7.8.3 创建Realm

关联自定义的UserRealm

```java
/**
	 * 创建Realm
	 */
	@Bean(name="userRealm")
	public UserRealm getRealm(){
		return new UserRealm();
	}
```

##### 7.8.4 配置ShiroDialect

```java
/**
	 * 配置ShiroDialect，用于thymeleaf和shiro标签配合使用
	 */
	@Bean
	public ShiroDialect getShiroDialect(){
		return new ShiroDialect();
	}
```

#### 7.9 设计项目页面

在resources下创建templates文件夹用存放项目所需要的html

##### 7.9.1 index.html

使用shiro与thymleaf的标签比对后端传来的信息权限比对

```html
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.w3.org/1999/xhtml" xmlns:shiro="http://www.w3.org/1999/xhtml">
<html>
<head>
<meta charset="UTF-8">
<title>首页</title>
</head>
<body>
    <!-- 获取后台传送的name值  -->
<h3 th:text="${name}"></h3>

<hr/>
<!-- 判断当前登录用户是否拥有user:add权限 有才显示<div>中的内容 -->
<div shiro:hasPermission="user:add">
进入用户添加功能： <a href="add">用户添加</a><br/>
</div>
<!--判断用户是否拥有user:update权限，有的话，才显示<div>中的内容-->
<div shiro:hasPermission="user:update">
进入用户更新功能： <a href="update">用户更新</a><br/>
</div>
<div>
    <a href="toLogin">登录</a>
</div>
<div>
    <a href="logout">注销</a>
</div>
</body>
</html>
```

##### 7.9.2 login.html

登录页面，输入用户名、密码传到后台执行登录操作

```html
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.w3.org/1999/xhtml">
<html>
<head>
<meta charset="UTF-8">
<title>登录页面</title>
</head>
<body>
<h3>登录</h3>
    <!-- 登录提示信息 -->
<h3 th:text="${msg}" style="color: red"></h3>

<form method="post" action="login">
	用户名:<input type="text" name="name"/><br/>
	密码：<input type="password" name="password"/><br/>
	<input type="submit" value="登录"/>
</form>
</body>
</html>
```

##### 7.9.3 noAuth.html

如果用户所访问页面未被授权则跳转到本页面

```html
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>未授权提示页面</title>
</head>
<body>
亲，你未经授权访问该页面
</body>
</html>
```

##### 7.9.4 add.html

用户添加页面

```html
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>用户添加页面</title>
</head>
<body>
用户添加
</body>
</html>
```

##### 7.9.5 update.html

用户修改页面

```html
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>用户更新页面</title>
</head>
<body>
用户更新
</body>
</html>
```

#### 7.10 编写Controller层

添加用户登录、用户退出、用户添加、用户修改、未授权跳转等方法

##### 7.10.1 用户登录

重点！登录业务逻辑在上面有源代码分析

```java
/**
     * 用户登录业务逻辑
     */
    @RequestMapping("/login")
    public String login(String name,String password,Model model){
        System.out.println("name="+name);//打印当前登录用户名
        /**
         * 使用Shiro编写认证操作
         */
        //1.获取Subject  -- 获取当前登录用户
        Subject subject = SecurityUtils.getSubject();

        //2.封装用户数据  创建用户名/密码验证Token（Web 应用中即为前台获取的用户名/密码
        UsernamePasswordToken token = new UsernamePasswordToken(name,password);

        //3.执行登录方法
        try {
            subject.login(token);
            //登录成功
            //跳转到首页
            return "redirect:/index";
        } catch (UnknownAccountException e) {
            //e.printStackTrace();
            //登录失败:用户名不存在，UnknownAccountException是Shiro抛出的找不到用户异常
            model.addAttribute("msg", "用户名不存在");
            return "login";
        }catch (IncorrectCredentialsException e) {
            //e.printStackTrace();
            //登录失败:密码错误，IncorrectCredentialsException是Shiro抛出的密码错误异常
            model.addAttribute("msg", "密码错误");
            return "login";
        }
    }

```



##### 7.10.2 用户退出

用户退出后执行subject的logout会注销认证信息

```java
    /**
     * 用户退出
     * @return
     * @throws Exception
     */
    @RequestMapping("/logout")
    public String logout() throws Exception{
        //获取当前用户
        Subject subject = SecurityUtils.getSubject();
        //执行注销功能
        subject.logout();
        //重定向到首页
        return "redirect:/index";
    }
```



##### 7.10.3 其它方法

```java
    /**
     * 用户添加
     * @return
     */
    @RequestMapping("/user/add")
    public String add(){
        return "/user/add";
    }

    /**
     * 用户修改
     * @return
     */
    @RequestMapping("/user/update")
    public String update(){
        return "/user/update";
    }

    /**~~~~~~****````****~~~~~~
     * 跳转登录页面
     * @return
     */
    @RequestMapping("/toLogin")
    public String toLogin(){
        return "/login";
    }

    /**
     * 跳转未授权页面
     * @return
     */
    @RequestMapping("/noAuth")
    public String noAuth(){
        return "/noAuth";
    }
```

#### 7.11 运行项目

输入相应的用户名和密码执行登录操作

##### 7.11.1 测试用户名不存在

##### 7.11.2 测试密码错误

##### 7.11.3 测试授权

登录成功进入首页，显示拥有的权限，没有的不显示

###### 测试拥有所有权限用户：

我们只设置用户添加和更新操作，看到均已显示

###### 测试只有更新权限用户：

##### 7.11.4 测试退出

点击会退出返回到登录页面，并销毁认证信息

## 结束