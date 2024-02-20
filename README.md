## 项目介绍
餐掌柜是专门为餐饮企业（餐厅、饭店）定制的一款软件产品，包括 系统管理后台 和 小程序端应用 两部分。其中系统管理后台主要提供给餐饮企业内部员工使用，可以对餐厅的分类、菜品、套餐、订单、员工等进行管理维护，对餐厅的各类数据进行统计。小程序端主要提供给消费者使用，可以在线浏览菜品、添加购物车、下单、支付、催单等。

### 技术选型

![](./image/Snipaste_2024-02-20_18-32-57.png)

#### 网关层
Nginx是一个服务器，主要用来作为Http服务器，部署静态资源，访问性能高。在Nginx中还有两个比较重要的作用： 反向代理和负载均衡， 在进行项目部署时，要实现Tomcat的负载均衡，就可以通过Nginx来实现。

#### 应用层

SpringBoot： 快速构建Spring项目, 采用 "约定优于配置" 的思想, 简化Spring项目的配置开发。

SpringMVC：SpringMVC是spring框架的一个模块，springmvc和spring无需通过中间整合层进行整合，可以无缝集成。

Spring Task:  由Spring提供的定时任务框架。

httpclient:  主要实现了对http请求的发送。

Spring Cache:  由Spring提供的数据缓存框架

JWT:  用于对应用程序上的用户进行身份验证的标记。

阿里云OSS:  对象存储服务，在项目中主要存储文件，如图片等。

Swagger： 可以自动的帮助开发人员生成接口文档，并对接口进行测试。

POI:  封装了对Excel表格的常用操作。

WebSocket: 一种通信网络协议，使客户端和服务器之间的数据交换更加简单，用于项目的来单、催单功能实现。

#### 数据层

MySQL： 关系型数据库, 本项目的核心业务数据都会采用MySQL进行存储。

Redis： 基于key-value格式存储的内存数据库, 访问速度快, 经常使用它做缓存。

Mybatis： 本项目持久层将会使用Mybatis开发。

pagehelper:  分页插件。

spring data redis:  简化java代码操作Redis的API。

#### 工具

git: 版本控制工具, 在团队协作中, 使用该工具对项目中的代码进行管理。

maven: 项目构建工具。

junit：单元测试工具，开发人员功能实现完毕后，需要通过junit对功能进行单元测试。

postman:  接口测工具，模拟用户发起的各类HTTP请求，获取对应的响应结果。



## 启动流程

#### 启动Ngnix

资料->day01->前端运行环境->ngnix

浏览器输入登陆端口：http://localhost:80

![](./image/Snipaste_2024-02-20_21-22-22.png)

#### 启动IDEA

sky-take-out -> sky-server -> SkyApplication

![](image/Snipaste_2024-02-20_21-24-54.png)

## Q&A

####  1.什么是Ngnix反向代理,为什么使用Ngnix反向代理?

**nginx 反向代理**，就是将前端发送的动态请求由 nginx 转发到后端服务器

- 提高访问速度

  因为nginx本身可以进行缓存，如果访问的同一接口，并且做了数据缓存，nginx就直接可把数据返回，不需要真正地访问服务端，从而提高访问速度。

- 进行负载均衡

  所谓负载均衡,就是把大量的请求按照我们指定的方式均衡的分配给集群中的每台服务器。

- 保证后端服务安全

  因为一般后台服务地址不会暴露，所以使用浏览器不能直接访问，可以把nginx作为请求访问的入口，请求到达nginx后转发到具体的服务中，从而保证后端服务的安全。

#### 2.怎么进行的前后端分离开发?

将管理端的接口json文档导入YApi平台

![](image/Snipaste_2024-02-20_22-05-59.png)

#### 3.怎么进行的业务开发?

以新增员工为例:

**打开YApi查看接口路径**

![](image/Snipaste_2024-02-20_22-09-58.png)

**查看请求参数,设计DTO类**

![](image/Snipaste_2024-02-20_22-10-37.png)

![](image/Snipaste_2024-02-20_22-11-29.png)

**在Controller中创建新增员工方法,同时编写Service,Mapper层代码**

![](image/Snipaste_2024-02-20_22-12-20.png)

#### 4.说说Controller,Service和Mapper

Controller负责处理HTTP请求，Service负责执行业务逻辑，而Mapper负责执行数据持久化操作

**Controller(控制器)**

在Spring Boot中，控制器通常由`@Controller`或`@RestController`注解标记，它们处理HTTP请求，并将请求分派到适当的服务层（Service）来执行业务逻辑.控制器通常包含一系列请求处理方法（handler methods），这些方法使用`@RequestMapping`或其他类似注解来映射URL和HTTP请求类型到方法上。在处理请求时，控制器通常会调用服务层的方法来执行业务逻辑，并将结果返回给客户端。

**Service(服务)**

服务层通常由`@Service`注解标记，以便Spring能够自动识别并注入到控制器或其他服务中。服务层可以包含多个方法，每个方法执行特定的业务逻辑。在典型的应用程序中，服务层可以调用持久层（Mapper）来访问数据库或执行其他数据持久化操作。

**Mapper（映射器）**

Mapper负责将Java对象映射到数据库表中的记录，并执行数据库查询、插入、更新和删除等操作。在MyBatis中，Mapper通常是一个接口，包含一组与数据库交互的方法，每个方法对应一个SQL查询或更新操作。

#### 5.使用JWT令牌进行用户身份校验

![](image/Snipaste_2024-02-20_22-58-19.png)

**认证流程**

- 前端通过Web表单将自己的用户名和密码发送到后端的接口。该过程一般是HTTP的POST请求。建议的方式是通过SSL加密的传输(https协议)，从而避免敏感信息被嗅探。
- 后端核对用户名和密码成功后，将用户的id等其他信息作为JWT Payload(负载)，将其与头部分别进行Base64编码拼接后签名，形成一个JWT(Token)。
- 后端将JWT字符串作为登录成功的返回结果返回给前端。前端可以将返回的结果保存在localStorage（浏览器本地缓存）或sessionStorage（session缓存）上，退出登录时前端删除保存的JWT即可。
- 前端在每次请求时将JWT放入HTTP的Header中的Authorization位。(解决XSS和XSRF问题）HEADER
  后端检查是否存在，如存在验证JWT的有效性。例如，检查签名是否正确﹔检查Token是否过期;检查Token的接收方是否是自己(可选）
- 验证通过后后端使用JWT中包含的用户信息进行其他逻辑操作，返回相应结果。
  

**程序中拦截器的应用**

1.自定义Jwt拦截器

```java
@Component
@Slf4j
public class JwtTokenAdminInterceptor implements HandlerInterceptor {

    @Autowired
    private JwtProperties jwtProperties;

    /**
     * 校验jwt
     *
     * @param request
     * @param response
     * @param handler
     * @return
     * @throws Exception
     */
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        //判断当前拦截到的是Controller的方法还是其他资源
        if (!(handler instanceof HandlerMethod)) {
            //当前拦截到的不是动态方法，直接放行
            return true;
        }

        //1、从请求头中获取令牌
        String token = request.getHeader(jwtProperties.getAdminTokenName());

        //2、校验令牌
        try {
            log.info("jwt校验:{}", token);
            Claims claims = JwtUtil.parseJWT(jwtProperties.getAdminSecretKey(), token);
            Long empId = Long.valueOf(claims.get(JwtClaimsConstant.EMP_ID).toString());
            log.info("当前员工id：", empId);
            BaseContext.setCurrentId(empId);
            //3、通过，放行
            return true;
        } catch (Exception ex) {
            //4、不通过，响应401状态码
            response.setStatus(401);
            return false;
        }
    }
}
```

2.在WebMvcConfiguration中注册拦截器

```java
@Configuration
@Slf4j
public class WebMvcConfiguration extends WebMvcConfigurationSupport {

    @Autowired
    private JwtTokenAdminInterceptor jwtTokenAdminInterceptor;
    @Autowired
    private JwtTokenUserInterceptor jwtTokenUserInterceptor;
    /**
     * 注册自定义拦截器
     *
     * @param registry
     */
    protected void addInterceptors(InterceptorRegistry registry) {
        log.info("开始注册自定义拦截器...");
        registry.addInterceptor(jwtTokenAdminInterceptor)
                .addPathPatterns("/admin/**")
                .excludePathPatterns("/admin/employee/login");
        registry.addInterceptor(jwtTokenUserInterceptor)
                .addPathPatterns("/user/**")
                .excludePathPatterns("/user/user/login")
                .excludePathPatterns("/user/shop/status");
    }

```

