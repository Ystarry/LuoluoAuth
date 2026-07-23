# luoluo-auth 功能使用指南

本文档按功能维度说明 `luoluo-auth` 各能力如何在 NestJS 应用中配置与使用。示例中的 API 均来自框架源码，对应版本以当前仓库实现为准。

---

## 目录

1. [安装与模块注册](#1-安装与模块注册)
2. [JWT Token](#2-jwt-token)
3. [Session 存储](#3-session-存储)
4. [登录策略](#4-登录策略)
5. [RBAC 权限](#5-rbac-权限)
6. [会话管理](#6-会话管理)
7. [二级认证](#7-二级认证)
8. [SSO 单点登录](#8-sso-单点登录)
9. [OAuth2 / OIDC](#9-oauth2--oidc)
10. [微服务鉴权](#10-微服务鉴权)
11. [API 签名认证](#11-api-签名认证)
12. [登录限流](#12-登录限流)
13. [设备指纹](#13-设备指纹)
14. [分布式锁](#14-分布式锁)
15. [Cookie 模式](#15-cookie-模式)
16. [Remember Me](#16-remember-me)
17. [多账号切换](#17-多账号切换)
18. [密码加密](#18-密码加密)
19. [数据持久化层](#19-数据持久化层)
20. [WebSocket 认证](#20-websocket-认证)
21. [统一错误码与 i18n](#21-统一错误码与-i18n)
22. [审计日志](#22-审计日志)

---

## 1. 安装与模块注册

### 安装依赖

```bash
npm install luoluo-auth ioredis jsonwebtoken class-validator class-transformer bcrypt argon2 ulid @nestjs/config @nestjs/microservices @grpc/grpc-js
```

### 同步注册（AuthModuleOptions）

```typescript
import { Module } from '@nestjs/common';
import { AuthModule } from 'luoluo-auth';

@Module({
  imports: [
    AuthModule.register({
      jwt: { secret: 'your-secret-at-least-32-characters-long', expiresIn: '7d' },
      auth: {
        tokenTtl: 7 * 24 * 60 * 60 * 1000,
        loginPolicy: 'multiple',
        autoRenew: true,
        maxSameDeviceSessions: 3,
        rememberMeTtl: 30 * 24 * 60 * 60 * 1000,
      },
      useRedis: true,
      redisOptions: { host: 'localhost', port: 6379 },
    }),
  ],
})
export class AppModule {}
```

### 异步注册

```typescript
AuthModule.registerAsync({
  useFactory: async (configService: ConfigService) => ({
    jwt: { secret: configService.get('AUTH_SECRET')!, expiresIn: '7d' },
    auth: { loginPolicy: 'single' },
    useRedis: configService.get('AUTH_REDIS_ENABLED') === 'true',
  }),
  inject: [ConfigService],
});
```

### 基于 @nestjs/config 注册（AuthFrameworkConfig）

```typescript
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from 'luoluo-auth';

@Module({
  imports: [ConfigModule.forRoot({ isGlobal: true }), AuthModule.forConfig()],
})
export class AppModule {}
```

对应 `app.config.ts` / `.env`：

```typescript
export default () => ({
  auth: {
    token: { secret: 'your-secret', expiresIn: '7d' },
    storage: { useRedis: false, maxSize: 10000 },
    loginPolicy: { policy: 'multiple', tokenTtl: 604800000, autoRenew: true },
    cookie: { enabled: true, secure: false },
  },
});
```

> **注意**：框架默认 JWT 密钥为 `default-secret-change-me`，启动时必须显式替换，否则直接抛出致命错误。若启用 API 签名，签名密钥 `default-signature-secret-change-me` 也必须替换。

### 全局守卫与异常过滤器

```typescript
import { NestFactory } from '@nestjs/core';
import { AuthGuard, AuthExceptionFilter } from 'luoluo-auth';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalGuards(app.get(AuthGuard));
  app.useGlobalFilters(new AuthExceptionFilter());
  await app.listen(3000);
}
bootstrap();
```

---

## 2. JWT Token

`luoluo-auth` 默认使用 JWT（HS256）作为 Token 策略，由 [JwtStrategy](file:///src/auth/strategies/jwt.strategy.ts) 实现。

### 配置

```typescript
AuthModule.register({
  jwt: {
    secret: 'your-secret',  // 必填
    expiresIn: '2h',        // 支持 '1h' / '7d' / '30m' 等
  },
  auth: {
    tokenTtl: 2 * 60 * 60 * 1000, // 毫秒，与会话存储 TTL 保持一致
  },
});
```

### 登录生成 Token

```typescript
const token = await authService.login(
  'user-001',           // userId
  'web',                // device
  ['user'],             // roles
  ['user:read'],        // permissions
  req.ip,               // ip（设备指纹用）
  req.headers['user-agent'] as string, // userAgent
  res,                  // response（Cookie 模式用）
  false,                // rememberMe
);
```

客户端请求时携带：

```http
Authorization: Bearer <token>
```

### 随机 Token 策略（可选）

若不想使用 JWT，可切换为服务端随机 Token：

```typescript
AuthModule.register({
  randomToken: { style: 'uuid-v7', prefix: 'luoluo' },
  useRedis: true,
});
```

支持风格：`uuid-v7`、`ulid`、`random-32`、`random-64`、`random-128`。

---

## 3. Session 存储

### MemoryStore（默认）

```typescript
AuthModule.register({
  maxSize: 10000, // 最大会话数，0 表示不限制
});
```

### RedisStore

```typescript
AuthModule.register({
  useRedis: true,
  redisOptions: { host: 'localhost', port: 6379, db: 0 },
  // 或传入已有实例
  // redisClient: new Redis({...}),
});
```

RedisStore 内部使用 Set 索引维护用户-会话、设备-会话关系，并自动清理僵尸索引。

---

## 4. 登录策略

通过 `auth.loginPolicy` 配置。

| 策略 | 说明 |
| --- | --- |
| `single` | 同一用户仅保留一个活跃会话，新登录踢掉旧会话 |
| `multiple` | 允许多个会话共存 |
| `mutual-exclusion` | 同一 `device` 最多保留 `maxSameDeviceSessions` 个会话 |

```typescript
AuthModule.register({
  auth: {
    loginPolicy: 'mutual-exclusion',
    maxSameDeviceSessions: 2,
    tokenTtl: 3600000,
  },
});
```

---

## 5. RBAC 权限

### 装饰器

```typescript
import { Controller, Get } from '@nestjs/common';
import { RequireLogin, RequireRoles, RequirePermissions } from 'luoluo-auth';

@Controller('user')
export class UserController {
  @Get('profile')
  @RequireLogin()
  @RequireRoles('admin', 'user')         // 满足任一角色即可
  @RequirePermissions('user:read')       // 需全部满足
  profile() {
    return { msg: 'ok' };
  }
}
```

### 通配符

权限字符串支持通配符匹配，例如：

- `user:*` 可匹配 `user:read`、`user:write`
- `*` 匹配所有权限

通配符解析由 [PermissionEngine](file:///src/auth/permission/permission.engine.ts) 完成。

---

## 6. 会话管理

通过注入 `AuthService` 调用相关方法。

```typescript
constructor(private readonly authService: AuthService) {}

// 强制下线指定会话
await this.authService.forceLogout(sessionId);

// 踢出用户（可按设备）
await this.authService.kickUser('user-001', 'web');

// 封禁 / 解封用户（秒）
await this.authService.banUser('user-001', 3600);
await this.authService.unbanUser('user-001');

// 检查封禁状态
const banned = await this.authService.isBanned('user-001');

// 身份切换
const newToken = await this.authService.switchIdentity(
  'user-001', 'user-002', 'web', req.ip, req.headers['user-agent'] as string,
);

// 滑动续签
await this.authService.renewSession(sessionId);

// 在线会话查询
const sessions = await this.authService.getOnlineSessions('user-001');

// 登录历史查询
const history = await this.authService.getLoginHistory('user-001', 20);
```

---

## 7. 二级认证

敏感操作二次校验。

### 配置

```typescript
AuthModule.register({
  auth: { safeAuthTtl: 30 * 60 * 1000 }, // 默认 30 分钟
});
```

### 使用

```typescript
// 开启二级认证
await this.authService.openSafeAuth(sessionId);

// 关闭二级认证
await this.authService.closeSafeAuth(sessionId);

// 控制器中要求二级认证
@Get('transfer')
@RequireSafeAuth()
transfer() {
  return { msg: 'transfer success' };
}
```

---

## 8. SSO 单点登录

### 模块注册

```typescript
import { SsoModule } from 'luoluo-auth';

@Module({
  imports: [
    SsoModule.register({
      loginUrl: 'https://sso.example.com/login',
      tokenParamName: 'token',
      tokenStrategy: ['header', 'cookie', 'query'],
      codeExchangeHandler: async (code, state) => {
        // 调用外部 SSO 授权服务器换取用户信息
        return {
          userId: 'user-001',
          accessToken: '...',
          refreshToken: '...',
          roles: ['user'],
          permissions: ['user:read'],
        };
      },
    }),
  ],
})
export class AppModule {}
```

### 服务调用

```typescript
constructor(private readonly ssoService: SsoService) {}

// 构建带 Token 的 SSO 跳转表单（推荐，Token 放 POST body）
const form = this.ssoService.buildRedirectFormData(
  'https://client.example.com/callback',
  token,
);

// 处理回调
const user = await this.ssoService.handleCallback({ code, state });
```

---

## 9. OAuth2 / OIDC

### 模块注册

```typescript
import { OAuth2Module } from 'luoluo-auth';

@Module({
  imports: [
    OAuth2Module.register({
      clients: [
        {
          clientId: 'public-client',
          clientSecret: '', // 公开客户端可为空
          redirectUris: ['http://localhost:3100/oauth/callback'],
          grants: ['authorization_code', 'refresh_token'],
          scopes: ['profile', 'openid'],
          isPublic: true,
        },
        {
          clientId: 'confidential-client',
          clientSecret: 'client-secret',
          redirectUris: ['http://localhost:3100/oauth/callback'],
          grants: ['authorization_code', 'password', 'client_credentials', 'refresh_token'],
          scopes: ['profile', 'openid', 'email'],
        },
      ],
      userValidator: async (username, password) => {
        if (username === 'alice' && password === 'secret') {
          return {
            userId: 'user-alice',
            roles: ['user'],
            permissions: ['profile:read'],
          };
        }
        return null;
      },
      oidc: {
        issuer: 'http://localhost:3100',
        secret: 'oidc-secret-at-least-32-characters',
      },
    }),
  ],
})
export class AppModule {}
```

### 标准端点

| 端点 | 说明 |
| --- | --- |
| `GET /oauth/authorize` | 获取授权码，支持 PKCE（仅 S256） |
| `POST /oauth/token` | 换取 / 刷新 Token |
| `GET /oauth/userinfo` | 获取用户信息 |
| `GET /.well-known/openid-configuration` | OIDC Discovery（启用 oidc 后可用） |

### Refresh Token Rotation

每次刷新 Token 时，旧 refresh token 被标记为 `used`。若检测到已使用的 refresh token 被再次使用，立即吊销整个 Token Family。

---

## 10. 微服务鉴权

### 服务端：微服务守卫

```typescript
import { AuthGuard } from 'luoluo-auth';

app.useGlobalGuards(AuthGuard.forMicroservice());
```

支持从 gRPC metadata 或 TCP 数据包中提取 Token，并校验 RPC IP 白名单。

### 客户端：Token 透传拦截器

```typescript
import { UseInterceptors } from '@nestjs/common';
import { MicroserviceAuthInterceptor } from 'luoluo-auth';

@UseInterceptors(MicroserviceAuthInterceptor)
export class MyController {}
```

手动在异步链路中透传 Token：

```typescript
await MicroserviceAuthInterceptor.runWithToken(token, async () => {
  await this.myRpcService.callSomething();
});
```

---

## 11. API 签名认证

### 配置

```typescript
AuthModule.register({
  signature: {
    secret: 'your-signature-secret',
    timestampTolerance: 5 * 60 * 1000, // 默认 5 分钟
  },
});
```

### 控制器使用

```typescript
import { Controller, UseGuards } from '@nestjs/common';
import { SignatureGuard, RequireSignature } from 'luoluo-auth';

@Controller('api')
@UseGuards(SignatureGuard)
export class ApiController {}

// 或仅在单个接口启用
@Get('secure')
@RequireSignature()
secure() {}
```

### 请求头

```http
X-Signature: <base64-hmac-sha256>
X-Timestamp: 1710000000000
X-Nonce: <random-string>
```

### 签名原文

```
METHOD\nPATH\nTIMESTAMP\nNONCE\nBODY
```

示例生成：

```typescript
import { generateSignature } from 'luoluo-auth';

const signature = generateSignature(
  {
    method: 'POST',
    path: '/api/secure',
    timestamp: Date.now(),
    nonce: crypto.randomUUID(),
    body: JSON.stringify({ foo: 'bar' }),
  },
  'your-signature-secret',
);
```

---

## 12. 登录限流

### 配置

```typescript
AuthModule.register({
  auth: {
    rateLimit: {
      enabled: true,
      windowSeconds: 60,
      maxRequests: 10,
    },
  },
});
```

框架在 `AuthService.login` 时按 `ip` + `userId` 双维度限流。若启用 Redis，则使用 RedisRateLimiter；否则回退到内存实现。

---

## 13. 设备指纹

登录时传入 `ip` 和 `userAgent`，框架即可将其绑定到会话。

### 配置

```typescript
AuthModule.register({
  auth: {
    fingerprint: {
      enabled: true,
      strict: true, // true：不匹配直接拒绝；false：仅告警
    },
  },
});
```

### 登录时绑定

```typescript
const token = await this.authService.login(
  'user-001',
  'web',
  ['user'],
  ['user:read'],
  req.ip,
  req.headers['user-agent'] as string,
);
```

后续 `AuthGuard` / `WsAuthGuard` / `validateRpcToken` 都会校验当前请求的 IP / User-Agent 是否与登录时一致。

---

## 14. 分布式锁

用于防止高并发登录竞态条件。

### 配置

```typescript
AuthModule.register({
  auth: {
    distributedLock: {
      enabled: true,
      ttlMs: 5000,
      retries: 3,
      retryDelayMs: 50,
    },
  },
});
```

启用 Redis 时自动使用 [RedisDistributedLock](file:///src/auth/distributed-lock/redis-distributed-lock.ts)（Lua 脚本安全释放）；否则使用 [MemoryDistributedLock](file:///src/auth/distributed-lock/memory-distributed-lock.ts)。

### 独立使用

```typescript
constructor(@Inject('LOCK_SERVICE') private readonly lock: DistributedLock) {}

const token = await this.lock.acquire('my:key', 5000);
if (token) {
  try {
    // 执行业务逻辑
  } finally {
    await this.lock.release(token);
  }
}
```

---

## 15. Cookie 模式

### 配置

```typescript
AuthModule.register({
  cookie: {
    enabled: true,
    name: 'auth-token',
    path: '/',
    httpOnly: true,
    secure: true,      // 本地开发可显式设为 false
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60,
  },
});
```

### 登录写 Cookie

```typescript
const token = await this.authService.login('user-001', 'web', ['user'], [], req.ip, req.headers['user-agent'] as string, res);
```

### 读取来源

`AuthGuard` 会优先从 `Authorization: Bearer` 读取，未找到时回退到 Cookie。

### 自动刷新

Cookie 模式下，每次通过 Cookie 鉴权的请求都会：

1. 若 Token 策略支持 rotate，则轮换 Token；
2. 将新 Token 写回 Cookie，刷新过期时间。

---

## 16. Remember Me

登录时传入 `rememberMe: true`，Token 与会话使用 `rememberMeTtl`（默认 30 天）而非 `tokenTtl`。

```typescript
const token = await this.authService.login(
  'user-001', 'web', ['user'], [],
  req.ip, req.headers['user-agent'] as string, res,
  true, // rememberMe
);
```

配置长期过期时间：

```typescript
AuthModule.register({
  auth: { rememberMeTtl: 30 * 24 * 60 * 60 * 1000 },
});
```

---

## 17. 多账号切换

### 配置

```typescript
AuthModule.register({
  auth: {
    multiAccount: {
      enabled: true,
      maxAccounts: 5,
    },
  },
});
```

### 使用

```typescript
// 列出当前设备上已登录的账号
const accounts = await this.authService.listAccounts('device-001');

// 切换到目标账号
const targetToken = await this.authService.switchAccount(currentToken, 'user-002');
```

多账号切换默认关闭。启用后，同一 `device` 可保存多个账号的会话。

---

## 18. 密码加密

框架内置 BCrypt / Argon2 封装，实现 [PasswordEncoder](file:///src/auth/password/password-encoder.interface.ts) 接口。

```typescript
import { BcryptPasswordEncoder, Argon2PasswordEncoder } from 'luoluo-auth';

const encoder = new BcryptPasswordEncoder({ rounds: 12 });
// const encoder = new Argon2PasswordEncoder({ ... });

const hash = await encoder.hash('plain-password');
const ok = await encoder.verify('plain-password', hash);
```

> BCrypt 默认 cost factor 不低于 12。

---

## 19. 数据持久化层

用于保存业务实体（如用户、应用配置），与 Session 存储解耦。

### 注册

```typescript
import { PersistenceModule, SimplePersistenceAdapterFactory, MySqlPersistenceAdapter } from 'luoluo-auth';

@Module({
  imports: [
    PersistenceModule.register({
      factory: new SimplePersistenceAdapterFactory(),
      adapters: {
        User: new MySqlPersistenceAdapter(userSqlExecutor),
      },
    }),
  ],
})
export class AppModule {}
```

### 使用

```typescript
constructor(
  @Inject('PERSISTENCE_ADAPTER_FACTORY')
  private readonly factory: PersistenceAdapterFactory,
) {}

async createUser() {
  const adapter = this.factory.getAdapter<User>('User');
  await adapter.create('user-001', { name: 'Alice' });
  const user = await adapter.findById('user-001');
}
```

支持适配器：内存、MySQL、PostgreSQL、Oracle、SQLite、MongoDB。

---

## 20. WebSocket 认证

### 使用守卫

```typescript
import { UseGuards } from '@nestjs/common';
import { WsAuthGuard } from 'luoluo-auth';

@UseGuards(WsAuthGuard)
@WebSocketGateway()
export class EventsGateway {}
```

### Token 提取优先级

`WsAuthGuard` 按以下优先级提取 Token：

1. `handshake.auth.token`
2. `handshake.headers.authorization`
3. Cookie（启用 Cookie 模式时）
4. `handshake.query.token`
5. 原生 WS `upgradeReq` 的 headers / query

校验成功后，用户信息挂载到 `client.data.user`。

---

## 21. 统一错误码与 i18n

框架错误码定义于 [auth-error-code.ts](file:///src/auth/errors/auth-error-code.ts)，按模块分段。异常由 [AuthException](file:///src/auth/errors/auth.exception.ts) 抛出，[AuthExceptionFilter](file:///src/auth/auth.filter.ts) 统一处理。

### i18n 使用

`AuthExceptionFilter` 已内置 i18n 能力，会根据请求的 `Accept-Language` 头自动返回 `zh-CN` 或 `en` 错误描述：

```typescript
app.useGlobalFilters(new AuthExceptionFilter());
```

响应示例：

```json
{
  "code": 10001,
  "message": "未登录或登录已过期",
  "path": "/user/profile",
  "timestamp": "2026-07-09T12:00:00.000Z"
}
```

内置语言包：`zh-CN`、`en`。

---

## 22. 审计日志

### 配置

```typescript
AuthModule.register({
  audit: {
    enabled: true,
    storage: 'console', // 'console' | 'file' | 'redis'
    logFilePath: './logs/audit.log',
  },
});
```

### 自动记录的操作

`login`、`logout`、`force_logout`、`kick`、`ban`、`unban`、`switch_identity`、`renew`、`open_safe_auth`、`close_safe_auth`、`rpc_call`、`signature_auth` 等。

### 查询登录历史

```typescript
const history = await this.authService.getLoginHistory('user-001', 50);
```

---

## 附录：核心装饰器速查

| 装饰器 | 说明 |
| --- | --- |
| `@RequireLogin()` | 要求已登录 |
| `@RequireRoles('admin', 'user')` | 要求拥有指定角色之一 |
| `@RequirePermissions('user:add')` | 要求拥有全部指定权限 |
| `@RequireSafeAuth()` | 要求已开启二级认证 |
| `@RequireSignature()` | 要求 API 签名认证 |

---

## 附录：Admin 管理接口

[AdminController](file:///src/extras/admin/admin.controller.ts) 提供以下接口，需 `admin` / `super-admin` 角色或 `admin:*` / `*` 权限：

| 接口 | 说明 |
| --- | --- |
| `GET /admin/sessions?userId=xxx` | 查询在线会话 |
| `POST /admin/kick?userId=xxx` | 踢出用户 |
| `POST /admin/ban?userId=xxx&duration=3600` | 封禁用户 |
| `POST /admin/ban?userId=xxx&action=unban` | 解封用户 |
| `POST /admin/revoke?token=xxx` | 吊销 Token |
| `GET /admin/config` | 查看框架配置摘要 |
| `POST /admin/clients` | 注册 OAuth2 客户端 |
| `DELETE /admin/clients?clientId=xxx` | 删除 OAuth2 客户端 |
