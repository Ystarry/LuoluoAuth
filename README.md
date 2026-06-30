# luoluo-auth

`luoluo-auth` is a NestJS authentication library that provides session management, JWT/random token strategies, RBAC, OAuth2/OIDC, SSO, API signature verification, and rate limiting. It is inspired by Java's Sa-Token and aims to keep common auth patterns in one place without pulling in too many external dependencies.

## Features

- **JWT Token**: HS256 signature with configurable expiration
- **Session Storage**: Built-in `MemoryStore` (LRU eviction) and `RedisStore` (Set-based index with zombie cleanup)
- **Login Policies**: `single`, `multiple`, and `mutual-exclusion`, with `maxSameDeviceSessions` support
- **RBAC**: Role and permission based access control with wildcard support (e.g. `user:*`)
- **Session Management**: Force logout, kick user, ban user, identity switch, sliding renewal, online session query, login history query
- **Secondary Auth**: Sensitive-operation verification with independent TTL
- **SSO**: Cross-domain single sign-on with multi-source token extraction (header / cookie / query)
- **OAuth2 / OIDC**: `authorization_code`, `password`, `client_credentials`, `refresh_token` grants with **Refresh Token Rotation + Reuse Detection**; supports PKCE, public clients, OIDC Discovery, and ID Token
- **Microservice Auth**: gRPC / TCP metadata token extraction, RPC IP whitelist, automatic token propagation interceptor
- **API Signature**: HMAC-SHA256 signature verification with timestamp & nonce replay protection, Redis-based nonce deduplication with in-memory LRU fallback, and timing-safe comparison
- **Login Rate Limiting**: IP + account dual-dimensional rate limiting with Redis / memory backends
- **Device Fingerprint**: Tokens can be bound to IP + User-Agent, with strict / warn modes
- **Distributed Lock**: Race-condition protection for high-concurrency logins, Redis (Lua-safe release) and in-memory implementations
- **Cookie Mode**: Supports both `Authorization: Bearer` header and Cookie token sources, with automatic Cookie expiration refresh
- **Remember Me**: Distinguishes temporary and long-term sessions
- **Multi-Account Switching**: Maintain multiple account login states on the same client, disabled by default, with `listAccounts` / `switchAccount`
- **Password Encoding**: Built-in BCrypt / Argon2 encoders with customizable parameters
- **Data Persistence Layer**: Abstract persistence interface with adapters for MySQL / PostgreSQL / Oracle / SQLite / MongoDB / in-memory
- **WebSocket Auth**: Token authentication for Socket.IO and native WebSocket
- **Unified Error Codes**: Module-segmented business error codes with i18n (Chinese / English)
- **Audit Logging**: Console / file / Redis storage backends

## Installation

```bash
npm install luoluo-auth ioredis jsonwebtoken @nestjs/config @nestjs/microservices @grpc/grpc-js
```

## Architecture

![Architecture Diagram](docs/项目架构图.png)

## Project Structure

```
src/
├── auth/                          # Core authentication module
│   ├── auth.module.ts             # AuthModule dynamic registration entry
│   ├── auth.service.ts            # Login, logout, session management, safe auth
│   ├── auth.guard.ts              # Global auth guard: JWT validation, roles & permissions
│   ├── auth.decorator.ts          # @RequireLogin, @RequireRoles, @RequirePermissions decorators
│   ├── auth.config.ts             # Default config and AuthFrameworkConfig types
│   ├── auth.filter.ts             # Unified authentication exception filter
│   ├── strategies/                # Token strategies
│   │   ├── jwt.strategy.ts        # JWT signing and verification
│   │   └── random-token.strategy.ts # UUID-v7 / ULID / random string token strategy
│   ├── stores/                    # Session store implementations
│   │   ├── memory-store.ts        # In-memory LRU session store
│   │   └── redis-store.ts         # Redis session store (Set index + zombie cleanup)
│   ├── permission/                # Permission engine
│   │   └── permission.engine.ts   # RBAC with wildcard matching
│   ├── signature/                 # API signature authentication
│   │   ├── signature.util.ts      # HMAC-SHA256 signature generation/verification
│   │   ├── signature.guard.ts     # Signature auth guard
│   │   └── nonce-store.ts         # Nonce deduplication (Redis / in-memory LRU fallback)
│   ├── audit/                     # Audit logging
│   │   └── audit.service.ts       # console / file / redis audit backends
│   ├── cookie/                    # Cookie mode
│   │   └── cookie.service.ts      # Cookie read/write and auto-refresh
│   ├── rate-limit/                # Login rate limiting
│   │   ├── memory-rate-limiter.ts # In-memory sliding-window / token-bucket
│   │   └── redis-rate-limiter.ts  # Redis distributed rate limiter
│   ├── distributed-lock/          # Distributed locks
│   │   ├── memory-distributed-lock.ts
│   │   └── redis-distributed-lock.ts
│   ├── persistence/               # Data persistence layer
│   │   ├── persistence.adapter.ts # Abstract persistence interface
│   │   ├── persistence.factory.ts # Adapter factory
│   │   ├── persistence.module.ts  # Dynamic module registration
│   │   └── adapters/              # Concrete storage adapters
│   │       ├── sql-persistence.adapter.ts
│   │       ├── mongodb-persistence.adapter.ts
│   │       └── memory-persistence.adapter.ts
│   ├── password/                  # Password encoding
│   │   └── password-encoder.ts    # BCrypt / Argon2 wrapper
│   ├── ws/                        # WebSocket authentication
│   │   └── ws-auth.guard.ts       # Socket.IO / native WS token auth
│   ├── i18n/                      # Internationalization
│   │   └── i18n.service.ts        # Chinese / English error-code i18n
│   ├── errors/                    # Exception hierarchy
│   │   ├── auth-error-code.ts
│   │   └── auth.exception.ts
│   ├── interfaces/                # Core interfaces
│   │   ├── session-store.interface.ts
│   │   ├── token-strategy.interface.ts
│   │   └── rate-limit.interface.ts
│   └── utils/                     # Utilities
│       └── token.util.ts          # Bearer token extraction
├── extras/                        # Optional extensions
│   ├── oauth2/                    # OAuth2 / OIDC authorization server
│   │   ├── client-store.ts        # OAuth2ClientStore interface + InMemoryOAuth2ClientStore
│   │   ├── redis-client-store.ts  # Redis-backed OAuth2 store (refresh token rotation)
│   │   ├── oauth2.controller.ts   # /oauth/authorize, /token, /userinfo endpoints
│   │   ├── oidc.controller.ts     # /.well-known/openid-configuration and ID Token
│   │   └── oauth2.module.ts       # OAuth2 dynamic module registration
│   ├── sso/                       # SSO single sign-on
│   │   ├── sso.service.ts
│   │   └── sso.module.ts
│   ├── microservice/              # Microservice authentication
│   │   ├── auth.interceptor.ts    # RPC token propagation interceptor
│   │   └── microservice.module.ts
│   ├── passport/                  # Passport adapter
│   │   └── passport.strategy.ts   # Passport-style verification adapter
│   └── admin/                     # Admin management API
│       └── admin.controller.ts    # Session / user / client management
├── index.ts                       # Public export barrel
├── app.module.ts                  # Sample root module
├── app.controller.ts
├── app.service.ts
└── main.ts                        # Sample bootstrap entry
```

## Quick Start

### 1. Synchronous Registration

```typescript
import { Module } from '@nestjs/common';
import { AuthModule } from 'luoluo-auth';

@Module({
  imports: [
    AuthModule.register({
      jwt: { secret: 'your-secret', expiresIn: '7d' },
      auth: { tokenTtl: 7 * 24 * 60 * 60 * 1000, loginPolicy: 'single' },
      useRedis: true,
      redisOptions: { host: 'localhost', port: 6379 },
    }),
  ],
})
export class AppModule {}
```

### 2. Asynchronous Registration

```typescript
import { Module } from '@nestjs/common';
import { AuthModule } from 'luoluo-auth';

@Module({
  imports: [
    AuthModule.registerAsync({
      useFactory: async (configService: ConfigService) => ({
        jwt: { secret: configService.get('AUTH_SECRET')!, expiresIn: '7d' },
        auth: {
          tokenTtl: configService.get('AUTH_TOKEN_TTL'),
          loginPolicy: 'single',
        },
        useRedis: configService.get('AUTH_REDIS_ENABLED') === 'true',
      }),
      inject: [ConfigService],
    }),
  ],
})
export class AppModule {}
```

### 3. ConfigService Registration

```typescript
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from 'luoluo-auth';

@Module({
  imports: [ConfigModule.forRoot({ isGlobal: true }), AuthModule.forConfig()],
})
export class AppModule {}
```

### 4. Global Guard and Filter

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

### 5. Usage in Controllers

```typescript
import { Controller, Get, Post } from '@nestjs/common';
import {
  RequireLogin,
  RequireRoles,
  RequirePermissions,
  RequireSafeAuth,
  AuthService,
} from 'luoluo-auth';

@Controller('user')
export class UserController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  async login() {
    const token = await this.authService.login('user123', 'web', ['user'], ['user:read']);
    return { token };
  }

  @Get('profile')
  @RequireLogin()
  @RequireRoles('admin', 'user')
  @RequirePermissions('user:read')
  async profile() {
    return { msg: 'success' };
  }

  @Get('transfer')
  @RequireSafeAuth()
  async transfer() {
    return { msg: 'transfer success' };
  }
}
```

## Core Features

### Login & Logout

```typescript
// Login: generate JWT token, handle old sessions based on policy
const token = await authService.login(userId, device, roles, permissions);

// Logout: delete the session associated with the token
await authService.logout(token);

// Validate token
const session = await authService.validateToken(token);
```

### Login Policies

| Policy             | Description                                                   |
| ------------------ | ------------------------------------------------------------- |
| `single`           | Only one active session per user; new login kicks the old one |
| `multiple`         | Multiple sessions allowed simultaneously                      |
| `mutual-exclusion` | Only one session per device type                              |

```typescript
AuthModule.register({
  auth: { loginPolicy: 'mutual-exclusion', tokenTtl: 3600000 },
});
```

### Session Management

```typescript
// Force logout a specific session
await authService.forceLogout(sessionId);

// Kick user (optionally by device)
await authService.kickUser(userId, 'web');

// Ban user (requires Redis)
await authService.banUser(userId, 3600); // Ban for 1 hour

// Switch identity
const newToken = await authService.switchIdentity(userId, targetUserId, device);

// Renew session
await authService.renewSession(sessionId);
```

### Secondary Authentication

```typescript
// Enable secondary auth (e.g. after SMS verification)
await authService.openSafeAuth(sessionId);

// Disable secondary auth
await authService.closeSafeAuth(sessionId);

// In controller
@Get('sensitive')
@RequireSafeAuth()
sensitiveOperation() {}
```

### Auto Renewal

When `autoRenew: true`, `AuthGuard` automatically calls `renewSession` when the token's remaining lifetime is less than 1/3 of the total TTL.

```typescript
AuthModule.register({
  auth: { autoRenew: true, tokenTtl: 3600000 },
});
```

## OAuth2 Authorization Server

Standard OAuth2 endpoints with four grant types, featuring built-in Refresh Token Rotation + Reuse Detection.

```typescript
import { Module } from '@nestjs/common';
import { OAuth2Module, OAuth2ClientStore } from 'luoluo-auth';

@Module({
  imports: [
    OAuth2Module.register({
      clientStore: new OAuth2ClientStore(),
    }),
  ],
})
export class AppModule {}
```

### Register Client

```typescript
const store = new OAuth2ClientStore();
store.registerClient({
  clientId: 'my-app',
  clientSecret: 'my-secret',
  redirectUris: ['http://localhost:3000/callback'],
  grants: ['authorization_code', 'refresh_token'],
  scopes: ['profile', 'email'],
});
```

### Endpoints

| Endpoint           | Method | Description               |
| ------------------ | ------ | ------------------------- |
| `/oauth/authorize` | GET    | Obtain authorization code |
| `/oauth/token`     | POST   | Exchange / refresh token  |
| `/oauth/userinfo`  | GET    | Get user info             |

### Refresh Token Rotation

- Each token refresh marks the old refresh token as `used`
- If a used refresh token is consumed again (reuse), the entire token family is revoked immediately
- Effectively prevents sustained abuse after refresh token leakage

## SSO Single Sign-On

```typescript
import { SsoModule } from 'luoluo-auth';

@Module({
  imports: [
    SsoModule.register({
      loginUrl: 'https://sso.example.com/login',
      tokenParamName: 'token',
      tokenStrategy: ['header', 'cookie', 'query'],
    }),
  ],
})
export class AppModule {}
```

## Microservice Authentication

### Server-side: Microservice Guard

```typescript
import { AuthGuard } from 'luoluo-auth';

app.useGlobalGuards(AuthGuard.forMicroservice());
```

Extracts token from gRPC metadata or TCP packets, with optional RPC IP whitelist validation.

### Client-side: Automatic Token Propagation

```typescript
import { MicroserviceAuthInterceptor } from 'luoluo-auth';

@UseInterceptors(MicroserviceAuthInterceptor)
export class MyController {}
```

## API Signature Authentication

Prevents request tampering and replay attacks.

```typescript
import { SignatureGuard } from 'luoluo-auth';

@Controller('api')
@UseGuards(SignatureGuard)
export class ApiController {}
```

Requests must include the following headers:

- `X-Signature`: HMAC-SHA256 signature (Base64)
- `X-Timestamp`: Request timestamp (ms)
- `X-Nonce`: Random string (replay protection)

Signature payload format:

```
METHOD\nPATH\nTIMESTAMP\nNONCE\nBODY
```

## Audit Logging

```typescript
AuthModule.register({
  audit: {
    enabled: true,
    storage: 'redis', // 'console' | 'file' | 'redis'
    logFilePath: './logs/audit.log',
  },
});
```

Automatically records the following actions: `login`, `logout`, `force_logout`, `kick`, `ban`, `switch_identity`, `renew`, `open_safe_auth`, `close_safe_auth`, `rpc_call`, `signature_auth`.

## Configuration Reference

```typescript
class AuthFrameworkConfig {
  token?: {
    secret: string;
    expiresIn?: string; // '1h', '7d', etc.
  };
  storage?: {
    useRedis?: boolean;
    redisOptions?: Record<string, unknown>;
    maxSize?: number; // MemoryStore max sessions, 0 = unlimited
  };
  loginPolicy?: {
    policy?: 'single' | 'multiple' | 'mutual-exclusion';
    tokenTtl?: number; // milliseconds
    autoRenew?: boolean;
    maxSameDeviceSessions?: number; // default 1
    rememberMeTtl?: number; // default 30 days
  };
  permission?: { enabled?: boolean };
  safeAuth?: {
    enabled?: boolean;
    ttl?: number; // default 30 minutes
  };
  sso?: {
    enabled?: boolean;
    loginUrl?: string;
    tokenParamName?: string;
    tokenStrategy?: ('header' | 'cookie' | 'query')[];
  };
  oauth2?: { enabled?: boolean };
  microservice?: {
    enabled?: boolean;
    rpcIpWhitelist?: string[];
  };
  audit?: {
    enabled?: boolean;
    storage?: 'console' | 'file' | 'redis';
    logFilePath?: string;
  };
  signature?: {
    enabled?: boolean;
    secret?: string;
    timestampTolerance?: number; // default 5 minutes
    headerName?: string;
    timestampHeader?: string;
    nonceHeader?: string;
  };
  rateLimit?: {
    enabled?: boolean;
    strategy?: 'sliding-window' | 'token-bucket';
    keyType?: 'ip' | 'user' | 'ip-user';
    windowSeconds?: number;
    maxRequests?: number;
    refillRate?: number;
    capacity?: number;
  };
  fingerprint?: {
    enabled?: boolean;
    strict?: boolean;
  };
  cookie?: {
    enabled?: boolean;
    name?: string;
    domain?: string;
    path?: string;
    httpOnly?: boolean;
    secure?: boolean;
    sameSite?: 'strict' | 'lax' | 'none';
    maxAge?: number; // seconds
  };
  distributedLock?: {
    enabled?: boolean;
    ttlMs?: number;
    retries?: number;
    retryDelayMs?: number;
  };
  multiAccount?: {
    enabled?: boolean;
    maxAccounts?: number;
  };
  randomToken?: {
    style: 'uuid-v7' | 'ulid' | 'random-32' | 'random-64' | 'random-128';
    prefix?: string;
  };
}
```

### Default Configuration

```typescript
const defaultConfig = {
  token: { secret: 'default-secret-change-me', expiresIn: '7d' },
  storage: { useRedis: false, maxSize: 0 },
  loginPolicy: { policy: 'single', tokenTtl: 604800000, autoRenew: false, maxSameDeviceSessions: 1, rememberMeTtl: 2592000000 },
  permission: { enabled: true },
  safeAuth: { enabled: false, ttl: 1800000 },
  sso: { enabled: false, loginUrl: '/auth/login', tokenParamName: 'token', tokenStrategy: ['header', 'cookie', 'query'] },
  oauth2: { enabled: false },
  microservice: { enabled: false, rpcIpWhitelist: [] },
  audit: { enabled: false, storage: 'console' },
  signature: { enabled: false, secret: 'default-signature-secret-change-me', timestampTolerance: 300000 },
  rateLimit: { enabled: false, strategy: 'sliding-window', keyType: 'ip-user', windowSeconds: 60, maxRequests: 10, refillRate: 1, capacity: 10 },
  fingerprint: { enabled: false, strict: false },
  cookie: { enabled: false, name: 'auth-token', path: '/', httpOnly: true, secure: true, sameSite: 'lax', maxAge: 604800 },
  distributedLock: { enabled: true, ttlMs: 5000, retries: 0, retryDelayMs: 50 },
  multiAccount: { enabled: false, maxAccounts: 5 },
};
```

## Decorators

| Decorator                                        | Description                                  |
| ------------------------------------------------ | -------------------------------------------- |
| `@RequireLogin()`                                | Requires authenticated user                  |
| `@RequireRoles('admin', 'user')`                 | Requires at least one of the specified roles |
| `@RequirePermissions('user:add', 'user:delete')` | Requires all specified permissions           |
| `@RequireSafeAuth()`                             | Requires secondary authentication            |
| `@RequireSignature()`                            | Requires API signature verification          |

## Comparison

### vs. Passport.js

Passport.js is the de facto authentication middleware framework for Node.js, with a Strategy-based mechanism supporting 500+ identity providers. The differences from luoluo-auth are mainly:

| Dimension | Passport.js | luoluo-auth |
| --- | --- | --- |
| Positioning | Authentication middleware framework | All-in-one NestJS authentication & authorization framework |
| Scope | Identity verification only | Authentication + authorization + session governance + security hardening |
| Ecosystem | 500+ strategies (Google, GitHub, SAML, OIDC, etc.) | Built-in JWT/random token, RBAC, OAuth2/OIDC, SSO, signature auth, rate limiting, audit logging |
| Session model | Usually stateless JWT or session cookie | Server-side session-centric, supports single/multiple/mutual-exclusion login, kick, ban, sliding renewal |
| NestJS integration | Wrapped via @nestjs/passport | Native dynamic module, inject directly |
| Extensibility | Pluggable strategies, mature community | Pluggable modules, Passport adapter to reuse part of the ecosystem |

**When to choose**

- Choose Passport.js if you need many third-party identity providers or the project is based on Express/Fastify.
- Choose luoluo-auth if you are in NestJS and need integrated session governance, RBAC, OAuth2 Server, SSO, API signature, etc.

### vs. Sa-Token (Java)

luoluo-auth is heavily inspired by Sa-Token in the Java ecosystem, aiming to bring Sa-Token's session governance philosophy to Node.js / NestJS:

| Dimension | Sa-Token (Java) | luoluo-auth |
| --- | --- | --- |
| Language / Runtime | Java / JVM | TypeScript / Node.js |
| Framework integration | Spring Boot / Spring Cloud | NestJS |
| Session model | Session-centric with distributed session support | Session-centric with Memory / Redis Store |
| Login policies | Single / multiple / mutual-exclusion login | Full port: single / multiple / mutual-exclusion |
| Token style | Random token by default, JWT extension supported | JWT by default, UUID-v7 / ULID / random string token supported |
| RBAC | Built-in role/permission and route interception | Built-in PermissionEngine + decorators |
| SSO / OAuth2 | Built-in Sa-Token-SSO, Sa-Token-OAuth2 | Built-in SsoModule, OAuth2Module |
| Microservices | Dubbo, Spring Cloud, etc. | gRPC / TCP via @nestjs/microservices |
| Type safety | Java generics | Native TypeScript, decorator metadata driven |
| Ecosystem maturity | Large community, many plugins | Emerging project, focused on NestJS ecosystem |

**When to choose**

- Choose Sa-Token if your stack is Java/Spring Boot.
- Choose luoluo-auth if your stack is Node.js/NestJS and you want Sa-Token-style session governance and permission system.

## Testing

```bash
# Run unit tests
npm test

# Run e2e tests
npm run test:e2e

# View coverage
npm run test:cov
```

Coverage thresholds are configured in `package.json` to prevent regression.

Current coverage: 33 unit test suites / 401 test cases plus 3 E2E suites / 14 cases, covering permission engine, auth service, memory/Redis session stores, OAuth2/OIDC, signature auth, nonce deduplication, rate limiting, device fingerprint, distributed lock, Cookie mode, Remember Me, multi-account switching, password encoding, WebSocket auth, data persistence layer, Passport adapter, Admin management API, module registration tests, and end-to-end authentication flows.

## API Documentation

Generate the API documentation with [Compodoc](https://compodoc.app/):

```bash
npm run docs:build
```

The generated documentation is written to the `documentation/` directory. To serve it locally:

```bash
npm run docs:serve
```

## Examples & Benchmarks

A complete sample application and load-test scripts are provided under [`examples/`](./examples).

### Run the sample app

```bash
npm run build
npm run example:start
```

The sample app starts on `http://localhost:3100` and demonstrates login, role/permission guards, session query, multi-account switching, and OAuth2/OIDC flows.

### Benchmark with Autocannon

```bash
# Start the sample app first, then run
npm run bench:autocannon
```

Benchmark environment: macOS, Node.js 22, 20/50 connections, 10s duration.

| Scenario             | Avg RPS  | p99 Latency |
| -------------------- | -------- | ----------- |
| Login                | 11,337   | 3 ms        |
| Protected route      | 18,697   | 4 ms        |
| OAuth2 password grant| 11,300   | 3 ms        |

### Benchmark with k6

[k6](https://k6.io/) must be installed separately.

```bash
# Start the sample app first, then run
npm run bench:k6
```

See [`examples/benchmarks/README.md`](./examples/benchmarks/README.md) for detailed configuration and per-scenario scripts.
