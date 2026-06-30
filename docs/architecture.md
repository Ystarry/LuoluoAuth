# luoluo-auth 架构设计说明

这份文档记录我在设计这个库时的一些想法、取舍和踩过的坑。不是完整的产品白皮书，更多是给后续维护者（可能是我自己）看的备忘。

<br />

想法是从2025年8月开始的，10月才正式开始创建仓库，期间创建了很多个项目，最后在合并到一个，然后在测试一遍，最后在合并到现在的这个仓库，期间遇到过各种问题，不过还好当下ai快速发展，可以咨询解决，不用在c s d n找解决方案。

## 1. 为什么要做这个库

我是一个前端开发者，这两年越来越明显地感觉到：纯前端的边界在缩小，全栈是大概率的方向。但国内 Node.js 生态一直不算大，身边人聊到后端还是 Java、Go 居多，Node.js 在企业级项目里的存在感很弱。

接触到 NestJS 之后，我觉得它是个转折点——装饰器、依赖注入、模块化的写法很像 Java 的 Spring Boot，对前端出身的开发者来说，上手曲线没那么陡。后来又看到若依（RuoYi）和 RuoYi-Plus，特别是 RuoYi-Plus 里用了 Sa-Token 做认证，功能覆盖很全，接入也很轻。当时就想着：既然 NestJS 已经能把 Spring Boot 的开发体验搬到 Node.js 这边，那能不能也参照 Sa-Token，做一个 NestJS 版本的认证框架？

做这个库的初衷不是要做多么宏大的"企业级框架"，而是想：

- 给国内 Node.js / NestJS 开发者一个开箱即用的认证方案；
- 降低中小企业选 Node.js 做后端的门槛，至少认证这块不用自己从头拼；
- 推动一下国内 Node.js 生态的使用率，让这套技术栈在后端选型里更有竞争力。

一开始确实是想**对标 Sa-Token**，把它的核心能力在 NestJS 上复刻一遍。但做到后面觉得，既然已经决定自己做，就没必要和 Sa-Token 完全一样——**我要把它做得更好、更强、功能更多**。所以 luoluo-auth 的定位是"Sa-Token 精神的 NestJS 实现"：以 Sa-Token 为起点，参考它的功能边界和易用性，但代码风格、依赖注入、模块组织都按 NestJS 的方式来，同时在 Sa-Token 的基础上往微服务、OAuth2/OIDC、API 签名、多持久层这些方向继续扩展。

## 2. 为什么不用 Passport

Passport 生态很成熟，但我遇到几个问题：

- **策略和 Guard 耦合太紧**：换个 token 生成方式要改好几个地方；
- **Session 支持弱**：默认偏向无状态 JWT，想做服务端 session 要自己拼；
- **OAuth2 太复杂**：@nestjs/passport 做 OAuth2 服务端需要接一堆策略，很多项目其实只需要 authorization\_code + refresh\_token。

所以我自己抽象了 `TokenStrategy` 和 `SessionStore` 接口，让 JWT 和 Random Token 可以互换，Redis 和 Memory 可以互换。

## 3. 模块划分思路

```
src/auth          // 核心，不依赖任何 extras
src/extras/admin  // 管理接口，可选
src/extras/oauth2 // OAuth2/OIDC 服务端，可选
src/extras/sso    // SSO，可选
src/extras/microservice // 微服务，可选
```

核心模块（auth）只依赖：

- `@nestjs/common`、`@nestjs/config`
- `ioredis`（类型）
- `jsonwebtoken`、`argon2`/`bcrypt`、`class-validator` 等

extras 是可选扩展，按需引入。这样用户不会因为要用基础认证就被迫安装 gRPC 或 OAuth2 相关依赖。

## 4. 几个关键设计决策

### 4.1 Token 策略抽象

```typescript
interface TokenStrategy {
  generate(payload: TokenPayload): Promise<string>;
  validate(token: string): Promise<TokenPayload | null>;
  destroy?(token: string): Promise<void>;
}
```

JWT 是无状态的，Random Token 需要配合 SessionStore。通过同一个接口，上层 `AuthService` 不用关心底层是哪种实现。

### 4.2 SessionStore 接口

```typescript
interface SessionStore {
  set(sessionId: string, data: SessionData, ttl?: number): Promise<void>;
  get(sessionId: string): Promise<SessionData | null>;
  delete(sessionId: string): Promise<void>;
  // ...
}
```

Redis 实现用 Set 维护 userId -> sessionIds 的索引，方便做强制下线、互斥登录。Memory 实现用 Map + LRU + setTimeout 做 TTL，用于开发环境或无 Redis 场景。

### 4.3 把 @nestjs/\* 放到 peerDependencies

这是踩过大坑后的决定。早期放在 dependencies 里，用 `npm link` 测试 sample-app 时出现两个 `@nestjs/core` 实例，导致 Guard 注入失败、生命周期事件重复触发。放到 peerDependencies 后，由宿主应用决定具体版本，避免了这类问题。

### 4.4 动态模块的三种注册方式

- `register()`：同步配置，简单场景；
- `registerAsync()`：异步配置，配合 `@nestjs/config` 的 `useFactory`；
- `forConfig()`：直接从 `ConfigService.get('auth')` 读取配置。

三种方式内部复用同一套核心 provider，减少重复代码。同步注册时 `AUTH_MODULE_OPTIONS` 用 `useValue`，异步和配置化用 `useFactory`。

## 5. 还没做完 / 已知问题

- Oracle 适配器只有接口实现，没有真实数据库测试；
- MongoDB 适配器依赖驱动类型，目前只做了基础 CRUD；
- OAuth2 的 device\_code 授权只实现了内存版，Redis 版还没做；
- 部分错误信息还是英文，i18n 覆盖不完全。

## 6. 踩坑记录

### pnpm 9 传参问题

CI 里原来写的是 `pnpm test --ci --coverage`，结果 pnpm 9 把 `--ci` 当成自己的选项，Jest 收不到。改成 `pnpm exec jest --ci --coverage` 才解决。

### npm 发布

- Granular Access Token 要选"All packages"或显式包名，不能只选 scope；
- 如果开了"Require two-factor authentication for write actions"，publish 会要 OTP，CI 里过不了。

### Redis 连接生命周期

早期 registerAsync 里漏了 `RedisLifecycleService`，导致应用关闭时 Redis 连接没正常 quit，测试时会出现连接泄漏警告。后来统一放到核心 provider 列表里。

## 7. 如果重来一次会怎么改

- 可能把 persistence 层单独拆成一个可选模块，现在放在 core 里还是有点重；
- 登录策略（single/multiple/mutual-exclusion）可以抽象成策略模式，现在 if/else 有点多；
- 配置校验可以更早做，有些非法组合到现在才在运行时发现；
- 继续往 Sa-Token 没有的方向扩展，比如更完善的管理后台、审计分析、多租户隔离等。

## 8. 后续

开发基于nestjs的luoluo框架，对标ruoyi-plus，敬请期待！！！
