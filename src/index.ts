// ==================== Core ====================

// 认证模块
export { AuthModule } from './auth/auth.module';
export type { AuthModuleOptions } from './auth/auth.module';

// 认证服务
export { AuthService } from './auth/auth.service';
export type { AuthServiceConfig, LoginPolicy } from './auth/auth.service';

// 认证守卫
export { AuthGuard } from './auth/auth.guard';
export { WsAuthGuard } from './auth/ws/ws-auth.guard';

// 认证装饰器
export {
  RequireLogin,
  RequireRoles,
  RequirePermissions,
  RequireSafeAuth,
  RequireSignature,
  AUTH_METADATA_KEY,
  ROLES_METADATA_KEY,
  PERMISSIONS_METADATA_KEY,
  SAFE_AUTH_METADATA_KEY,
  SIGNATURE_METADATA_KEY,
} from './auth/auth.decorator';

// 认证异常过滤器
export { AuthExceptionFilter } from './auth/auth.filter';

// 认证配置
export { defaultConfig } from './auth/auth.config';
export type { AuthFrameworkConfig } from './auth/auth.config';

// Session 存储接口
export type {
  SessionData,
  SessionStore,
} from './auth/interfaces/session-store.interface';

// Token 策略接口
export type {
  TokenPayload,
  TokenStrategy,
} from './auth/interfaces/token-strategy.interface';

// 内存存储
export { MemoryStore } from './auth/stores/memory-store';
export type { MemoryStoreOptions } from './auth/stores/memory-store';

// Redis 存储
export { RedisStore } from './auth/stores/redis-store';

// JWT 策略
export { JwtStrategy } from './auth/strategies/jwt.strategy';
export type { JwtStrategyOptions } from './auth/strategies/jwt.strategy';

// 权限引擎
export { PermissionEngine } from './auth/permission/permission.engine';
export type { SessionWithPermissions } from './auth/permission/permission.engine';

// 审计日志服务
export { AuditService } from './auth/audit/audit.service';
export type {
  AuditLog,
  AuditAction,
  AuditConfig,
} from './auth/audit/audit.service';

// 密码加密工具
export { BcryptPasswordEncoder, Argon2PasswordEncoder } from './auth/password';
export type { PasswordEncoder } from './auth/password';

// ==================== Extras ====================

// SSO 模块
export { SsoModule } from './extras/sso/sso.module';

// SSO 服务
export { SsoService } from './extras/sso/sso.service';
export type {
  SsoServiceConfig,
  SsoCallbackQuery,
  SsoUserInfo,
  SsoCodeExchangeResult,
  SsoCodeExchangeHandler,
} from './extras/sso/sso.service';

// OAuth2 模块
export { OAuth2Module } from './extras/oauth2/oauth2.module';
export type { OAuth2ModuleOptions } from './extras/oauth2/oauth2.module';

// OAuth2 控制器
export { OAuth2Controller } from './extras/oauth2/oauth2.controller';
export type {
  OAuth2AuthorizeConfig,
  OAuth2AuthCheckMode,
} from './extras/oauth2/oauth2.controller';

// OAuth2 客户端存储
export { InMemoryOAuth2ClientStore } from './extras/oauth2/client-store';
export type { OAuth2ClientStore } from './extras/oauth2/client-store';
export type {
  OAuth2Client,
  OAuth2Token,
  AuthorizationCode,
  DeviceCode,
  GrantType,
  UserValidator,
} from './extras/oauth2/client-store';

// OIDC 服务
export { OidcService } from './extras/oauth2/oidc.service';
export type {
  OidcConfig,
  OidcDiscoveryMetadata,
} from './extras/oauth2/oidc.service';

// Passport 适配器
export { PassportAuthStrategy } from './extras/passport/passport.strategy';
export type {
  PassportAuthConfig,
  PassportRequest,
  PassportUser,
} from './extras/passport/passport.strategy';

// Admin 管理接口
export { AdminController } from './extras/admin/admin.controller';

// 微服务认证模块
export { MicroserviceModule } from './extras/microservice/microservice.module';

// 微服务认证拦截器
export { MicroserviceAuthInterceptor } from './extras/microservice/auth.interceptor';
export type {
  RpcTokenResolver,
  MicroserviceAuthInterceptorConfig,
} from './extras/microservice/auth.interceptor';

// 分布式锁模块
export {
  MemoryDistributedLock,
  RedisDistributedLock,
} from './auth/distributed-lock';
export type {
  DistributedLock,
  LockToken,
} from './auth/distributed-lock/distributed-lock.interface';

// 数据持久化层
export {
  MemoryPersistenceAdapter,
  MySqlPersistenceAdapter,
  PostgresPersistenceAdapter,
  OraclePersistenceAdapter,
  SqlitePersistenceAdapter,
  MongoDbPersistenceAdapter,
  SimplePersistenceAdapterFactory,
  PersistenceModule,
} from './auth/persistence';
export type {
  PersistenceAdapter,
  PersistenceAdapterFactory,
  PersistenceFilter,
  SqlExecutor,
  MongoCollection,
  PersistenceModuleOptions,
} from './auth/persistence';

// API 签名认证
export { SignatureGuard } from './auth/signature/signature.guard';
export {
  generateSignature,
  verifySignature,
  isTimestampValid,
} from './auth/signature/signature.util';
export type {
  SignatureConfig,
  SignaturePayload,
} from './auth/signature/signature.util';
