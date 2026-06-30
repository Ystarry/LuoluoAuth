import { DynamicModule, Module, Provider } from '@nestjs/common';
import { ConfigService } from '@nestjs/config'; // 需安装: @nestjs/config
import Redis from 'ioredis';
import type { RedisOptions } from 'ioredis';
import { plainToInstance } from 'class-transformer';
import { validateSync } from 'class-validator';
import { AuthService, AuthServiceConfig } from './auth.service';
import { AuthGuard } from './auth.guard';
import { JwtStrategy, JwtStrategyOptions } from './strategies/jwt.strategy';
import {
  RandomTokenStrategy,
  RandomTokenStrategyOptions,
} from './strategies/random-token.strategy';
import { MemoryStore } from './stores/memory-store';
import { RedisStore } from './stores/redis-store';
import type { SessionStore } from './interfaces/session-store.interface';
import { PermissionEngine } from './permission/permission.engine';
import {
  AuthFrameworkConfig,
  DEFAULT_JWT_SECRET,
  DEFAULT_SIGNATURE_SECRET,
  defaultConfig,
} from './auth.config';
import { AuditConfig, AuditService } from './audit/audit.service';
import { SignatureGuard } from './signature/signature.guard';
import { SignatureConfig } from './signature/signature.util';
import { MemoryRateLimiter } from './rate-limit/memory-rate-limiter';
import { RedisRateLimiter } from './rate-limit/redis-rate-limiter';
import { MemoryNonceStore, RedisNonceStore } from './signature/nonce-store';
import { CookieService } from './cookie/cookie.service';
import type { CookieConfig } from './cookie/cookie.config';
import { WsAuthGuard } from './ws/ws-auth.guard';
import {
  MemoryDistributedLock,
  RedisDistributedLock,
} from './distributed-lock';

/**
 * 认证模块配置选项（兼容旧版）
 */
export interface AuthModuleOptions {
  /** JWT 配置 */
  jwt?: JwtStrategyOptions;
  /** 随机 Token 配置（若配置则优先使用随机 Token 策略） */
  randomToken?: RandomTokenStrategyOptions;
  /** 认证服务配置 */
  auth?: AuthServiceConfig;
  /** 是否使用 Redis 存储（默认 false，使用内存存储） */
  useRedis?: boolean;
  /** Redis 连接实例（可选，若提供则优先使用） */
  redisClient?: Redis;
  /** Redis 连接配置（用于内部创建连接） */
  redisOptions?: RedisOptions;
  /** 内存存储最大会话数（默认 0 表示不限制） */
  maxSize?: number;
  /** 审计日志配置 */
  audit?: AuditConfig;
  /** API 签名认证配置 */
  signature?: SignatureConfig;
  /** 登录限流配置 */
  rateLimit?: {
    /** 是否启用（默认 false） */
    enabled?: boolean;
    /** 时间窗口大小（秒，默认 60） */
    windowSeconds?: number;
    /** 窗口内最大请求次数（默认 10） */
    maxRequests?: number;
  };
  /** Cookie 模式配置 */
  cookie?: CookieConfig;
}

/**
 * 认证模块
 * 提供动态注册能力，支持同步、异步配置加载和 @nestjs/config 集成
 */
@Module({})
export class AuthModule {
  /**
   * 同步注册认证模块
   * @param options - 认证模块配置选项
   * @returns 动态模块定义
   */
  static register(options: AuthModuleOptions): DynamicModule {
    this.validateSecrets(options);
    const providers = this.createProviders(options);
    const signatureProviders = this.createSignatureProviders(options);
    const cookieProviders = this.createCookieProviders(options.cookie);
    return {
      module: AuthModule,
      providers: [
        ...providers,
        ...signatureProviders,
        ...cookieProviders,
        AuthService,
        AuthGuard,
        WsAuthGuard,
        PermissionEngine,
        AuditService,
      ],
      exports: [
        AuthService,
        AuthGuard,
        WsAuthGuard,
        PermissionEngine,
        AuditService,
        'RATE_LIMITER',
        'NONCE_STORE',
        'LOCK_SERVICE',
        CookieService,
      ],
      global: true,
    };
  }

  /**
   * 校验 JWT 和签名密钥是否仍为框架默认值
   * 若未显式配置有效密钥，则抛出致命错误，防止生产环境使用默认密钥
   * @param options - 认证模块配置选项
   */
  private static validateSecrets(options: AuthModuleOptions): void {
    const jwtSecret = options.jwt?.secret;
    if (jwtSecret === DEFAULT_JWT_SECRET) {
      throw new Error(
        `[luoluo-auth] JWT secret must not be the default value "${DEFAULT_JWT_SECRET}". Please set a strong secret via AuthModule.register({ jwt: { secret: '...' } }).`,
      );
    }

    if (
      options.signature &&
      options.signature.secret === DEFAULT_SIGNATURE_SECRET
    ) {
      throw new Error(
        `[luoluo-auth] Signature secret must not be the default value "${DEFAULT_SIGNATURE_SECRET}". Please set a strong secret via AuthModule.register({ signature: { secret: '...' } }).`,
      );
    }
  }

  /**
   * 异步注册认证模块
   * 支持通过 @nestjs/config 动态加载配置
   * @param options - 异步配置工厂
   * @returns 动态模块定义
   */
  static registerAsync(options: {
    useFactory: (
      ...args: any[]
    ) => Promise<AuthModuleOptions> | AuthModuleOptions;

    inject?: any[];
  }): DynamicModule {
    const optionsProvider: Provider = {
      provide: 'AUTH_MODULE_OPTIONS',

      useFactory: async (...args: any[]) => {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
        const opts = await options.useFactory(...args);
        this.validateSecrets(opts);
        return opts;
      },
      inject: options.inject || [],
    };

    const providers: Provider[] = [
      optionsProvider,
      {
        provide: 'SESSION_STORE',
        useFactory: (opts: AuthModuleOptions) => {
          if (opts.useRedis) {
            if (opts.redisClient) {
              return new RedisStore(opts.redisClient);
            }
            return new RedisStore(new Redis(opts.redisOptions || {}));
          }
          return new MemoryStore({ maxSize: opts.maxSize });
        },
        inject: ['AUTH_MODULE_OPTIONS'],
      },
      {
        provide: 'TOKEN_STRATEGY',
        useFactory: (opts: AuthModuleOptions, store: SessionStore) => {
          if (opts.randomToken) {
            return new RandomTokenStrategy(store, opts.randomToken);
          }
          return new JwtStrategy(
            opts.jwt || {
              secret: DEFAULT_JWT_SECRET,
            },
          );
        },
        inject: ['AUTH_MODULE_OPTIONS', 'SESSION_STORE'],
      },
      {
        provide: 'AUTH_CONFIG',
        useFactory: (opts: AuthModuleOptions) => {
          return opts.auth || {};
        },
        inject: ['AUTH_MODULE_OPTIONS'],
      },
      {
        provide: 'REDIS_CLIENT',
        useFactory: (opts: AuthModuleOptions) => {
          if (opts.useRedis) {
            return opts.redisClient || new Redis(opts.redisOptions || {});
          }
          return undefined;
        },
        inject: ['AUTH_MODULE_OPTIONS'],
      },
      {
        provide: 'AUDIT_CONFIG',
        useFactory: (opts: AuthModuleOptions) => {
          return opts.audit;
        },
        inject: ['AUTH_MODULE_OPTIONS'],
      },
      {
        provide: 'SIGNATURE_CONFIG',
        useFactory: (opts: AuthModuleOptions) => {
          return opts.signature;
        },
        inject: ['AUTH_MODULE_OPTIONS'],
      },
      {
        provide: 'RATE_LIMITER',
        useFactory: (opts: AuthModuleOptions, redis?: Redis) => {
          if (!opts.rateLimit?.enabled) {
            return undefined;
          }
          const windowSeconds = opts.rateLimit.windowSeconds ?? 60;
          const maxRequests = opts.rateLimit.maxRequests ?? 10;
          if (redis) {
            return new RedisRateLimiter(redis, windowSeconds, maxRequests);
          }
          return new MemoryRateLimiter(windowSeconds, maxRequests);
        },
        inject: [
          'AUTH_MODULE_OPTIONS',
          { token: 'REDIS_CLIENT', optional: true },
        ],
      },
      {
        provide: 'NONCE_STORE',
        useFactory: (redis?: Redis) => {
          if (redis) {
            return new RedisNonceStore(redis);
          }
          return new MemoryNonceStore();
        },
        inject: [{ token: 'REDIS_CLIENT', optional: true }],
      },
      {
        provide: 'LOCK_SERVICE',
        useFactory: (redis?: Redis) => {
          if (redis) {
            return new RedisDistributedLock(redis);
          }
          return new MemoryDistributedLock();
        },
        inject: [{ token: 'REDIS_CLIENT', optional: true }],
      },
      {
        provide: 'COOKIE_CONFIG',
        useFactory: (opts: AuthModuleOptions) => opts.cookie,
        inject: ['AUTH_MODULE_OPTIONS'],
      },
      {
        provide: CookieService,
        useFactory: (cookieConfig?: CookieConfig) =>
          new CookieService(cookieConfig),
        inject: [{ token: 'COOKIE_CONFIG', optional: true }],
      },
      AuthService,
      AuthGuard,
      WsAuthGuard,
      PermissionEngine,
      AuditService,
      SignatureGuard,
    ];

    return {
      module: AuthModule,
      providers,
      exports: [
        AuthService,
        AuthGuard,
        WsAuthGuard,
        PermissionEngine,
        AuditService,
        'RATE_LIMITER',
        'NONCE_STORE',
        'LOCK_SERVICE',
        CookieService,
      ],
      global: true,
    };
  }

  /**
   * 使用 @nestjs/config 注册认证模块
   * 从 ConfigService 中读取 'auth' 配置项
   *
   * 注意：调用方需先在应用根模块中导入 ConfigModule.forRoot()，
   * 否则 ConfigService 不可用，启动时会抛出依赖注入错误。
   *
   * @returns 动态模块定义
   */
  static forConfig(): DynamicModule {
    return {
      module: AuthModule,
      providers: [
        {
          provide: 'AUTH_MODULE_OPTIONS',
          useFactory: (configService: ConfigService) => {
            const rawConfig =
              configService.get<AuthFrameworkConfig>('auth') || {};
            const config = plainToInstance(AuthFrameworkConfig, rawConfig);
            const validationErrors = validateSync(config, {
              whitelist: true,
              forbidNonWhitelisted: false,
            });
            if (validationErrors.length > 0) {
              const messages = validationErrors
                .map(
                  (err) =>
                    `${err.property}: ${Object.values(err.constraints || {}).join(', ')}`,
                )
                .join('; ');
              throw new Error(
                `[luoluo-auth] Invalid auth configuration: ${messages}`,
              );
            }
            const opts = AuthModule.mapFrameworkConfig(config);
            this.validateSecrets(opts);
            return opts;
          },
          inject: [ConfigService],
        },
        {
          provide: 'SESSION_STORE',
          useFactory: (opts: AuthModuleOptions) => {
            if (opts.useRedis) {
              if (opts.redisClient) {
                return new RedisStore(opts.redisClient);
              }
              return new RedisStore(new Redis(opts.redisOptions || {}));
            }
            return new MemoryStore({ maxSize: opts.maxSize });
          },
          inject: ['AUTH_MODULE_OPTIONS'],
        },
        {
          provide: 'TOKEN_STRATEGY',
          useFactory: (opts: AuthModuleOptions, store: SessionStore) => {
            if (opts.randomToken) {
              return new RandomTokenStrategy(store, opts.randomToken);
            }
            return new JwtStrategy(
              opts.jwt || {
                secret: DEFAULT_JWT_SECRET,
              },
            );
          },
          inject: ['AUTH_MODULE_OPTIONS', 'SESSION_STORE'],
        },
        {
          provide: 'AUTH_CONFIG',
          useFactory: (opts: AuthModuleOptions) => {
            return opts.auth || {};
          },
          inject: ['AUTH_MODULE_OPTIONS'],
        },
        {
          provide: 'REDIS_CLIENT',
          useFactory: (opts: AuthModuleOptions) => {
            if (opts.useRedis) {
              return opts.redisClient || new Redis(opts.redisOptions || {});
            }
            return undefined;
          },
          inject: ['AUTH_MODULE_OPTIONS'],
        },
        {
          provide: 'AUDIT_CONFIG',
          useFactory: (opts: AuthModuleOptions) => {
            return opts.audit;
          },
          inject: ['AUTH_MODULE_OPTIONS'],
        },
        {
          provide: 'SIGNATURE_CONFIG',
          useFactory: (opts: AuthModuleOptions) => {
            return opts.signature;
          },
          inject: ['AUTH_MODULE_OPTIONS'],
        },
        {
          provide: 'RATE_LIMITER',
          useFactory: (opts: AuthModuleOptions, redis?: Redis) => {
            if (!opts.rateLimit?.enabled) {
              return undefined;
            }
            const windowSeconds = opts.rateLimit.windowSeconds ?? 60;
            const maxRequests = opts.rateLimit.maxRequests ?? 10;
            if (redis) {
              return new RedisRateLimiter(redis, windowSeconds, maxRequests);
            }
            return new MemoryRateLimiter(windowSeconds, maxRequests);
          },
          inject: [
            'AUTH_MODULE_OPTIONS',
            { token: 'REDIS_CLIENT', optional: true },
          ],
        },
        {
          provide: 'NONCE_STORE',
          useFactory: (redis?: Redis) => {
            if (redis) {
              return new RedisNonceStore(redis);
            }
            return new MemoryNonceStore();
          },
          inject: [{ token: 'REDIS_CLIENT', optional: true }],
        },
        {
          provide: 'LOCK_SERVICE',
          useFactory: (redis?: Redis) => {
            if (redis) {
              return new RedisDistributedLock(redis);
            }
            return new MemoryDistributedLock();
          },
          inject: [{ token: 'REDIS_CLIENT', optional: true }],
        },
        {
          provide: 'COOKIE_CONFIG',
          useFactory: (opts: AuthModuleOptions) => opts.cookie,
          inject: ['AUTH_MODULE_OPTIONS'],
        },
        {
          provide: CookieService,
          useFactory: (cookieConfig?: CookieConfig) =>
            new CookieService(cookieConfig),
          inject: [{ token: 'COOKIE_CONFIG', optional: true }],
        },
        AuthService,
        AuthGuard,
        WsAuthGuard,
        PermissionEngine,
        AuditService,
        SignatureGuard,
      ],
      exports: [
        AuthService,
        AuthGuard,
        WsAuthGuard,
        PermissionEngine,
        AuditService,
        'RATE_LIMITER',
        'NONCE_STORE',
        'LOCK_SERVICE',
        CookieService,
      ],
      global: true,
    };
  }

  /**
   * 将 AuthFrameworkConfig 映射为 AuthModuleOptions
   * @param config - 框架配置
   * @returns 模块配置选项
   */
  private static mapFrameworkConfig(
    config: AuthFrameworkConfig,
  ): AuthModuleOptions {
    const merged = { ...defaultConfig, ...config };

    return {
      jwt: {
        secret:
          merged.token?.secret &&
          merged.token.secret !== defaultConfig.token!.secret
            ? merged.token.secret
            : defaultConfig.token!.secret,
        expiresIn: (merged.token?.expiresIn ||
          defaultConfig.token!.expiresIn) as JwtStrategyOptions['expiresIn'],
      },
      auth: {
        tokenTtl:
          merged.loginPolicy?.tokenTtl || defaultConfig.loginPolicy!.tokenTtl,
        loginPolicy:
          merged.loginPolicy?.policy || defaultConfig.loginPolicy!.policy,
        autoRenew:
          merged.loginPolicy?.autoRenew || defaultConfig.loginPolicy!.autoRenew,
        maxSameDeviceSessions:
          merged.loginPolicy?.maxSameDeviceSessions ??
          defaultConfig.loginPolicy!.maxSameDeviceSessions,
        rememberMeTtl:
          merged.loginPolicy?.rememberMeTtl ??
          defaultConfig.loginPolicy!.rememberMeTtl,
        rpcIpWhitelist: merged.microservice?.rpcIpWhitelist,
        safeAuthTtl: merged.safeAuth?.ttl || defaultConfig.safeAuth!.ttl,
        rateLimit: merged.rateLimit,
        fingerprint: merged.fingerprint,
        distributedLock: merged.distributedLock,
        multiAccount: merged.multiAccount,
      },
      useRedis: merged.storage?.useRedis || false,
      redisOptions: merged.storage?.redisOptions,
      maxSize: merged.storage?.maxSize,
      audit: merged.audit,
      signature: merged.signature?.enabled
        ? {
            secret:
              merged.signature.secret &&
              merged.signature.secret !== defaultConfig.signature!.secret
                ? merged.signature.secret
                : defaultConfig.signature!.secret!,
            timestampTolerance:
              merged.signature.timestampTolerance ||
              defaultConfig.signature!.timestampTolerance,
          }
        : undefined,
      randomToken: merged.randomToken,
      cookie: merged.cookie,
    };
  }

  /**
   * 创建同步注册时的 Provider 列表
   * @param options - 认证模块配置选项
   * @returns Provider 数组
   */
  private static createProviders(options: AuthModuleOptions): Provider[] {
    return [
      {
        provide: 'SESSION_STORE',
        useFactory: () => {
          if (options.useRedis) {
            if (options.redisClient) {
              return new RedisStore(options.redisClient);
            }
            return new RedisStore(new Redis(options.redisOptions || {}));
          }
          return new MemoryStore({ maxSize: options.maxSize });
        },
      },
      {
        provide: 'TOKEN_STRATEGY',
        useFactory: (store: SessionStore) => {
          if (options.randomToken) {
            return new RandomTokenStrategy(store, options.randomToken);
          }
          return new JwtStrategy(
            options.jwt || {
              secret: DEFAULT_JWT_SECRET,
            },
          );
        },
        inject: ['SESSION_STORE'],
      },
      {
        provide: 'AUTH_CONFIG',
        useValue: options.auth || {},
      },
      {
        provide: 'REDIS_CLIENT',
        useFactory: () => {
          if (options.useRedis) {
            return options.redisClient || new Redis(options.redisOptions || {});
          }
          return undefined;
        },
      },
      {
        provide: 'AUDIT_CONFIG',
        useValue: options.audit,
      },
      {
        provide: 'SIGNATURE_CONFIG',
        useValue: options.signature,
      },
      {
        provide: 'RATE_LIMITER',
        useFactory: () => {
          if (!options.rateLimit?.enabled) {
            return undefined;
          }
          const windowSeconds = options.rateLimit.windowSeconds ?? 60;
          const maxRequests = options.rateLimit.maxRequests ?? 10;
          if (options.useRedis) {
            const redis =
              options.redisClient || new Redis(options.redisOptions || {});
            return new RedisRateLimiter(redis, windowSeconds, maxRequests);
          }
          return new MemoryRateLimiter(windowSeconds, maxRequests);
        },
      },
      {
        provide: 'NONCE_STORE',
        useFactory: (redis?: Redis) => {
          if (redis) {
            return new RedisNonceStore(redis);
          }
          return new MemoryNonceStore();
        },
        inject: [{ token: 'REDIS_CLIENT', optional: true }],
      },
      {
        provide: 'LOCK_SERVICE',
        useFactory: (redis?: Redis) => {
          if (redis) {
            return new RedisDistributedLock(redis);
          }
          return new MemoryDistributedLock();
        },
        inject: [{ token: 'REDIS_CLIENT', optional: true }],
      },
      ...this.createCookieProviders(options.cookie),
    ];
  }

  /**
   * 创建 Cookie 相关 Provider
   * @param config - Cookie 配置
   * @returns Provider 数组
   */
  private static createCookieProviders(config?: CookieConfig): Provider[] {
    return [
      {
        provide: 'COOKIE_CONFIG',
        useValue: config,
      },
      {
        provide: CookieService,
        useFactory: (cookieConfig?: CookieConfig) =>
          new CookieService(cookieConfig),
        inject: [{ token: 'COOKIE_CONFIG', optional: true }],
      },
    ];
  }

  /**
   * 创建签名认证 Provider 列表
   * @param options - 认证模块配置选项
   * @returns Provider 数组
   */
  private static createSignatureProviders(
    options: AuthModuleOptions,
  ): Provider[] {
    if (!options.signature) {
      return [];
    }
    return [
      {
        provide: 'SIGNATURE_CONFIG',
        useValue: options.signature,
      },
      SignatureGuard,
    ];
  }
}
