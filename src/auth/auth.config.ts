import {
  IsArray,
  IsBoolean,
  IsIn,
  IsInt,
  IsNumber,
  IsObject,
  IsOptional,
  IsString,
  Min,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';
/**
 * Token 策略配置
 */
export class TokenConfig {
  /** JWT 密钥 */
  @IsString()
  secret!: string;

  /** Token 过期时间（如 '1h', '7d'） */
  @IsOptional()
  @IsString()
  expiresIn?: string;
}

/**
 * 存储配置
 */
export class StorageConfig {
  /** 是否使用 Redis（默认 false） */
  @IsOptional()
  @IsBoolean()
  useRedis?: boolean;

  /** Redis 连接配置 */
  @IsOptional()
  @IsObject()
  redisOptions?: Record<string, unknown>;

  /** 内存存储最大会话数（默认 0 表示不限制） */
  @IsOptional()
  @IsInt()
  @Min(0)
  maxSize?: number;
}

/**
 * 登录策略配置
 */
export class LoginPolicyConfig {
  /** 登录策略 */
  @IsOptional()
  @IsIn(['single', 'multiple', 'mutual-exclusion'])
  policy?: 'single' | 'multiple' | 'mutual-exclusion';

  /** Token 过期时间（毫秒） */
  @IsOptional()
  @IsInt()
  @Min(0)
  tokenTtl?: number;

  /** 是否启用自动续签 */
  @IsOptional()
  @IsBoolean()
  autoRenew?: boolean;

  /** 同一设备最多同时在线会话数（mutual-exclusion 策略，默认 1） */
  @IsOptional()
  @IsInt()
  @Min(1)
  maxSameDeviceSessions?: number;

  /** Remember Me 长期 Token 过期时间（毫秒，默认 30 天） */
  @IsOptional()
  @IsInt()
  @Min(0)
  rememberMeTtl?: number;
}

/**
 * 权限配置
 */
export class PermissionConfig {
  /** 是否启用 RBAC */
  @IsOptional()
  @IsBoolean()
  enabled?: boolean;
}

/**
 * SSO 配置
 */
export class SsoConfig {
  /** 是否启用 SSO */
  @IsOptional()
  @IsBoolean()
  enabled?: boolean;

  /** SSO 登录页 URL */
  @IsOptional()
  @IsString()
  loginUrl?: string;

  /** Token 参数名 */
  @IsOptional()
  @IsString()
  tokenParamName?: string;

  /** Token 读取策略 */
  @IsOptional()
  @IsArray()
  @IsIn(['header', 'cookie', 'query'], { each: true })
  tokenStrategy?: ('header' | 'cookie' | 'query')[];
}

/**
 * OAuth2 配置
 */
export class OAuth2Config {
  /** 是否启用 OAuth2 */
  @IsOptional()
  @IsBoolean()
  enabled?: boolean;
}

/**
 * 二级认证配置
 */
export class SafeAuthConfig {
  /** 是否启用二级认证 */
  @IsOptional()
  @IsBoolean()
  enabled?: boolean;

  /** 二级认证有效期（毫秒，默认 30 分钟） */
  @IsOptional()
  @IsInt()
  @Min(0)
  ttl?: number;
}

/**
 * 审计日志配置
 */
export class AuditConfig {
  /** 是否启用审计日志 */
  @IsOptional()
  @IsBoolean()
  enabled?: boolean;

  /** 日志存储方式：console | file | redis（默认 console） */
  @IsOptional()
  @IsIn(['console', 'file', 'redis'])
  storage?: 'console' | 'file' | 'redis';

  /** 日志文件路径（storage 为 file 时生效） */
  @IsOptional()
  @IsString()
  logFilePath?: string;
}

/**
 * Cookie 配置
 */
export class CookieConfig {
  /** 是否启用 Cookie 模式 */
  @IsOptional()
  @IsBoolean()
  enabled?: boolean;

  /** Cookie 名称 */
  @IsOptional()
  @IsString()
  name?: string;

  /** Cookie 域名 */
  @IsOptional()
  @IsString()
  domain?: string;

  /** Cookie 路径 */
  @IsOptional()
  @IsString()
  path?: string;

  /** 是否仅允许 HTTP 读取 */
  @IsOptional()
  @IsBoolean()
  httpOnly?: boolean;

  /** 是否仅通过 HTTPS 传输 */
  @IsOptional()
  @IsBoolean()
  secure?: boolean;

  /** SameSite 策略 */
  @IsOptional()
  @IsIn(['strict', 'lax', 'none'])
  sameSite?: 'strict' | 'lax' | 'none';

  /** Cookie 最大存活时间（秒） */
  @IsOptional()
  @IsInt()
  @Min(0)
  maxAge?: number;
}

/**
 * 限流配置
 */
export class RateLimitConfig {
  /** 是否启用限流（默认 false） */
  @IsOptional()
  @IsBoolean()
  enabled?: boolean;

  /**
   * 限流策略
   * - sliding-window：滑动窗口计数
   * - token-bucket：令牌桶
   */
  @IsOptional()
  @IsIn(['sliding-window', 'token-bucket'])
  strategy?: 'sliding-window' | 'token-bucket';

  /** 限流 key 维度 */
  @IsOptional()
  @IsIn(['ip', 'user', 'ip-user'])
  keyType?: 'ip' | 'user' | 'ip-user';

  /** 时间窗口大小（秒，默认 60） */
  @IsOptional()
  @IsInt()
  @Min(1)
  windowSeconds?: number;

  /** 窗口内最大请求次数（默认 10） */
  @IsOptional()
  @IsInt()
  @Min(1)
  maxRequests?: number;

  /** 令牌桶每秒填充速率（strategy 为 token-bucket 时生效） */
  @IsOptional()
  @IsNumber()
  @Min(0)
  refillRate?: number;

  /** 令牌桶容量（strategy 为 token-bucket 时生效） */
  @IsOptional()
  @IsInt()
  @Min(1)
  capacity?: number;
}

/**
 * API 签名认证配置
 */
export class SignatureConfig {
  /** 是否启用签名认证 */
  @IsOptional()
  @IsBoolean()
  enabled?: boolean;

  /** 签名密钥 */
  @IsOptional()
  @IsString()
  secret?: string;

  /** 时间戳容忍度（毫秒，默认 5 分钟） */
  @IsOptional()
  @IsInt()
  @Min(0)
  timestampTolerance?: number;

  /** 签名头字段名 */
  @IsOptional()
  @IsString()
  headerName?: string;

  /** 时间戳头字段名 */
  @IsOptional()
  @IsString()
  timestampHeader?: string;

  /** nonce 头字段名 */
  @IsOptional()
  @IsString()
  nonceHeader?: string;
}

/**
 * 微服务配置
 */
export class MicroserviceConfig {
  /** 是否启用微服务鉴权 */
  @IsOptional()
  @IsBoolean()
  enabled?: boolean;

  /** RPC 调用 IP 白名单 */
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  rpcIpWhitelist?: string[];
}

/**
 * 分布式锁配置
 */
export class DistributedLockConfig {
  /** 是否启用（默认 true） */
  @IsOptional()
  @IsBoolean()
  enabled?: boolean;

  /** 锁键 TTL（毫秒，默认 5000） */
  @IsOptional()
  @IsInt()
  @Min(1)
  ttlMs?: number;

  /** 获取锁失败时重试次数（默认 0） */
  @IsOptional()
  @IsInt()
  @Min(0)
  retries?: number;

  /** 重试间隔（毫秒，默认 50） */
  @IsOptional()
  @IsInt()
  @Min(0)
  retryDelayMs?: number;
}

/**
 * 多账号切换配置
 */
export class MultiAccountConfig {
  /** 是否启用同一设备多账号切换（默认 false） */
  @IsOptional()
  @IsBoolean()
  enabled?: boolean;

  /** 同一设备最多保存的账号数量（默认 5） */
  @IsOptional()
  @IsInt()
  @Min(1)
  maxAccounts?: number;
}

/**
 * 设备指纹配置
 */
export class FingerprintConfig {
  /** 是否启用设备指纹绑定 */
  @IsOptional()
  @IsBoolean()
  enabled?: boolean;

  /** 严格模式：指纹不匹配时直接拒绝；非严格模式仅告警 */
  @IsOptional()
  @IsBoolean()
  strict?: boolean;
}

/**
 * 随机 Token 配置
 */
export class RandomTokenConfig {
  /** Token 风格 */
  @IsIn(['uuid-v7', 'ulid', 'random-32', 'random-64', 'random-128'])
  style!: 'uuid-v7' | 'ulid' | 'random-32' | 'random-64' | 'random-128';

  /** Token 前缀 */
  @IsOptional()
  @IsString()
  prefix?: string;
}

/**
 * 完整的认证框架配置
 */
export class AuthFrameworkConfig {
  /** Token 策略配置 */
  @IsOptional()
  @ValidateNested()
  @Type(() => TokenConfig)
  token?: TokenConfig;

  /** 存储配置 */
  @IsOptional()
  @ValidateNested()
  @Type(() => StorageConfig)
  storage?: StorageConfig;

  /** 登录策略配置 */
  @IsOptional()
  @ValidateNested()
  @Type(() => LoginPolicyConfig)
  loginPolicy?: LoginPolicyConfig;

  /** 权限配置 */
  @IsOptional()
  @ValidateNested()
  @Type(() => PermissionConfig)
  permission?: PermissionConfig;

  /** SSO 配置 */
  @IsOptional()
  @ValidateNested()
  @Type(() => SsoConfig)
  sso?: SsoConfig;

  /** OAuth2 配置 */
  @IsOptional()
  @ValidateNested()
  @Type(() => OAuth2Config)
  oauth2?: OAuth2Config;

  /** 微服务配置 */
  @IsOptional()
  @ValidateNested()
  @Type(() => MicroserviceConfig)
  microservice?: MicroserviceConfig;

  /** 二级认证配置 */
  @IsOptional()
  @ValidateNested()
  @Type(() => SafeAuthConfig)
  safeAuth?: SafeAuthConfig;

  /** 审计日志配置 */
  @IsOptional()
  @ValidateNested()
  @Type(() => AuditConfig)
  audit?: AuditConfig;

  /** API 签名认证配置 */
  @IsOptional()
  @ValidateNested()
  @Type(() => SignatureConfig)
  signature?: SignatureConfig;

  /** 登录限流配置 */
  @IsOptional()
  @ValidateNested()
  @Type(() => RateLimitConfig)
  rateLimit?: RateLimitConfig;

  /** 设备指纹配置 */
  @IsOptional()
  @ValidateNested()
  @Type(() => FingerprintConfig)
  fingerprint?: FingerprintConfig;

  /** 随机 Token 配置（若配置则优先于 JWT） */
  @IsOptional()
  @ValidateNested()
  @Type(() => RandomTokenConfig)
  randomToken?: RandomTokenConfig;

  /** Cookie 模式配置 */
  @IsOptional()
  @ValidateNested()
  @Type(() => CookieConfig)
  cookie?: CookieConfig;

  /** 分布式锁配置 */
  @IsOptional()
  @ValidateNested()
  @Type(() => DistributedLockConfig)
  distributedLock?: DistributedLockConfig;

  /** 多账号切换配置 */
  @IsOptional()
  @ValidateNested()
  @Type(() => MultiAccountConfig)
  multiAccount?: MultiAccountConfig;
}

/**
 * 框架保留的默认 JWT 密钥
 * 若用户未显式配置且最终生效的 secret 仍等于该值，则启动时抛出致命错误
 */
export const DEFAULT_JWT_SECRET = 'default-secret-change-me';

/**
 * 框架保留的默认签名密钥
 * 若用户未显式配置且最终生效的 secret 仍等于该值，则启动时抛出致命错误
 */
export const DEFAULT_SIGNATURE_SECRET = 'default-signature-secret-change-me';

/**
 * 默认配置
 * 使用 JWT + MemoryStore + single 登录策略
 */
export const defaultConfig: AuthFrameworkConfig = {
  token: {
    secret: DEFAULT_JWT_SECRET,
    expiresIn: '7d',
  },
  storage: {
    useRedis: false,
    maxSize: 0,
  },
  loginPolicy: {
    policy: 'single',
    tokenTtl: 7 * 24 * 60 * 60 * 1000, // 7 天
    autoRenew: false,
    maxSameDeviceSessions: 1,
    rememberMeTtl: 30 * 24 * 60 * 60 * 1000, // 30 天
  },
  permission: {
    enabled: true,
  },
  sso: {
    enabled: false,
    loginUrl: '/auth/login',
    tokenParamName: 'token',
    tokenStrategy: ['header', 'cookie', 'query'],
  },
  oauth2: {
    enabled: false,
  },
  microservice: {
    enabled: false,
    rpcIpWhitelist: [],
  },
  safeAuth: {
    enabled: false,
    ttl: 30 * 60 * 1000, // 30 分钟
  },
  audit: {
    enabled: false,
    storage: 'console',
  },
  signature: {
    enabled: false,
    secret: DEFAULT_SIGNATURE_SECRET,
    timestampTolerance: 5 * 60 * 1000,
  },
  rateLimit: {
    enabled: false,
    strategy: 'sliding-window',
    keyType: 'ip-user',
    windowSeconds: 60,
    maxRequests: 10,
    refillRate: 1,
    capacity: 10,
  },
  fingerprint: {
    enabled: false,
    strict: false,
  },
  cookie: {
    enabled: false,
    name: 'auth-token',
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60,
  },
  distributedLock: {
    enabled: true,
    ttlMs: 5000,
    retries: 0,
    retryDelayMs: 50,
  },
  multiAccount: {
    enabled: false,
    maxAccounts: 5,
  },
};
