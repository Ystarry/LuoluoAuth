import { Inject, Injectable, Optional } from '@nestjs/common';
import { randomUUID } from 'crypto';
import type Redis from 'ioredis'; // 需安装: ioredis
import type {
  SessionData,
  SessionStore,
} from './interfaces/session-store.interface';
import type {
  TokenPayload,
  TokenStrategy,
} from './interfaces/token-strategy.interface';
import { AuditService, AuditLog } from './audit/audit.service';
import type { RateLimiter } from './rate-limit/rate-limit.interface';
import type {
  DistributedLock,
  LockToken,
} from './distributed-lock/distributed-lock.interface';
import type { Response } from 'express';
import { CookieService } from './cookie/cookie.service';
import { AuthErrorCode } from './errors/auth-error-code';
import { AuthException } from './errors/auth.exception';

/**
 * 登录策略类型
 * - single: 单点登录，同一用户只能有一个活跃会话
 * - multiple: 多点登录，允许同一用户多个会话共存
 * - mutual-exclusion: 互斥登录，同一设备类型最多允许 N 个会话（默认 1 个）
 */
export type LoginPolicy = 'single' | 'multiple' | 'mutual-exclusion';

/**
 * 认证服务配置选项
 */
export interface AuthServiceConfig {
  /** Token 过期时间（毫秒） */
  tokenTtl?: number;
  /** 登录策略（默认 multiple） */
  loginPolicy?: LoginPolicy;
  /** 是否启用自动续签（默认 false） */
  autoRenew?: boolean;
  /** RPC 调用 IP 白名单 */
  rpcIpWhitelist?: string[];
  /** 二级认证有效期（毫秒，默认 30 分钟） */
  safeAuthTtl?: number;
  /** 登录限流配置 */
  rateLimit?: {
    /** 是否启用（默认 false） */
    enabled?: boolean;
    /** 时间窗口大小（秒，默认 60） */
    windowSeconds?: number;
    /** 窗口内最大请求次数（默认 10） */
    maxRequests?: number;
  };
  /** Remember Me 长期 Token 过期时间（毫秒，默认 30 天） */
  rememberMeTtl?: number;
  /** 设备指纹绑定配置 */
  fingerprint?: {
    /** 是否启用（默认 false） */
    enabled?: boolean;
    /** 指纹不一致时是否拒绝访问（默认 false，仅告警） */
    strict?: boolean;
  };
  /** 同一设备最多同时在线会话数（mutual-exclusion 策略，默认 1） */
  maxSameDeviceSessions?: number;
  /** 分布式锁配置（高并发登录竞态条件防护） */
  distributedLock?: {
    /** 是否启用（默认 true） */
    enabled?: boolean;
    /** 锁键 TTL（毫秒，默认 5000） */
    ttlMs?: number;
    /** 获取锁失败时重试次数（默认 0） */
    retries?: number;
    /** 重试间隔（毫秒，默认 50） */
    retryDelayMs?: number;
  };
  /** 多账号切换配置（同一客户端保持多个账号登录态） */
  multiAccount?: {
    /** 是否启用（默认 false） */
    enabled?: boolean;
    /** 同一设备最多保存的账号数量（默认 5） */
    maxAccounts?: number;
  };
}

/**
 * 扩展的 SessionStore 接口
 * 支持按用户和设备删除会话、滑动续签，以及黑名单能力
 */
interface SessionStoreWithDevice extends SessionStore {
  /** 根据用户 ID 和设备标识删除会话 */
  deleteByUserIdAndDevice?(userId: string, device: string): Promise<void>;
  /** 查询用户指定设备的所有会话 ID，按创建时间升序排列（最旧在前） */
  listByUserIdAndDevice?(userId: string, device: string): Promise<string[]>;
  /** 查询指定设备的所有会话 ID */
  listByDevice?(device: string): Promise<string[]>;
  /** 刷新会话过期时间 */
  renew?(sessionId: string, ttl?: number): Promise<void>;
  /** 封禁用户 */
  ban?(userId: string, duration: number): Promise<void>;
  /** 检查用户是否被封禁 */
  isBanned?(userId: string): Promise<boolean>;
  /** 解除封禁 */
  unban?(userId: string): Promise<void>;
}

/**
 * 认证服务
 * 提供登录、登出、Token 校验、强制下线、封禁、身份切换等核心功能
 * 支持多种登录策略配置
 */
@Injectable()
export class AuthService {
  /** Redis 黑名单 key 前缀 */
  private readonly blacklistPrefix = 'auth:blacklist';

  /**
   * @param store - Session 存储实例
   * @param tokenStrategy - Token 策略实例
   * @param config - 认证服务配置
   * @param redis - Redis 连接实例（可选，用于黑名单等高级功能）
   * @param auditService - 审计日志服务（可选）
   */
  constructor(
    @Inject('SESSION_STORE')
    private readonly store: SessionStoreWithDevice,
    @Inject('TOKEN_STRATEGY')
    private readonly tokenStrategy: TokenStrategy,
    @Inject('AUTH_CONFIG')
    private readonly config: AuthServiceConfig,
    @Inject('REDIS_CLIENT')
    private readonly redis: Redis | undefined,
    @Inject(AuditService)
    @Optional()
    private readonly auditService: AuditService | undefined,
    @Inject('RATE_LIMITER')
    @Optional()
    private readonly rateLimiter?: RateLimiter,
    @Inject(CookieService)
    @Optional()
    private readonly cookieService?: CookieService,
    @Inject('LOCK_SERVICE')
    @Optional()
    private readonly lockService?: DistributedLock,
  ) {}

  /**
   * 用户登录
   * 根据登录策略处理旧会话，生成唯一 sessionId，创建会话并返回 Token
   * @param userId - 用户 ID
   * @param device - 设备标识（可选）
   * @param roles - 角色列表（可选）
   * @param permissions - 权限列表（可选）
   * @param ip - 客户端 IP（可选，用于设备指纹绑定）
   * @param userAgent - 客户端 User-Agent（可选，用于设备指纹绑定）
   * @param res - HTTP 响应对象（可选，启用 Cookie 模式时写入 Cookie）
   * @param rememberMe - 是否记住登录（使用 rememberMeTtl 长期 Token）
   * @returns 生成的 Token 字符串
   */
  async login(
    userId: string,
    device?: string,
    roles?: string[],
    permissions?: string[],
    ip?: string,
    userAgent?: string,
    res?: Response,
    rememberMe?: boolean,
  ): Promise<string> {
    // 登录限流检查
    if (this.config.rateLimit?.enabled && this.rateLimiter && ip) {
      const allowed = await this.rateLimiter.allow({
        ip,
        userId,
        action: 'login',
      });
      if (!allowed) {
        throw new AuthException(AuthErrorCode.LOGIN_RATE_LIMITED, 429);
      }
    }

    const lockConfig = this.config.distributedLock;
    const lockEnabled = (lockConfig?.enabled ?? true) && !!this.lockService;
    const lockKey = this.buildLoginLockKey(userId, device);
    const lockTtl = lockConfig?.ttlMs ?? 5000;
    const lockRetries = lockConfig?.retries ?? 0;
    const lockRetryDelay = lockConfig?.retryDelayMs ?? 50;

    const lock = lockEnabled
      ? await this.acquireLockWithRetry(
          lockKey,
          lockTtl,
          lockRetries,
          lockRetryDelay,
        )
      : undefined;

    if (lockEnabled && !lock) {
      throw new AuthException(AuthErrorCode.LOGIN_CONCURRENT_LIMIT, 423);
    }

    try {
      const policy = this.config.loginPolicy || 'multiple';

      // 根据登录策略处理旧会话
      if (policy === 'single') {
        await this.store.deleteByUserId(userId);
      } else if (policy === 'mutual-exclusion' && device) {
        if (this.store.listByUserIdAndDevice) {
          const maxSame = this.config.maxSameDeviceSessions ?? 1;
          const sessionIds = await this.store.listByUserIdAndDevice(
            userId,
            device,
          );
          const overflow = sessionIds.length - maxSame + 1;
          if (overflow > 0) {
            for (let i = 0; i < overflow; i++) {
              await this.store.delete(sessionIds[i]);
            }
          }
        } else if (this.store.deleteByUserIdAndDevice) {
          // 旧版存储兼容：直接删除同一设备所有会话
          await this.store.deleteByUserIdAndDevice(userId, device);
        }
      }

      // 多账号切换控制
      if (device && this.store.listByDevice) {
        await this.handleMultiAccountLogin(userId, device);
      }

      const sessionId = randomUUID();
      const sessionData: SessionData = {
        userId,
        device,
        createTime: Date.now(),
        roles,
        permissions,
        ip,
        userAgent,
        rememberMe,
      };

      const payload: TokenPayload = {
        sessionId,
        userId,
        device,
      };

      const token = this.tokenStrategy.generate(payload);

      const storeSessionId = this.tokenStrategy.extractSessionId
        ? await this.tokenStrategy.extractSessionId(token)
        : payload.sessionId;

      const ttl = rememberMe
        ? this.config.rememberMeTtl || this.config.tokenTtl
        : this.config.tokenTtl;
      await this.store.set(storeSessionId, sessionData, ttl);

      await this.auditService?.log({
        userId,
        action: 'login',
        device,
        timestamp: Date.now(),
        sessionId,
        details: { policy: this.config.loginPolicy || 'multiple', ip },
      });

      // Cookie 模式：将 Token 写入响应 Cookie，Remember Me 时使用长期过期时间
      if (this.cookieService?.isEnabled() && res) {
        const maxAgeSeconds = ttl ? Math.floor(ttl / 1000) : undefined;
        this.cookieService.write(res, token, maxAgeSeconds);
      }

      return token;
    } finally {
      if (lock) {
        await this.lockService?.release(lock);
      }
    }
  }

  /**
   * 构造登录分布式锁键
   */
  private buildLoginLockKey(userId: string, device?: string): string {
    return `login:${userId}:${device || 'unknown'}`;
  }

  /**
   * 带重试的锁获取
   */
  private async acquireLockWithRetry(
    key: string,
    ttlMs: number,
    retries: number,
    retryDelayMs: number,
  ): Promise<LockToken | undefined> {
    for (let i = 0; i <= retries; i++) {
      const lock = await this.lockService?.acquire(key, ttlMs);
      if (lock) {
        return lock;
      }
      if (i < retries) {
        await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
      }
    }
    return undefined;
  }

  /**
   * 处理多账号登录逻辑
   * - 未启用时：保持原有登录策略行为，不干预其他账号会话
   * - 启用时：按 maxAccounts 限制同一设备上的账号数量
   */
  private async handleMultiAccountLogin(
    userId: string,
    device: string,
  ): Promise<void> {
    const multiAccount = this.config.multiAccount;
    const enabled = multiAccount?.enabled ?? false;

    if (!enabled) {
      return;
    }

    const sessionIds = await this.store.listByDevice!(device);
    const maxAccounts = multiAccount?.maxAccounts ?? 5;
    const distinctUsers = new Set<string>();
    const sessions: {
      sessionId: string;
      userId: string;
      createTime: number;
    }[] = [];

    for (const sessionId of sessionIds) {
      const session = await this.store.get(sessionId);
      if (session) {
        distinctUsers.add(session.userId);
        sessions.push({
          sessionId,
          userId: session.userId,
          createTime: session.createTime || 0,
        });
      }
    }

    // 如果当前用户已存在，则不占用新的账号额度
    if (!distinctUsers.has(userId) && distinctUsers.size >= maxAccounts) {
      throw new AuthException(AuthErrorCode.MULTI_ACCOUNT_LIMIT_EXCEEDED, 403);
    }

    // 若同一用户已登录且超出单用户单设备限制，按创建时间淘汰最旧会话
    const userSessions = sessions.filter((s) => s.userId === userId);
    if (userSessions.length > 0) {
      const maxSame = this.config.maxSameDeviceSessions ?? 1;
      userSessions.sort((a, b) => a.createTime - b.createTime);
      const overflow = userSessions.length - maxSame + 1;
      if (overflow > 0) {
        for (let i = 0; i < overflow; i++) {
          await this.store.delete(userSessions[i].sessionId);
        }
      }
    }
  }

  /**
   * 校验 Token 并返回会话数据
   * 若启用设备指纹绑定，会校验当前请求的 IP / User-Agent 是否与登录时一致
   * @param token - Token 字符串
   * @param clientIp - 当前请求客户端 IP（可选）
   * @param clientUserAgent - 当前请求 User-Agent（可选）
   * @returns 会话数据
   * @throws Token 无效、会话不存在或指纹不匹配（strict 模式）时抛出异常
   */
  async validateToken(
    token: string,
    clientIp?: string,
    clientUserAgent?: string,
  ): Promise<SessionData> {
    const payload = await this.tokenStrategy.verify(token);
    const sessionData = await this.store.get(payload.sessionId);

    if (!sessionData) {
      throw new AuthException(AuthErrorCode.SESSION_NOT_FOUND, 401);
    }

    await this.checkFingerprint(sessionData, clientIp, clientUserAgent);

    return sessionData;
  }

  /**
   * 用户登出
   * 删除指定 Token 对应的会话；若启用 Cookie 模式并传入响应对象，则同时清除 Cookie
   * @param token - Token 字符串
   * @param res - HTTP 响应对象（可选，用于清除 Cookie）
   */
  async logout(token: string, res?: Response): Promise<void> {
    // Cookie 模式：优先清除响应 Cookie，即使 Token 校验失败也应清理
    if (this.cookieService?.isEnabled() && res) {
      this.cookieService.clear(res);
    }

    try {
      const payload = await this.tokenStrategy.verify(token);
      await this.store.delete(payload.sessionId);

      await this.auditService?.log({
        userId: payload.userId,
        action: 'logout',
        device: payload.device,
        timestamp: Date.now(),
        sessionId: payload.sessionId,
      });
    } catch {
      // Token 无效时静默处理，无需抛出异常
    }
  }

  /**
   * 强制下线指定会话
   * 直接删除 Redis 中的指定 session，无需 Token
   * @param sessionId - 会话唯一标识
   */
  async forceLogout(sessionId: string): Promise<void> {
    await this.store.delete(sessionId);

    await this.auditService?.log({
      userId: 'system',
      action: 'force_logout',
      timestamp: Date.now(),
      sessionId,
    });
  }

  /**
   * 踢出用户
   * 根据 userId 和 device 踢出指定用户的会话
   * @param userId - 用户 ID
   * @param device - 设备标识（可选，若传入则只踢该设备）
   */
  async kickUser(userId: string, device?: string): Promise<void> {
    if (device && this.store.deleteByUserIdAndDevice) {
      await this.store.deleteByUserIdAndDevice(userId, device);
    } else {
      await this.store.deleteByUserId(userId);
    }

    await this.auditService?.log({
      userId,
      action: 'kick',
      device,
      timestamp: Date.now(),
      details: { byDevice: !!device },
    });
  }

  /**
   * 封禁用户
   * 在 Redis 中设置黑名单，禁止该用户登录或访问
   * @param userId - 用户 ID
   * @param duration - 封禁时长（秒）
   */
  async banUser(userId: string, duration: number): Promise<void> {
    if (this.store.ban) {
      await this.store.ban(userId, duration);
    } else if (this.redis) {
      const key = `${this.blacklistPrefix}:${userId}`;
      await this.redis.set(key, '1', 'EX', duration);
    } else {
      throw new AuthException(
        AuthErrorCode.INTERNAL_ERROR,
        500,
        'Either the session store must support blacklist operations or a Redis client must be provided',
      );
    }

    await this.auditService?.log({
      userId,
      action: 'ban',
      timestamp: Date.now(),
      details: { duration },
    });
  }

  /**
   * 检查用户是否在黑名单中
   * @param userId - 用户 ID
   * @returns 是否被封禁
   */
  async isBanned(userId: string): Promise<boolean> {
    if (this.store.isBanned) {
      return this.store.isBanned(userId);
    }
    if (!this.redis) {
      return false;
    }
    const key = `${this.blacklistPrefix}:${userId}`;
    const result = await this.redis.get(key);
    return result !== null;
  }

  /**
   * 解除用户封禁
   * @param userId - 用户 ID
   */
  async unbanUser(userId: string): Promise<void> {
    if (this.store.unban) {
      await this.store.unban(userId);
    } else if (this.redis) {
      const key = `${this.blacklistPrefix}:${userId}`;
      await this.redis.del(key);
    } else {
      throw new AuthException(
        AuthErrorCode.INTERNAL_ERROR,
        500,
        'Either the session store must support blacklist operations or a Redis client must be provided',
      );
    }

    await this.auditService?.log({
      userId,
      action: 'unban',
      timestamp: Date.now(),
    });
  }

  /**
   * 切换身份
   * 生成一个新 Token，session 中记录原始用户 ID 和切换时间
   * @param userId - 当前用户 ID
   * @param targetUserId - 目标用户 ID（切换后的身份）
   * @param device - 设备标识（可选）
   * @param ip - 客户端 IP（可选，用于设备指纹绑定）
   * @param userAgent - 客户端 User-Agent（可选，用于设备指纹绑定）
   * @returns 新 Token 字符串
   */
  async switchIdentity(
    userId: string,
    targetUserId: string,
    device?: string,
    ip?: string,
    userAgent?: string,
  ): Promise<string> {
    const sessionId = randomUUID();
    const sessionData: SessionData = {
      userId: targetUserId,
      device,
      createTime: Date.now(),
      originalUserId: userId,
      switchTime: Date.now(),
      ip,
      userAgent,
    };

    const payload: TokenPayload = {
      sessionId,
      userId: targetUserId,
      device,
    };

    const token = this.tokenStrategy.generate(payload);

    const storeSessionId = this.tokenStrategy.extractSessionId
      ? await this.tokenStrategy.extractSessionId(token)
      : payload.sessionId;

    const ttl = this.config.tokenTtl;
    await this.store.set(storeSessionId, sessionData, ttl);

    await this.auditService?.log({
      userId,
      action: 'switch_identity',
      device,
      timestamp: Date.now(),
      sessionId,
      details: { targetUserId, originalUserId: userId },
    });

    return token;
  }

  /**
   * 续签会话
   * 刷新 Redis 中指定 session 的过期时间
   * @param sessionId - 会话唯一标识
   */
  async renewSession(sessionId: string): Promise<void> {
    if (this.store.renew) {
      const ttl = this.config.tokenTtl;
      await this.store.renew(sessionId, ttl);
    }
  }

  /**
   * 开启二级认证
   * 在会话中标记 safeAuth = true，并记录开启时间
   * @param sessionId - 会话 ID
   * @param ttl - 二级认证有效期（毫秒，默认使用配置值）
   */
  async openSafeAuth(sessionId: string, ttl?: number): Promise<void> {
    const session = await this.store.get(sessionId);
    if (!session) {
      throw new AuthException(AuthErrorCode.SESSION_NOT_FOUND, 404);
    }

    const safeAuthTtl = ttl || this.config.safeAuthTtl || 30 * 60 * 1000;
    const updatedSession = {
      ...session,
      safeAuth: true,
      safeAuthTime: Date.now(),
    };

    await this.store.set(sessionId, updatedSession, safeAuthTtl);

    await this.auditService?.log({
      userId: session.userId,
      action: 'open_safe_auth',
      device: session.device,
      timestamp: Date.now(),
      sessionId,
    });
  }

  /**
   * 关闭二级认证
   * 在会话中移除 safeAuth 标记
   * @param sessionId - 会话 ID
   */
  async closeSafeAuth(sessionId: string): Promise<void> {
    const session = await this.store.get(sessionId);
    if (!session) {
      throw new AuthException(AuthErrorCode.SESSION_NOT_FOUND, 404);
    }

    const updatedSession = { ...session };
    delete updatedSession.safeAuth;
    delete updatedSession.safeAuthTime;

    await this.store.set(sessionId, updatedSession, this.config.tokenTtl);

    await this.auditService?.log({
      userId: session.userId,
      action: 'close_safe_auth',
      device: session.device,
      timestamp: Date.now(),
      sessionId,
    });
  }

  /**
   * 检查会话是否已开启二级认证
   * @param sessionData - 会话数据
   * @returns 是否已开启且未过期
   */
  isSafeAuth(sessionData: SessionData): boolean {
    if (!sessionData.safeAuth || !sessionData.safeAuthTime) {
      return false;
    }

    const ttl = this.config.safeAuthTtl || 30 * 60 * 1000;
    const elapsed = Date.now() - sessionData.safeAuthTime;
    return elapsed < ttl;
  }

  /**
   * 查询用户的所有在线会话
   * @param userId - 用户 ID
   * @returns 在线会话数据数组
   */
  async getOnlineSessions(userId: string): Promise<SessionData[]> {
    if (!this.store.listByUserId) {
      throw new AuthException(
        AuthErrorCode.INTERNAL_ERROR,
        500,
        'Session store does not support listing sessions by user',
      );
    }

    return this.store.listByUserId(userId);
  }

  /**
   * 查询用户登录历史
   * 依赖审计服务；若审计未启用则返回空数组
   * @param userId - 用户 ID
   * @param limit - 最大返回条数
   * @returns 登录历史记录列表
   */
  async getLoginHistory(userId: string, limit?: number): Promise<AuditLog[]> {
    if (!this.auditService) {
      return [];
    }

    return this.auditService.getLoginHistory(userId, limit);
  }

  /**
   * 查询当前设备上已登录的账号列表
   * 用于多账号切换场景展示可选账号
   * @param device - 设备标识
   * @returns 账号会话数据数组
   */
  async listAccounts(device: string): Promise<SessionData[]> {
    if (!this.store.listByDevice) {
      return [];
    }

    const sessionIds = await this.store.listByDevice(device);
    const accounts: SessionData[] = [];

    for (const sessionId of sessionIds) {
      const session = await this.store.get(sessionId);
      if (session) {
        accounts.push(session);
      }
    }

    return accounts;
  }

  /**
   * 切换到当前设备上已登录的另一个账号
   * 默认多账号切换未启用时抛出异常
   * @param token - 当前账号 Token
   * @param targetUserId - 目标账号用户 ID
   * @returns 目标账号的 Token
   */
  async switchAccount(token: string, targetUserId: string): Promise<string> {
    const multiAccount = this.config.multiAccount;
    if (!(multiAccount?.enabled ?? false)) {
      throw new AuthException(AuthErrorCode.MULTI_ACCOUNT_SWITCH_DISABLED, 403);
    }

    const payload = await this.tokenStrategy.verify(token);
    const device = payload.device;
    if (!device || !this.store.listByDevice) {
      throw new AuthException(
        AuthErrorCode.MULTI_ACCOUNT_TARGET_NOT_FOUND,
        404,
      );
    }

    const sessionIds = await this.store.listByDevice(device);
    for (const sessionId of sessionIds) {
      const session = await this.store.get(sessionId);
      if (session && session.userId === targetUserId) {
        const targetPayload: TokenPayload = {
          sessionId,
          userId: targetUserId,
          device,
        };
        return this.tokenStrategy.generate(targetPayload);
      }
    }

    throw new AuthException(AuthErrorCode.MULTI_ACCOUNT_TARGET_NOT_FOUND, 404);
  }

  /**
   * 获取认证服务配置
   * @returns 当前认证服务配置
   */
  getConfig(): AuthServiceConfig {
    return this.config;
  }

  /**
   * 校验 RPC Token 并返回会话数据
   * 除校验 token 有效性外，还支持 IP 白名单与设备指纹校验
   * @param token - Token 字符串
   * @param clientIp - 调用方 IP 地址（可选）
   * @param clientUserAgent - 调用方 User-Agent（可选）
   * @returns 会话数据
   * @throws RpcException Token 无效、IP 不在白名单或指纹不匹配时抛出
   */
  async validateRpcToken(
    token: string,
    clientIp?: string,
    clientUserAgent?: string,
  ): Promise<SessionData> {
    // 优先校验 IP 白名单（如果配置了的话）
    const whitelist = this.config.rpcIpWhitelist;
    if (whitelist && whitelist.length > 0) {
      if (!clientIp || !whitelist.includes(clientIp)) {
        throw new AuthException(
          AuthErrorCode.FORBIDDEN,
          403,
          `RPC call from IP ${clientIp || 'unknown'} is not in whitelist`,
        );
      }
    }

    // 校验 Token 有效性
    const payload = await this.tokenStrategy.verify(token);
    const sessionData = await this.store.get(payload.sessionId);

    if (!sessionData) {
      throw new AuthException(AuthErrorCode.SESSION_NOT_FOUND, 401);
    }

    await this.checkFingerprint(sessionData, clientIp, clientUserAgent);

    return sessionData;
  }

  /**
   * 检查设备指纹是否一致
   * 启用指纹绑定后，若当前请求的 IP / User-Agent 与 session 中记录的不一致，
   * strict 模式抛出异常拒绝访问，非 strict 模式记录审计告警
   * @param sessionData - 会话数据
   * @param clientIp - 当前请求 IP
   * @param clientUserAgent - 当前请求 User-Agent
   */
  private async checkFingerprint(
    sessionData: SessionData,
    clientIp?: string,
    clientUserAgent?: string,
  ): Promise<void> {
    const fingerprint = this.config.fingerprint;
    if (!fingerprint?.enabled) {
      return;
    }

    // 未提供任何指纹信息时不做校验
    if (!clientIp && !clientUserAgent) {
      return;
    }

    // 未记录到指纹信息时不做校验（兼容旧会话）
    if (!sessionData.ip && !sessionData.userAgent) {
      return;
    }

    const ipMismatch =
      sessionData.ip && clientIp && sessionData.ip !== clientIp;
    const uaMismatch =
      sessionData.userAgent &&
      clientUserAgent &&
      sessionData.userAgent !== clientUserAgent;

    if (!ipMismatch && !uaMismatch) {
      return;
    }

    const details = {
      expectedIp: sessionData.ip,
      expectedUserAgent: sessionData.userAgent,
      actualIp: clientIp,
      actualUserAgent: clientUserAgent,
    };

    if (fingerprint.strict) {
      await this.auditService?.log({
        userId: sessionData.userId,
        action: 'fingerprint_mismatch_reject',
        timestamp: Date.now(),
        details,
      });
      throw new AuthException(AuthErrorCode.FINGERPRINT_MISMATCH, 403);
    }

    await this.auditService?.log({
      userId: sessionData.userId,
      action: 'fingerprint_mismatch_warn',
      timestamp: Date.now(),
      details,
    });
  }
}
