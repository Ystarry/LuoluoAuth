import Redis from 'ioredis';
import { randomUUID } from 'crypto';
import type {
  AuthorizationCode,
  ConsumeRefreshTokenResult,
  OAuth2Client,
  OAuth2ClientStore,
  OAuth2Token,
} from './client-store';

/**
 * Redis 版 OAuth2 客户端与 Token 存储
 * 支持 refresh token rotation + reuse detection
 * 数据持久化到 Redis，重启后 token 仍可复用
 *
 * Key 设计：
 * - 客户端：oauth2:clients:{clientId}
 * - 授权码：oauth2:codes:{code}
 * - 访问令牌：oauth2:tokens:{accessToken}
 * - 刷新令牌：oauth2:refresh-tokens:{refreshToken}
 * - 令牌族索引：oauth2:families:{family} (Set)
 */
export class RedisOAuth2ClientStore implements OAuth2ClientStore {
  /** Redis key 前缀 */
  private readonly prefix = 'oauth2';

  /**
   * @param redis - ioredis 连接实例
   * @param tokenTtlSeconds - Token 默认 TTL（秒），默认 7 天
   * @param codeTtlSeconds - 授权码默认 TTL（秒），默认 10 分钟
   */
  constructor(
    private readonly redis: Redis,
    private readonly tokenTtlSeconds = 7 * 24 * 60 * 60,
    private readonly codeTtlSeconds = 10 * 60,
  ) {}

  private getClientKey(clientId: string): string {
    return `${this.prefix}:clients:${clientId}`;
  }

  private getCodeKey(code: string): string {
    return `${this.prefix}:codes:${code}`;
  }

  private getTokenKey(accessToken: string): string {
    return `${this.prefix}:tokens:${accessToken}`;
  }

  private getRefreshTokenKey(refreshToken: string): string {
    return `${this.prefix}:refresh-tokens:${refreshToken}`;
  }

  private getFamilyKey(family: string): string {
    return `${this.prefix}:families:${family}`;
  }

  private serialize(value: unknown): string {
    return JSON.stringify(value);
  }

  private deserialize<T>(value: string | null): T | undefined {
    if (!value) return undefined;
    return JSON.parse(value) as T;
  }

  /**
   * 注册客户端
   * @param client - 客户端信息
   */
  async registerClient(client: OAuth2Client): Promise<void> {
    await this.redis.set(
      this.getClientKey(client.clientId),
      this.serialize(client),
    );
  }

  /**
   * 根据 clientId 获取客户端信息
   * @param clientId - 客户端 ID
   * @returns 客户端信息，不存在则返回 undefined
   */
  async getClient(clientId: string): Promise<OAuth2Client | undefined> {
    const value = await this.redis.get(this.getClientKey(clientId));
    return this.deserialize<OAuth2Client>(value);
  }

  /**
   * 验证客户端密钥
   * @param clientId - 客户端 ID
   * @param clientSecret - 客户端密钥
   * @returns 是否验证通过
   */
  async verifyClientSecret(
    clientId: string,
    clientSecret: string,
  ): Promise<boolean> {
    const client = await this.getClient(clientId);
    return client !== undefined && client.clientSecret === clientSecret;
  }

  /**
   * 验证回调地址是否合法
   * @param clientId - 客户端 ID
   * @param redirectUri - 回调地址
   * @returns 是否合法
   */
  async verifyRedirectUri(
    clientId: string,
    redirectUri: string,
  ): Promise<boolean> {
    const client = await this.getClient(clientId);
    if (!client) {
      return false;
    }
    return client.redirectUris.includes(redirectUri);
  }

  /**
   * 验证客户端是否支持指定授权类型
   * @param clientId - 客户端 ID
   * @param grantType - 授权类型
   * @returns 是否支持
   */
  async supportsGrant(clientId: string, grantType: string): Promise<boolean> {
    const client = await this.getClient(clientId);
    if (!client) {
      return false;
    }
    return client.grants.includes(grantType as OAuth2Client['grants'][number]);
  }

  /**
   * 保存授权码
   * @param code - 授权码信息
   */
  async saveAuthorizationCode(code: AuthorizationCode): Promise<void> {
    await this.redis.set(
      this.getCodeKey(code.code),
      this.serialize(code),
      'EX',
      this.codeTtlSeconds,
    );
  }

  /**
   * 获取并消费授权码（使用后删除）
   * @param code - 授权码字符串
   * @returns 授权码信息，不存在或已过期则返回 undefined
   */
  async consumeAuthorizationCode(
    code: string,
  ): Promise<AuthorizationCode | undefined> {
    const key = this.getCodeKey(code);
    const value = await this.redis.get(key);
    if (!value) {
      return undefined;
    }
    const authCode = this.deserialize<AuthorizationCode>(value);
    if (!authCode) {
      return undefined;
    }

    // 检查是否过期（即使 Redis TTL 兜底，仍做二次校验）
    if (Date.now() > authCode.expiresAt) {
      await this.redis.del(key);
      return undefined;
    }

    // 消费后删除（一次性使用）
    await this.redis.del(key);
    return authCode;
  }

  /**
   * 保存 Token
   * @param token - Token 信息
   * @param family - 令牌族 ID（refresh_token 模式复用同一 family）
   */
  async saveToken(token: OAuth2Token, family?: string): Promise<void> {
    const tokenKey = this.getTokenKey(token.accessToken);
    const pipeline = this.redis.pipeline();

    pipeline.set(tokenKey, this.serialize(token), 'EX', this.tokenTtlSeconds);

    if (token.refreshToken) {
      const tokenFamily = family || randomUUID();
      const refreshTokenKey = this.getRefreshTokenKey(token.refreshToken);
      const familyKey = this.getFamilyKey(tokenFamily);

      pipeline.set(
        refreshTokenKey,
        this.serialize({
          accessToken: token.accessToken,
          family: tokenFamily,
          used: false,
        }),
        'EX',
        this.tokenTtlSeconds,
      );
      pipeline.sadd(familyKey, token.refreshToken);
      pipeline.expire(familyKey, this.tokenTtlSeconds);
    }

    await pipeline.exec();
  }

  /**
   * 根据访问令牌获取 Token 信息
   * @param accessToken - 访问令牌
   * @returns Token 信息，不存在则返回 undefined
   */
  async getToken(accessToken: string): Promise<OAuth2Token | undefined> {
    const value = await this.redis.get(this.getTokenKey(accessToken));
    return this.deserialize<OAuth2Token>(value);
  }

  /**
   * 消费刷新令牌（支持轮换与复用检测）
   * 使用 Redis 事务保证读取、标记已使用、校验的原子性
   * @param refreshToken - 刷新令牌
   * @returns 旧 Token 信息和令牌族 ID；若已复用则返回 reuseDetected = true
   */
  async consumeRefreshToken(
    refreshToken: string,
  ): Promise<ConsumeRefreshTokenResult> {
    const refreshTokenKey = this.getRefreshTokenKey(refreshToken);

    // 使用 Lua 脚本原子化读取并标记已使用
    const luaScript = `
      local key = KEYS[1]
      local value = redis.call('get', key)
      if not value then
        return nil
      end
      local entry = cjson.decode(value)
      if entry.used then
        return cjson.encode({ reuseDetected = true, family = entry.family })
      end
      entry.used = true
      redis.call('set', key, cjson.encode(entry), 'EX', redis.call('ttl', key))
      return cjson.encode({ accessToken = entry.accessToken, family = entry.family, reuseDetected = false })
    `;

    const result = (await this.redis.eval(luaScript, 1, refreshTokenKey)) as
      | string
      | null;

    if (!result) {
      return undefined;
    }

    const parsed = JSON.parse(result) as {
      accessToken?: string;
      family: string;
      reuseDetected: boolean;
    };

    if (parsed.reuseDetected) {
      return { reuseDetected: true, family: parsed.family };
    }

    const token = await this.getToken(parsed.accessToken!);
    if (!token) {
      return undefined;
    }

    return {
      token,
      family: parsed.family,
      reuseDetected: false,
    };
  }

  /**
   * 吊销整个令牌族（检测到复用时使用）
   * 删除该 family 下所有 refresh token 及其对应的 access token
   * @param family - 令牌族 ID
   */
  async revokeTokenFamily(family: string): Promise<void> {
    const familyKey = this.getFamilyKey(family);
    const refreshTokens = await this.redis.smembers(familyKey);

    if (refreshTokens.length === 0) {
      await this.redis.del(familyKey);
      return;
    }

    const pipeline = this.redis.pipeline();

    for (const refreshToken of refreshTokens) {
      const refreshTokenKey = this.getRefreshTokenKey(refreshToken);
      const value = await this.redis.get(refreshTokenKey);
      const entry = this.deserialize<{ accessToken: string }>(value);
      if (entry) {
        pipeline.del(this.getTokenKey(entry.accessToken));
        pipeline.del(refreshTokenKey);
      }
    }

    pipeline.del(familyKey);
    await pipeline.exec();
  }

  /**
   * 吊销刷新令牌（同时删除对应访问令牌）
   * @param refreshToken - 刷新令牌
   */
  async revokeRefreshToken(refreshToken: string): Promise<void> {
    const refreshTokenKey = this.getRefreshTokenKey(refreshToken);
    const value = await this.redis.get(refreshTokenKey);
    const entry = this.deserialize<{
      accessToken: string;
      family: string;
    }>(value);
    if (!entry) {
      return;
    }

    const pipeline = this.redis.pipeline();
    pipeline.del(refreshTokenKey);
    pipeline.del(this.getTokenKey(entry.accessToken));
    pipeline.srem(this.getFamilyKey(entry.family), refreshToken);
    await pipeline.exec();
  }

  /**
   * 删除 Token
   * @param accessToken - 访问令牌
   */
  async removeToken(accessToken: string): Promise<void> {
    const tokenKey = this.getTokenKey(accessToken);
    const value = await this.redis.get(tokenKey);
    const token = this.deserialize<OAuth2Token>(value);

    const pipeline = this.redis.pipeline();
    pipeline.del(tokenKey);

    if (token?.refreshToken) {
      const refreshTokenKey = this.getRefreshTokenKey(token.refreshToken);
      const refreshValue = await this.redis.get(refreshTokenKey);
      const entry = this.deserialize<{ family: string }>(refreshValue);
      pipeline.del(refreshTokenKey);
      if (entry) {
        pipeline.srem(this.getFamilyKey(entry.family), token.refreshToken);
      }
    }

    await pipeline.exec();
  }
}
