import { randomUUID, timingSafeEqual } from 'crypto';

/**
 * OAuth2 授权类型
 */
export type GrantType =
  | 'authorization_code'
  | 'password'
  | 'client_credentials'
  | 'refresh_token'
  | 'device_code';

/**
 * 用户名密码校验器
 * 用于 password 授权模式校验用户身份
 */
export type UserValidator = (
  username: string,
  password: string,
) => Promise<{
  userId: string;
  roles?: string[];
  permissions?: string[];
} | null>;

/**
 * OAuth2 客户端信息
 */
export interface OAuth2Client {
  /** 客户端 ID */
  clientId: string;
  /** 客户端密钥 */
  clientSecret: string;
  /** 允许的回调地址列表 */
  redirectUris: string[];
  /** 支持的授权类型 */
  grants: GrantType[];
  /** 客户端名称 */
  name?: string;
  /** 允许的 scope */
  scopes?: string[];
  /** 是否为公共客户端（SPA/移动端等无法安全保存密钥的客户端） */
  isPublic?: boolean;
}

/**
 * OAuth2 授权码信息
 */
export interface AuthorizationCode {
  /** 授权码 */
  code: string;
  /** 客户端 ID */
  clientId: string;
  /** 用户 ID */
  userId: string;
  /** 回调地址 */
  redirectUri: string;
  /** 过期时间戳 */
  expiresAt: number;
  /** 状态值 */
  state?: string;
  /** 请求的 scope */
  scope?: string;
  /** OIDC nonce */
  nonce?: string;
  /** PKCE code_challenge */
  codeChallenge?: string;
  /** PKCE code_challenge_method */
  codeChallengeMethod?: 'plain' | 'S256';
}

/**
 * OAuth2 Token 信息
 */
export interface OAuth2Token {
  /** 访问令牌 */
  accessToken: string;
  /** 刷新令牌 */
  refreshToken?: string;
  /** Token 类型 */
  tokenType: string;
  /** 过期时间（秒） */
  expiresIn: number;
  /** 请求的 scope */
  scope?: string;
  /** 关联用户 ID（内部使用） */
  userId?: string;
  /** OIDC ID Token */
  idToken?: string;
}

/**
 * OAuth2 Device Code 信息 (RFC 8628)
 * 用于输入受限设备（智能电视、CLI 工具等）的授权流程
 */
export interface DeviceCode {
  /** 设备码（展示给用户） */
  deviceCode: string;
  /** 用户码（用户输入到验证页面） */
  userCode: string;
  /** 验证 URI */
  verificationUri: string;
  /** 完整验证 URI（含 user_code） */
  verificationUriComplete?: string;
  /** 客户端 ID */
  clientId: string;
  /** 请求的 scope */
  scope?: string;
  /** 轮询间隔（秒） */
  interval: number;
  /** 过期时间戳 */
  expiresAt: number;
  /** 是否已被授权 */
  authorized?: boolean;
  /** 授权后的用户 ID */
  userId?: string;
}

/**
 * 消费刷新令牌的结果
 */
export type ConsumeRefreshTokenSuccess = {
  token: OAuth2Token;
  family: string;
  reuseDetected: false;
};
export type ConsumeRefreshTokenReuse = {
  reuseDetected: true;
  family: string;
};
export type ConsumeRefreshTokenResult =
  | ConsumeRefreshTokenSuccess
  | ConsumeRefreshTokenReuse
  | undefined;

/**
 * OAuth2 客户端与 Token 存储接口
 * 支持 refresh token rotation + reuse detection
 * 可对接内存实现或 Redis 实现
 */
export interface OAuth2ClientStore {
  /** 注册客户端 */
  registerClient(client: OAuth2Client): void | Promise<void>;
  /** 获取客户端信息 */
  getClient(
    clientId: string,
  ): OAuth2Client | undefined | Promise<OAuth2Client | undefined>;
  /** 验证客户端密钥 */
  verifyClientSecret(
    clientId: string,
    clientSecret: string,
  ): boolean | Promise<boolean>;
  /** 验证回调地址是否合法 */
  verifyRedirectUri(
    clientId: string,
    redirectUri: string,
  ): boolean | Promise<boolean>;
  /** 验证客户端是否支持指定授权类型 */
  supportsGrant(
    clientId: string,
    grantType: GrantType,
  ): boolean | Promise<boolean>;
  /** 保存授权码 */
  saveAuthorizationCode(code: AuthorizationCode): void | Promise<void>;
  /** 消费授权码（一次性使用） */
  consumeAuthorizationCode(
    code: string,
  ): AuthorizationCode | undefined | Promise<AuthorizationCode | undefined>;
  /** 保存 Token */
  saveToken(token: OAuth2Token, family?: string): void | Promise<void>;
  /** 根据访问令牌获取 Token 信息 */
  getToken(
    accessToken: string,
  ): OAuth2Token | undefined | Promise<OAuth2Token | undefined>;
  /** 消费刷新令牌（支持轮换与复用检测） */
  consumeRefreshToken(
    refreshToken: string,
  ): ConsumeRefreshTokenResult | Promise<ConsumeRefreshTokenResult>;
  /** 吊销整个令牌族（检测到复用时使用） */
  revokeTokenFamily(family: string): void | Promise<void>;
  /** 吊销刷新令牌（同时删除对应访问令牌） */
  revokeRefreshToken(refreshToken: string): void | Promise<void>;
  /** 删除 Token */
  removeToken(accessToken: string): void | Promise<void>;
}

/**
 * 刷新令牌条目（支持轮换与复用检测）
 */
interface RefreshTokenEntry {
  /** 关联的访问令牌 */
  accessToken: string;
  /** 所属令牌族（同一登录链路的 refresh token 共享同一 family） */
  family: string;
  /** 是否已被使用过 */
  used: boolean;
}

/**
 * OAuth2 客户端内存存储
 * 提供客户端注册、授权码和 Token 的临时存储
 * 支持 refresh token rotation + reuse detection
 */
export class InMemoryOAuth2ClientStore implements OAuth2ClientStore {
  private readonly clients = new Map<string, OAuth2Client>();
  private readonly authorizationCodes = new Map<string, AuthorizationCode>();
  private readonly tokens = new Map<string, OAuth2Token>();
  /** refreshToken -> RefreshTokenEntry */
  private readonly refreshTokens = new Map<string, RefreshTokenEntry>();
  /** family -> Set<refreshToken> */
  private readonly tokenFamilies = new Map<string, Set<string>>();

  /**
   * 注册客户端
   * @param client - 客户端信息
   */
  registerClient(client: OAuth2Client): void {
    this.clients.set(client.clientId, client);
  }

  /**
   * 根据 clientId 获取客户端信息
   * @param clientId - 客户端 ID
   * @returns 客户端信息，不存在则返回 undefined
   */
  getClient(clientId: string): OAuth2Client | undefined {
    return this.clients.get(clientId);
  }

  /**
   * 验证客户端密钥
   * 使用 timingSafeEqual 防止时序攻击
   * @param clientId - 客户端 ID
   * @param clientSecret - 客户端密钥
   * @returns 是否验证通过
   */
  verifyClientSecret(clientId: string, clientSecret: string): boolean {
    const client = this.clients.get(clientId);
    if (!client || !client.clientSecret) {
      return false;
    }
    const expected = Buffer.from(client.clientSecret, 'utf8');
    const actual = Buffer.from(clientSecret, 'utf8');
    if (expected.length !== actual.length) {
      return false;
    }
    return timingSafeEqual(expected, actual);
  }

  /**
   * 验证回调地址是否合法
   * @param clientId - 客户端 ID
   * @param redirectUri - 回调地址
   * @returns 是否合法
   */
  verifyRedirectUri(clientId: string, redirectUri: string): boolean {
    const client = this.clients.get(clientId);
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
  supportsGrant(clientId: string, grantType: GrantType): boolean {
    const client = this.clients.get(clientId);
    if (!client) {
      return false;
    }
    return client.grants.includes(grantType);
  }

  /**
   * 保存授权码
   * @param code - 授权码信息
   */
  saveAuthorizationCode(code: AuthorizationCode): void {
    this.authorizationCodes.set(code.code, code);
  }

  /**
   * 获取并消费授权码（使用后删除）
   * @param code - 授权码字符串
   * @returns 授权码信息，不存在或已过期则返回 undefined
   */
  consumeAuthorizationCode(code: string): AuthorizationCode | undefined {
    const authCode = this.authorizationCodes.get(code);
    if (!authCode) {
      return undefined;
    }

    // 检查是否过期
    if (Date.now() > authCode.expiresAt) {
      this.authorizationCodes.delete(code);
      return undefined;
    }

    // 消费后删除（一次性使用）
    this.authorizationCodes.delete(code);
    return authCode;
  }

  /**
   * 保存 Token
   * @param token - Token 信息
   * @param family - 令牌族 ID（refresh_token 模式复用同一 family）
   */
  saveToken(token: OAuth2Token, family?: string): void {
    this.tokens.set(token.accessToken, token);
    if (token.refreshToken) {
      const tokenFamily = family || randomUUID();
      this.refreshTokens.set(token.refreshToken, {
        accessToken: token.accessToken,
        family: tokenFamily,
        used: false,
      });

      // 维护令牌族索引
      if (!this.tokenFamilies.has(tokenFamily)) {
        this.tokenFamilies.set(tokenFamily, new Set<string>());
      }
      this.tokenFamilies.get(tokenFamily)!.add(token.refreshToken);
    }
  }

  /**
   * 根据访问令牌获取 Token 信息
   * @param accessToken - 访问令牌
   * @returns Token 信息，不存在则返回 undefined
   */
  getToken(accessToken: string): OAuth2Token | undefined {
    return this.tokens.get(accessToken);
  }

  /**
   * 消费刷新令牌（支持轮换与复用检测）
   * @param refreshToken - 刷新令牌
   * @returns 旧 Token 信息和令牌族 ID；若已复用则返回 reuseDetected = true
   */
  consumeRefreshToken(refreshToken: string): ConsumeRefreshTokenResult {
    const entry = this.refreshTokens.get(refreshToken);
    if (!entry) {
      return undefined;
    }

    const token = this.tokens.get(entry.accessToken);
    if (!token) {
      return undefined;
    }

    // 复用检测：若该 refresh token 已被使用过，说明被盗用
    if (entry.used) {
      return { reuseDetected: true, family: entry.family };
    }

    // 标记为已使用
    entry.used = true;

    return { token, family: entry.family, reuseDetected: false };
  }

  /**
   * 吊销整个令牌族（检测到复用时使用）
   * 删除该 family 下所有 refresh token 及其对应的 access token
   * @param family - 令牌族 ID
   */
  revokeTokenFamily(family: string): void {
    const tokens = this.tokenFamilies.get(family);
    if (!tokens) {
      return;
    }

    for (const refreshToken of tokens) {
      const entry = this.refreshTokens.get(refreshToken);
      if (entry) {
        this.tokens.delete(entry.accessToken);
        this.refreshTokens.delete(refreshToken);
      }
    }

    this.tokenFamilies.delete(family);
  }

  /**
   * 吊销刷新令牌（同时删除对应访问令牌）
   * @param refreshToken - 刷新令牌
   */
  revokeRefreshToken(refreshToken: string): void {
    const entry = this.refreshTokens.get(refreshToken);
    if (!entry) {
      return;
    }

    this.refreshTokens.delete(refreshToken);
    this.tokens.delete(entry.accessToken);

    // 从令牌族中移除
    const familyTokens = this.tokenFamilies.get(entry.family);
    if (familyTokens) {
      familyTokens.delete(refreshToken);
      if (familyTokens.size === 0) {
        this.tokenFamilies.delete(entry.family);
      }
    }
  }

  /**
   * 删除 Token
   * @param accessToken - 访问令牌
   */
  removeToken(accessToken: string): void {
    const token = this.tokens.get(accessToken);
    this.tokens.delete(accessToken);
    if (token?.refreshToken) {
      const entry = this.refreshTokens.get(token.refreshToken);
      this.refreshTokens.delete(token.refreshToken);
      if (entry) {
        const familyTokens = this.tokenFamilies.get(entry.family);
        if (familyTokens) {
          familyTokens.delete(token.refreshToken);
          if (familyTokens.size === 0) {
            this.tokenFamilies.delete(entry.family);
          }
        }
      }
    }
  }
}
