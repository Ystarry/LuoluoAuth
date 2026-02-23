import type { Request, Response } from 'express';

/**
 * 第三方用户信息（归一化后）
 */
export interface ThirdPartyUserInfo {
  /** 提供商标识 */
  provider: string;
  /** 用户在 provider 侧的唯一 ID */
  providerUserId: string;
  /** 用户名/昵称 */
  username?: string;
  /** 邮箱 */
  email?: string;
  /** 手机号 */
  phone?: string;
  /** 头像 */
  avatar?: string;
  /** 原始响应数据 */
  raw?: Record<string, unknown>;
}

/**
 * OAuth2 / OIDC Provider 配置
 */
export interface OAuth2ProviderConfig {
  /** 提供商标识，如 google、wechat、github */
  id: string;
  /** 显示名称 */
  name: string;
  /** 授权端点 */
  authorizationEndpoint: string;
  /** Token 端点 */
  tokenEndpoint: string;
  /** 用户信息端点（OIDC 可省略，使用 id_token） */
  userInfoEndpoint?: string;
  /** 客户端 ID */
  clientId: string;
  /** 客户端密钥 */
  clientSecret: string;
  /** 回调地址 */
  redirectUri: string;
  /** 请求 scope */
  scopes: string[];
  /** 是否在授权 URL 中携带 state 参数（默认 true） */
  useState?: boolean;
  /** 额外授权参数 */
  extraAuthorizationParams?: Record<string, string>;
  /**
   * 将 token 端点响应归一化为 accessToken
   * 默认取 response.access_token
   */
  tokenExtractor?: (response: Record<string, unknown>) => string;
  /**
   * 使用 accessToken 获取并归一化用户信息
   */
  userInfoExtractor: (response: Record<string, unknown>) => ThirdPartyUserInfo;
  /**
   * OIDC 模式下从 id_token payload 提取用户信息
   */
  idTokenExtractor?: (payload: Record<string, unknown>) => ThirdPartyUserInfo;
}

/**
 * 第三方登录后，业务方将 ThirdPartyUserInfo 映射为本地用户并登录
 */
export interface ThirdPartyLoginHandler {
  (
    userInfo: ThirdPartyUserInfo,
    req: Request,
    res: Response,
  ): Promise<{ userId: string; roles?: string[]; permissions?: string[] }>;
}

/**
 * OAuth2 state 临时存储
 * 用于校验回调时的 state 参数，防止 CSRF
 */
// export interface StateStore {
//   /** 保存 state，返回保存的 key */
//   save(state: string, ttlSeconds: number): Promise<string>;
//   /** 校验并消费 state，返回是否有效 */
//   verify(key: string, state: string): Promise<boolean>;
// }

/**
 * 第三方认证模块配置
 */
export interface ThirdPartyAuthModuleOptions {
  /** 注册的 OAuth2 / OIDC Provider 列表 */
  providers: OAuth2ProviderConfig[];
  /**
   * 登录成功后的处理函数
   * 负责把第三方用户信息映射成本地用户，并决定 roles / permissions
   */
  loginHandler: ThirdPartyLoginHandler;
  /**
   * 用于签名 OAuth2 state 的密钥
   * 防止 CSRF，生产环境必须配置强密钥
   */
  stateSecret: string;
}

/**
 * Passport Bridge 配置
 */
export interface PassportBridgeOptions {
  /** Passport 实例（通常即 import * as passport from 'passport'） */
  passport: PassportInstance;
  /** Passport 策略实例映射，key 为策略名 */
  strategies: Record<string, PassportStrategyLike>;
  /** 登录成功后的处理函数 */
  loginHandler: ThirdPartyLoginHandler;
}

/**
 * 最小化的 Passport 实例接口
 */
export interface PassportInstance {
  use(name: string, strategy: PassportStrategyLike): void;
  authenticate(
    name: string,
    options?: Record<string, unknown>,
    callback?: (
      err: Error | null,
      user?: unknown,
      info?: unknown,
    ) => void | Promise<void>,
  ): (req: unknown, res: unknown, next: unknown) => void;
}

/**
 * 最小化的 Passport Strategy 接口
 */
export interface PassportStrategyLike {
  name?: string;
  authenticate(req: unknown, options?: Record<string, unknown>): void;
}