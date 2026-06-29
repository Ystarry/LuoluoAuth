import { Inject, Injectable } from '@nestjs/common';
import type { Request } from 'express';
import { AuthService } from '../../auth/auth.service';

/**
 * Token 读取来源
 */
export type TokenSource = 'header' | 'cookie' | 'query';

/**
 * 授权码换取 Token 后的用户信息解析结果
 */
export interface SsoCodeExchangeResult {
  /** 用户 ID */
  userId: string;
  /** 访问令牌 */
  accessToken?: string;
  /** 刷新令牌 */
  refreshToken?: string;
  /** 用户名 */
  username?: string;
  /** 角色列表 */
  roles?: string[];
  /** 权限列表 */
  permissions?: string[];
  /** 原始响应数据 */
  raw?: Record<string, unknown>;
}

/**
 * 授权码换取 Token 处理器
 * 由业务方实现，用于对接具体的 SSO 授权服务器
 */
export type SsoCodeExchangeHandler = (
  code: string,
  state?: string,
) => Promise<SsoCodeExchangeResult>;

/**
 * SSO 服务配置选项
 */
export interface SsoServiceConfig {
  /** Token 读取策略顺序（默认 ['header', 'cookie', 'query']） */
  tokenStrategy?: TokenSource[];
  /** SSO 登录页 URL */
  loginUrl?: string;
  /** Token 参数名（默认 'token'） */
  tokenParamName?: string;
  /**
   * 授权码换取 Token 处理器
   * 提供后，handleCallback 将调用该处理器换取用户信息
   */
  codeExchangeHandler?: SsoCodeExchangeHandler;
}

/**
 * SSO 回调查询参数
 */
export interface SsoCallbackQuery {
  /** 授权码 */
  code?: string;
  /** 状态值 */
  state?: string;
  /** 错误码 */
  error?: string;
  /** 错误描述 */
  error_description?: string;
}

/**
 * SSO 重定向表单数据
 * 用于将 Token 通过 POST body 安全传递给 SSO 登录页，避免暴露在 URL 中
 */
export interface SsoRedirectFormData {
  /** 登录页 URL */
  url: string;
  /** 提交表单所需的数据 */
  fields: {
    redirect_uri: string;
    token: string;
  };
}

/**
 * SSO 用户信息
 */
export interface SsoUserInfo {
  /** 用户 ID */
  userId: string;
  /** 用户名 */
  username?: string;
  /** 角色列表 */
  roles?: string[];
  /** 权限列表 */
  permissions?: string[];
}

/**
 * SSO 服务
 * 提供跨域单点登录的跳转构建和回调处理功能
 */
@Injectable()
export class SsoService {
  /**
   * @param authService - 认证服务实例
   * @param config - SSO 服务配置
   */
  constructor(
    @Inject(AuthService)
    private readonly authService: AuthService,
    @Inject('SSO_CONFIG')
    private readonly config: SsoServiceConfig,
  ) {}

  /**
   * 构建 SSO 重定向表单数据
   * 将 Token 通过 POST body 安全传递给 SSO 登录页，避免暴露在 URL query 中
   * @param clientAppUrl - 客户端应用回调地址
   * @param token - 当前用户的认证 Token
   * @returns 登录页 URL 及需要提交的表单数据
   */
  buildRedirectFormData(
    clientAppUrl: string,
    token: string,
  ): SsoRedirectFormData {
    const loginUrl = this.config.loginUrl || '/auth/login';

    return {
      url: loginUrl,
      fields: {
        redirect_uri: clientAppUrl,
        token,
      },
    };
  }

  /**
   * 构建 SSO 重定向 URL（已弃用）
   * 该方法会将 Token 暴露在 URL query 中，存在泄露风险。
   * 请改用 buildRedirectFormData() 并通过 POST body 传递 Token。
   * @deprecated Use buildRedirectFormData instead.
   */
  buildRedirectUrl(clientAppUrl: string, token: string): string {
    const loginUrl = this.config.loginUrl || '/auth/login';
    const tokenParamName = this.config.tokenParamName || 'token';

    const url = new URL(loginUrl, 'http://localhost');
    url.searchParams.set('redirect_uri', clientAppUrl);
    url.searchParams.set(tokenParamName, token);

    return url.toString();
  }

  /**
   * 处理 SSO 回调
   * 1. 若配置了 codeExchangeHandler，则调用业务方实现的授权码换 Token 逻辑
   * 2. 否则回退到本地 Token 校验模式（适用于本框架自身作为 SSO 认证中心）
   * @param query - 回调查询参数
   * @returns 用户信息
   * @throws 授权失败时抛出异常
   */
  async handleCallback(query: SsoCallbackQuery): Promise<SsoUserInfo> {
    if (query.error) {
      throw new Error(
        `SSO authorization failed: ${query.error} - ${query.error_description || ''}`,
      );
    }

    if (!query.code) {
      throw new Error('Missing authorization code in SSO callback');
    }

    // 优先使用业务方提供的授权码换 Token 处理器
    if (this.config.codeExchangeHandler) {
      const result = await this.config.codeExchangeHandler(
        query.code,
        query.state,
      );
      if (!result || !result.userId) {
        throw new Error('SSO code exchange did not return a valid userId');
      }
      return {
        userId: result.userId,
        username: result.username || result.userId,
        roles: result.roles,
        permissions: result.permissions,
      };
    }

    // 回退：本框架作为 SSO 认证中心时，code 直接为本地 Token
    try {
      const session = await this.authService.validateToken(query.code);
      return {
        userId: session.userId,
        username: session.userId,
        roles: session.roles,
        permissions: session.permissions,
      };
    } catch {
      throw new Error('Invalid authorization code');
    }
  }

  /**
   * 从请求中按策略顺序查找 Token
   * 支持从 header、cookie、query 中读取
   * @param request - HTTP 请求对象
   * @returns Token 字符串，未找到则返回 undefined
   */
  extractTokenFromRequest(request: Request): string | undefined {
    const strategies = this.config.tokenStrategy || [
      'header',
      'cookie',
      'query',
    ];
    const tokenParamName = this.config.tokenParamName || 'token';

    for (const source of strategies) {
      const token = this.extractTokenFromSource(
        request,
        source,
        tokenParamName,
      );
      if (token) {
        return token;
      }
    }

    return undefined;
  }

  /**
   * 从指定来源提取 Token
   * @param request - HTTP 请求对象
   * @param source - Token 来源
   * @param paramName - 参数名
   * @returns Token 字符串，未找到则返回 undefined
   */
  private extractTokenFromSource(
    request: Request,
    source: TokenSource,
    paramName: string,
  ): string | undefined {
    switch (source) {
      case 'header': {
        const authHeader = request.headers.authorization;
        if (authHeader) {
          const [type, token] = authHeader.split(' ');
          return type === 'Bearer' ? token : undefined;
        }
        return undefined;
      }
      case 'cookie': {
        const cookies = request.cookies as Record<string, string> | undefined;
        return cookies?.[paramName];
      }
      case 'query': {
        const query = request.query as Record<string, unknown> | undefined;
        const value = query?.[paramName];
        return typeof value === 'string' ? value : undefined;
      }
      default:
        return undefined;
    }
  }
}
