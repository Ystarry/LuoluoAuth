import { Injectable, Logger, Optional, Inject } from '@nestjs/common';
import { AuthService } from '../../auth/auth.service';
import { extractBearerToken } from '../../auth/utils/token.util';

/**
 * luoluo-auth Passport 策略适配器
 *
 * 将 luoluo-auth 的认证能力封装为 Passport 风格的验证函数，
 * 方便在 NestJS Guard 中直接使用，无需额外封装。
 *
 * ## 使用示例
 * ```typescript
 * import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
 * import { PassportAuthStrategy } from 'luoluo-auth';
 *
 * @Injectable()
 * export class AuthGuard implements CanActivate {
 *   constructor(private readonly passportStrategy: PassportAuthStrategy) {}
 *
 *   async canActivate(context: ExecutionContext): Promise<boolean> {
 *     const request = context.switchToHttp().getRequest();
 *     const user = await this.passportStrategy.validate(request);
 *     if (!user) {
 *       throw new UnauthorizedException();
 *     }
 *     request.user = user;
 *     return true;
 *   }
 * }
 * ```
 */
@Injectable()
export class PassportAuthStrategy {
  private readonly logger = new Logger(PassportAuthStrategy.name);

  constructor(
    @Inject(AuthService)
    private readonly authService: AuthService,
    @Optional()
    @Inject('PASSPORT_AUTH_CONFIG')
    private readonly config?: PassportAuthConfig,
  ) {}

  /**
   * 验证请求中的 Token 并返回用户信息
   * 模拟 Passport 策略的 validate 方法签名
   *
   * @param request - HTTP 请求对象
   * @returns 验证通过的用户信息，失败返回 null
   */
  async validate(request: PassportRequest): Promise<PassportUser | null> {
    const token = this.extractToken(request);

    if (!token) {
      this.logger.debug('No token found in request');
      return null;
    }

    try {
      const session = await this.authService.validateToken(
        token,
        this.config?.extractIp ? this.config.extractIp(request) : request.ip,
        this.config?.extractUserAgent
          ? this.config.extractUserAgent(request)
          : (request.headers?.['user-agent'] as string),
      );

      return {
        userId: session.userId,
        roles: session.roles || [],
        permissions: session.permissions || [],
        token,
      };
    } catch {
      this.logger.debug('Token validation failed');
      return null;
    }
  }

  /**
   * 从请求中提取 Token
   * 优先级：Authorization header > Cookie
   */
  private extractToken(request: PassportRequest): string | undefined {
    // 优先从 Authorization header 提取
    const authHeader =
      request.headers?.authorization || request.headers?.Authorization;
    if (authHeader) {
      return extractBearerToken(authHeader as string);
    }

    // 从 Cookie 中提取
    const cookieName = this.config?.cookieName || 'token';
    const cookies = request.cookies;
    if (cookies?.[cookieName]) {
      return cookies[cookieName] as string;
    }

    if (this.config?.tokenExtractor) {
      return this.config.tokenExtractor(request);
    }

    return undefined;
  }
}

/**
 * Passport 适配器配置
 */
export interface PassportAuthConfig {
  /** Cookie 名称（默认 'token'） */
  cookieName?: string;
  /** 自定义 Token 提取器 */
  tokenExtractor?: (request: PassportRequest) => string | undefined;
  /** 自定义 IP 提取器 */
  extractIp?: (request: PassportRequest) => string | undefined;
  /** 自定义 User-Agent 提取器 */
  extractUserAgent?: (request: PassportRequest) => string | undefined;
}

/**
 * 最小化的 HTTP 请求接口
 */
export interface PassportRequest {
  ip?: string;
  headers?: Record<string, unknown>;
  cookies?: Record<string, unknown>;
  [key: string]: unknown;
}

/**
 * Passport 验证后的用户信息
 */
export interface PassportUser {
  userId: string;
  roles: string[];
  permissions: string[];
  token: string;
}
