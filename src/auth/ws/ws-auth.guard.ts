import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
  Optional,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from '../auth.service';
import { CookieService } from '../cookie/cookie.service';
import { extractBearerToken } from '../utils/token.util';

/**
 * WebSocket 认证守卫
 * 支持从 Socket.IO handshake（auth / query / headers）或原生 WS upgradeReq 中提取 Token，
 * 校验成功后把用户信息挂载到 client.data.user
 */
@Injectable()
export class WsAuthGuard implements CanActivate {
  constructor(
    @Inject(AuthService)
    private readonly authService: AuthService,
    @Inject(CookieService)
    @Optional()
    private readonly cookieService?: CookieService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const client = context.switchToWs().getClient<unknown>();
    const token = this.extractToken(client);

    if (!token) {
      throw new UnauthorizedException('Missing WebSocket authorization token');
    }

    const clientInfo = this.extractClientInfo(client);

    try {
      const user = await this.authService.validateToken(
        token,
        clientInfo.ip,
        clientInfo.userAgent,
      );

      const clientRecord = client as Record<string, unknown>;
      clientRecord.data = clientRecord.data || {};
      (clientRecord.data as Record<string, unknown>).user = user;
      return true;
    } catch {
      throw new UnauthorizedException('Invalid or expired WebSocket token');
    }
  }

  /**
   * 从 WebSocket 客户端中提取 Token
   * 支持优先级：Socket.IO auth.token > query.token > headers.authorization > Cookie
   */
  private extractToken(client: unknown): string | undefined {
    const handshake = this.getObject(client, 'handshake');
    if (handshake) {
      const authToken = this.getStringFromObject(
        this.getObject(handshake, 'auth'),
        'token',
      );
      if (authToken) {
        return authToken;
      }

      const queryToken = this.getStringFromObject(
        this.getObject(handshake, 'query'),
        'token',
      );
      if (queryToken) {
        return queryToken;
      }

      const authHeader = this.getStringFromObject(
        this.getObject(handshake, 'headers'),
        'authorization',
      );
      const headerToken = extractBearerToken(authHeader);
      if (headerToken) {
        return headerToken;
      }

      const cookieHeader = this.getStringFromObject(
        this.getObject(handshake, 'headers'),
        'cookie',
      );
      if (cookieHeader && this.cookieService?.isEnabled()) {
        return this.readCookie(cookieHeader);
      }
    }

    const upgradeReq = this.getObject(client, 'upgradeReq');
    if (upgradeReq) {
      const url = this.getStringFromObject(upgradeReq, 'url');
      const urlToken = this.extractTokenFromUrl(url);
      if (urlToken) {
        return urlToken;
      }

      const authHeader = this.getStringFromObject(
        this.getObject(upgradeReq, 'headers'),
        'authorization',
      );
      const headerToken = extractBearerToken(authHeader);
      if (headerToken) {
        return headerToken;
      }

      const cookieHeader = this.getStringFromObject(
        this.getObject(upgradeReq, 'headers'),
        'cookie',
      );
      if (cookieHeader && this.cookieService?.isEnabled()) {
        return this.readCookie(cookieHeader);
      }
    }

    return undefined;
  }

  /**
   * 从 URL query 字符串中提取 token
   */
  private extractTokenFromUrl(url?: string): string | undefined {
    if (!url) {
      return undefined;
    }
    try {
      const search = url.split('?')[1];
      if (!search) {
        return undefined;
      }
      const params = new URLSearchParams(search);
      return params.get('token') || undefined;
    } catch {
      return undefined;
    }
  }

  /**
   * 从 Cookie 请求头中读取框架配置的 Cookie Token
   */
  private readCookie(cookieHeader: string): string | undefined {
    const name = this.cookieService?.getName() ?? 'auth-token';
    const match = cookieHeader
      .split(';')
      .map((part) => part.trim())
      .find((part) => part.startsWith(`${name}=`));
    if (!match) {
      return undefined;
    }
    return decodeURIComponent(match.slice(name.length + 1));
  }

  /**
   * 提取客户端 IP 与 User-Agent
   */
  private extractClientInfo(client: unknown): {
    ip?: string;
    userAgent?: string;
  } {
    const handshake = this.getObject(client, 'handshake');
    if (handshake) {
      const headers = this.getObject(handshake, 'headers');
      return {
        ip: this.getStringFromObject(handshake, 'address'),
        userAgent: this.getStringFromObject(headers, 'user-agent'),
      };
    }

    const upgradeReq = this.getObject(client, 'upgradeReq');
    if (upgradeReq) {
      const socket = this.getObject(upgradeReq, 'socket');
      const headers = this.getObject(upgradeReq, 'headers');
      return {
        ip: this.getStringFromObject(socket, 'remoteAddress'),
        userAgent: this.getStringFromObject(headers, 'user-agent'),
      };
    }

    return {};
  }

  /**
   * 安全地从未知对象中读取对象属性
   */
  private getObject(
    value: unknown,
    key: string,
  ): Record<string, unknown> | undefined {
    if (value && typeof value === 'object' && key in value) {
      const v = (value as Record<string, unknown>)[key];
      if (v !== null && typeof v === 'object') {
        return v as Record<string, unknown>;
      }
    }
    return undefined;
  }

  /**
   * 安全地从未知对象中读取字符串属性
   */
  private getStringFromObject(
    obj: Record<string, unknown> | undefined,
    key: string,
  ): string | undefined {
    if (!obj) {
      return undefined;
    }
    return this.asString(obj[key]);
  }

  /**
   * 将未知值标准化为字符串
   */
  private asString(value: unknown): string | undefined {
    if (typeof value === 'string') {
      return value;
    }
    if (
      Array.isArray(value) &&
      value.length > 0 &&
      typeof value[0] === 'string'
    ) {
      return value[0];
    }
    return undefined;
  }
}
