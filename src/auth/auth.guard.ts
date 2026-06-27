import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Inject,
  Injectable,
  Optional,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request, Response } from 'express';
import { RpcException } from '@nestjs/microservices'; // 需安装: @nestjs/microservices
import jwt from 'jsonwebtoken'; // 需安装: jsonwebtoken
import { AuthService } from './auth.service';
import { CookieService } from './cookie/cookie.service';
import {
  PermissionEngine,
  SessionWithPermissions,
} from './permission/permission.engine';
import {
  AUTH_METADATA_KEY,
  ROLES_METADATA_KEY,
  PERMISSIONS_METADATA_KEY,
  SAFE_AUTH_METADATA_KEY,
} from './auth.decorator';
import {
  extractBearerToken,
  extractTokenFromRpcContext,
} from './utils/token.util';

/**
 * JWT Token 解码后的载荷（不校验签名）
 */
interface DecodedToken {
  /** 会话 ID */
  sessionId: string;
  /** 用户 ID */
  userId: string;
  /** 设备标识（可选） */
  device?: string;
  /** 签发时间戳 */
  iat?: number;
  /** 过期时间戳 */
  exp?: number;
}

/**
 * 认证守卫
 * 从请求头中提取 Token 并校验，支持黑名单检查、自动续签、角色和权限的 RBAC 校验
 */
@Injectable()
export class AuthGuard implements CanActivate {
  /**
   * @param authService - 认证服务实例
   * @param reflector - 反射器，用于读取元数据
   * @param permissionEngine - 权限校验引擎
   */
  constructor(
    @Inject(AuthService)
    private readonly authService: AuthService,
    private readonly reflector: Reflector,
    @Inject(PermissionEngine)
    private readonly permissionEngine: PermissionEngine,
    @Inject(CookieService)
    @Optional()
    private readonly cookieService?: CookieService,
  ) {}

  /**
   * 判断是否允许通过
   * 1. 提取 Token
   * 2. 校验 Token 有效性（先确保 Token 合法）
   * 3. 检查黑名单
   * 4. 自动续签（若配置启用）
   * 5. 校验角色权限
   * 6. 校验操作权限
   * @param context - 执行上下文
   * @returns 是否通过校验
   * @throws UnauthorizedException Token 无效或缺失时抛出
   * @throws ForbiddenException 账号被封禁或角色/权限不足时抛出
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();

    // 检查当前路由是否有认证相关的元数据
    const hasAuthMetadata: boolean =
      !!this.reflector.getAllAndOverride<unknown>(AUTH_METADATA_KEY, [
        context.getHandler(),
        context.getClass(),
      ]) ||
      !!this.reflector.getAllAndOverride<unknown>(ROLES_METADATA_KEY, [
        context.getHandler(),
        context.getClass(),
      ]) ||
      !!this.reflector.getAllAndOverride<unknown>(PERMISSIONS_METADATA_KEY, [
        context.getHandler(),
        context.getClass(),
      ]) ||
      !!this.reflector.getAllAndOverride<unknown>(SAFE_AUTH_METADATA_KEY, [
        context.getHandler(),
        context.getClass(),
      ]);

    // 如果没有认证相关元数据，直接放行
    if (!hasAuthMetadata) {
      return true;
    }

    const tokenSource = this.extractToken(request);

    if (!tokenSource) {
      throw new UnauthorizedException('Missing authorization token');
    }

    const { token, source } = tokenSource;

    // 先校验 Token 有效性（防止伪造 Token 触发黑名单查询）
    // 同时传入当前请求的 IP 与 User-Agent 进行设备指纹绑定校验
    let session: SessionWithPermissions;
    let decoded: DecodedToken;
    try {
      session = await this.authService.validateToken(
        token,
        request.ip,
        request.headers['user-agent'],
      );
      decoded = jwt.decode(token) as DecodedToken;
      // 将会话数据挂载到请求对象上
      request['user'] = session;
    } catch {
      throw new UnauthorizedException('Invalid or expired token');
    }

    // 黑名单检查（在 Token 校验通过后执行）
    if (decoded && decoded.userId) {
      const isBanned = await this.authService.isBanned(decoded.userId);
      if (isBanned) {
        throw new ForbiddenException('账号已封禁');
      }
    }

    // Cookie 模式自动续期：每次请求后刷新 Cookie 有效期
    if (source === 'cookie' && this.cookieService?.isEnabled()) {
      const response = context.switchToHttp().getResponse<Response>();
      this.cookieService.write(response, token);
    }

    // JWT 自动续签逻辑
    if (decoded) {
      await this.tryAutoRenew(token, decoded);
    }

    // 校验角色
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(
      ROLES_METADATA_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (requiredRoles && requiredRoles.length > 0) {
      const hasRole = this.permissionEngine.hasRole(session, requiredRoles);
      if (!hasRole) {
        throw new ForbiddenException(
          `Requires one of roles: ${requiredRoles.join(', ')}`,
        );
      }
    }

    // 校验权限
    const requiredPermissions = this.reflector.getAllAndOverride<string[]>(
      PERMISSIONS_METADATA_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (requiredPermissions && requiredPermissions.length > 0) {
      const hasPermission = this.permissionEngine.hasPermission(
        session,
        requiredPermissions,
      );
      if (!hasPermission) {
        throw new ForbiddenException(
          `Requires permissions: ${requiredPermissions.join(', ')}`,
        );
      }
    }

    // 校验二级认证
    const requireSafeAuth = this.reflector.getAllAndOverride<boolean>(
      SAFE_AUTH_METADATA_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (requireSafeAuth) {
      const safeAuthValid = this.authService.isSafeAuth(session);
      if (!safeAuthValid) {
        throw new ForbiddenException(
          'Requires secondary authentication (safeAuth)',
        );
      }
    }

    return true;
  }

  /**
   * 尝试自动续签会话
   * 如果配置了 autoRenew: true，且 token 剩余时间小于总有效期的 1/3，则自动续签
   * @param token - 当前 Token 字符串
   * @param decoded - 解码后的 Token 载荷
   */
  private async tryAutoRenew(
    token: string,
    decoded: DecodedToken,
  ): Promise<void> {
    const config = this.authService.getConfig();
    if (!config || !config.autoRenew) {
      return;
    }

    const now = Math.floor(Date.now() / 1000);
    const iat = decoded.iat || now;
    const exp = decoded.exp || now;
    const totalTtl = exp - iat;
    const remaining = exp - now;

    // 剩余时间小于总有效期的 1/3 时续签
    if (totalTtl > 0 && remaining < totalTtl / 3) {
      await this.authService.renewSession(decoded.sessionId);
    }
  }

  /**
   * 从请求中提取 Token
   * 优先从 Authorization 头读取 Bearer Token，未找到时回退到 Cookie
   * @param request - HTTP 请求对象
   * @returns Token 及其来源，未找到则返回 undefined
   */
  private extractToken(
    request: Request,
  ): { token: string; source: 'header' | 'cookie' } | undefined {
    const authHeader = request.headers.authorization;
    const headerToken = extractBearerToken(authHeader);
    if (headerToken) {
      return { token: headerToken, source: 'header' };
    }

    if (this.cookieService?.isEnabled()) {
      const cookieToken = this.cookieService.read(request);
      if (cookieToken) {
        return { token: cookieToken, source: 'cookie' };
      }
    }

    return undefined;
  }

  /**
   * 创建微服务专用的混合守卫
   * 支持从 gRPC metadata 或 TCP 消息头中提取 token
   * @returns 微服务守卫类
   */
  static forMicroservice(): typeof AuthGuard {
    return class MicroserviceAuthGuard extends AuthGuard {
      /**
       * 微服务场景下的权限校验
       * 从 gRPC metadata 或 TCP 数据包中提取 Token 并校验
       * @param context - 执行上下文
       * @returns 是否通过校验
       * @throws RpcException Token 无效或缺失时抛出
       */
      async canActivate(context: ExecutionContext): Promise<boolean> {
        const type = context.getType<'http' | 'rpc'>();

        // HTTP 场景回退到父类逻辑
        if (type === 'http') {
          return super.canActivate(context);
        }

        // RPC 场景：从 metadata 中提取 token
        const rpcContext: unknown = context.switchToRpc().getContext();
        const token = extractTokenFromRpcContext(rpcContext);

        if (!token) {
          throw new RpcException('Missing authorization token');
        }

        // 先校验 Token 有效性（防止伪造 Token 触发黑名单查询）
        let session: SessionWithPermissions;
        try {
          const clientIp = this.extractClientIpFromRpc(rpcContext);
          session = await this.authService.validateRpcToken(token, clientIp);
        } catch (error: unknown) {
          const message =
            error instanceof Error ? error.message : 'Invalid or expired token';
          throw new RpcException(message);
        }

        // 黑名单检查（在 Token 校验通过后执行）
        const isBanned = await this.authService.isBanned(session.userId);
        if (isBanned) {
          throw new RpcException('账号已封禁');
        }

        // 将 session 挂载到 RPC 上下文
        if (rpcContext && typeof rpcContext === 'object') {
          (rpcContext as Record<string, unknown>)['user'] = session;
        }

        // 校验角色
        const requiredRoles = this.reflector.getAllAndOverride<string[]>(
          ROLES_METADATA_KEY,
          [context.getHandler(), context.getClass()],
        );

        if (requiredRoles && requiredRoles.length > 0) {
          const hasRole = this.permissionEngine.hasRole(session, requiredRoles);
          if (!hasRole) {
            throw new RpcException(
              `Requires one of roles: ${requiredRoles.join(', ')}`,
            );
          }
        }

        // 校验权限
        const requiredPermissions = this.reflector.getAllAndOverride<string[]>(
          PERMISSIONS_METADATA_KEY,
          [context.getHandler(), context.getClass()],
        );

        if (requiredPermissions && requiredPermissions.length > 0) {
          const hasPermission = this.permissionEngine.hasPermission(
            session,
            requiredPermissions,
          );
          if (!hasPermission) {
            throw new RpcException(
              `Requires permissions: ${requiredPermissions.join(', ')}`,
            );
          }
        }

        // 校验二级认证
        const requireSafeAuth = this.reflector.getAllAndOverride<boolean>(
          SAFE_AUTH_METADATA_KEY,
          [context.getHandler(), context.getClass()],
        );

        if (requireSafeAuth) {
          const safeAuthValid = this.authService.isSafeAuth(session);
          if (!safeAuthValid) {
            throw new RpcException(
              'Requires secondary authentication (safeAuth)',
            );
          }
        }

        return true;
      }

      /**
       * 从 RPC 上下文中提取客户端 IP
       * @param rpcContext - RPC 上下文
       * @returns IP 字符串，未找到则返回 undefined
       */
      private extractClientIpFromRpc(rpcContext: unknown): string | undefined {
        if (!rpcContext || typeof rpcContext !== 'object') {
          return undefined;
        }

        const ctx = rpcContext as Record<string, unknown>;
        return (ctx['ip'] || ctx['clientIp'] || ctx['peer'] || undefined) as
          | string
          | undefined;
      }
    };
  }
}
