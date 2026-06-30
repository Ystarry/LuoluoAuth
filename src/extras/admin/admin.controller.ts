import {
  BadRequestException,
  Controller,
  Delete,
  Get,
  Inject,
  NotFoundException,
  Optional,
  Post,
  Query,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import type { Request } from 'express';
import { AuthService } from '../../auth/auth.service';
import { extractBearerToken } from '../../auth/utils/token.util';
import { CookieService } from '../../auth/cookie/cookie.service';
import type { AuthFrameworkConfig } from '../../auth/auth.config';
import type {
  SessionStore,
  SessionData,
} from '../../auth/interfaces/session-store.interface';
import type { OAuth2ClientStore, OAuth2Client } from '../oauth2/client-store';

/**
 * Admin 管理接口控制器
 * 提供 Token 管理、会话管理、客户端管理等管理功能
 *
 * ## 路由前缀
 * 所有接口以 `/admin` 为前缀
 *
 * ## 权限要求
 * 需要 admin 角色或 super-admin 权限
 */
@Controller('admin')
export class AdminController {
  constructor(
    @Inject(AuthService)
    private readonly authService: AuthService,
    @Optional()
    @Inject('SESSION_STORE')
    private readonly sessionStore?: SessionStore,
    @Optional()
    @Inject('OAUTH2_CLIENT_STORE')
    private readonly oauth2ClientStore?: OAuth2ClientStore,
    @Optional()
    @Inject(CookieService)
    private readonly cookieService?: CookieService,
    @Optional()
    @Inject('AUTH_CONFIG')
    private readonly authConfig?: AuthFrameworkConfig,
  ) {}

  /**
   * 校验管理员权限
   */
  private async requireAdmin(req: Request): Promise<void> {
    const token = extractBearerToken(req.headers.authorization);
    if (!token) {
      throw new UnauthorizedException('Admin token required');
    }

    let session: SessionData;
    try {
      session = await this.authService.validateToken(
        token,
        req.ip,
        req.headers['user-agent'],
      );
    } catch {
      throw new UnauthorizedException('Invalid admin token');
    }

    const isAdmin =
      session.roles?.includes('admin') ||
      session.roles?.includes('super-admin') ||
      session.permissions?.includes('admin:*') ||
      session.permissions?.includes('*');

    if (!isAdmin) {
      throw new UnauthorizedException('Admin privileges required');
    }
  }

  /**
   * 查询在线用户列表
   * GET /admin/sessions?userId=xxx
   */
  @Get('sessions')
  async listSessions(
    @Req() req: Request,
    @Query('userId') userId?: string,
  ): Promise<Record<string, unknown>> {
    await this.requireAdmin(req);

    const store = this.sessionStore;
    if (!store?.listByUserId) {
      throw new BadRequestException('Session store not configured');
    }

    if (userId) {
      const sessions = await store.listByUserId(userId);
      return { userId, sessions, count: sessions.length };
    }

    return { message: 'userId query parameter required' };
  }

  /**
   * 踢出指定用户的所有会话
   * POST /admin/kick?userId=xxx
   */
  @Post('kick')
  async kickUser(
    @Req() req: Request,
    @Query('userId') userId?: string,
  ): Promise<Record<string, unknown>> {
    await this.requireAdmin(req);

    if (!userId) {
      throw new BadRequestException('userId is required');
    }

    await this.authService.kickUser(userId);
    return { success: true, userId };
  }

  /**
   * 封禁/解封用户
   * POST /admin/ban?userId=xxx&action=banned|unban&duration=3600
   */
  @Post('ban')
  async banUser(
    @Req() req: Request,
    @Query('userId') userId?: string,
    @Query('action') action?: string,
    @Query('duration') duration?: string,
  ): Promise<Record<string, unknown>> {
    await this.requireAdmin(req);

    if (!userId) {
      throw new BadRequestException('userId is required');
    }

    if (action === 'unban') {
      await this.authService.unbanUser(userId);
      return { success: true, userId, action: 'unbanned' };
    }

    const dur = parseInt(duration || '3600', 10);
    await this.authService.banUser(userId, dur);

    return { success: true, userId, action: 'banned', duration: dur };
  }

  /**
   * 查询 OAuth2 客户端列表
   * GET /admin/clients
   */
  @Get('clients')
  async listClients(@Req() req: Request): Promise<Record<string, unknown>> {
    await this.requireAdmin(req);

    if (!this.oauth2ClientStore) {
      throw new BadRequestException('OAuth2 client store not configured');
    }

    return { message: 'Use client management endpoints to register clients' };
  }

  /**
   * 注册 OAuth2 客户端
   * POST /admin/clients
   */
  @Post('clients')
  async registerClient(@Req() req: Request): Promise<Record<string, unknown>> {
    await this.requireAdmin(req);

    const clientStore = this.oauth2ClientStore;
    if (!clientStore) {
      throw new BadRequestException('OAuth2 client store not configured');
    }

    const body = req.body as OAuth2Client & {
      clientId: string;
      clientSecret: string;
      redirectUris: string[];
      grants: string[];
    };

    if (!body.clientId || !body.clientSecret || !body.redirectUris) {
      throw new BadRequestException(
        'clientId, clientSecret, and redirectUris are required',
      );
    }

    const client: OAuth2Client = {
      clientId: body.clientId,
      clientSecret: body.clientSecret,
      redirectUris: body.redirectUris,
      grants: body.grants || ['authorization_code', 'refresh_token'],
      name: body.name,
      scopes: body.scopes,
      isPublic: body.isPublic,
    };

    await clientStore.registerClient(client);
    return {
      success: true,
      client: { clientId: client.clientId, name: client.name },
    };
  }

  /**
   * 删除 OAuth2 客户端
   * DELETE /admin/clients?clientId=xxx
   */
  @Delete('clients')
  async deleteClient(
    @Req() req: Request,
    @Query('clientId') clientId?: string,
  ): Promise<Record<string, unknown>> {
    await this.requireAdmin(req);

    if (!clientId) {
      throw new BadRequestException('clientId is required');
    }

    const store = this.oauth2ClientStore;
    if (!store) {
      throw new BadRequestException('OAuth2 client store not configured');
    }

    const client = await store.getClient(clientId);
    if (!client) {
      throw new NotFoundException('Client not found');
    }

    await store.removeToken(clientId);
    return { success: true, clientId };
  }

  /**
   * 吊销指定 Token
   * POST /admin/revoke?token=xxx
   */
  @Post('revoke')
  async revokeToken(
    @Req() req: Request,
    @Query('token') token?: string,
  ): Promise<Record<string, unknown>> {
    await this.requireAdmin(req);

    if (!token) {
      throw new BadRequestException('token is required');
    }

    await this.authService.logout(token, req.res);

    return { success: true };
  }

  /**
   * 获取框架当前配置信息
   * GET /admin/config
   */
  @Get('config')
  async getConfig(@Req() req: Request): Promise<Record<string, unknown>> {
    await this.requireAdmin(req);

    return {
      cookieMode: this.authConfig?.cookie?.enabled || false,
      fingerprintEnabled: this.authConfig?.fingerprint?.enabled || false,
      multiAccountEnabled: this.authConfig?.multiAccount?.enabled || false,
      loginPolicy: this.authConfig?.loginPolicy?.policy || 'single',
      rateLimitEnabled: this.authConfig?.rateLimit?.enabled || false,
    };
  }
}
