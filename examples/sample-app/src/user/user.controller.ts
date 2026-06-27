import {
  Controller,
  Get,
  Post,
  Body,
  Req,
  Res,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import {
  AuthService,
  RequireLogin,
  RequireRoles,
  RequirePermissions,
} from 'luoluo-auth';

class LoginDto {
  userId!: string;
  device?: string;
  rememberMe?: boolean;
}

class SwitchDto {
  targetUserId!: string;
}

@Controller('user')
export class UserController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() dto: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const token = await this.authService.login(
      dto.userId,
      dto.device || 'web',
      dto.userId.startsWith('admin') ? ['admin'] : ['user'],
      dto.userId.startsWith('admin') ? ['*'] : ['profile:read'],
      req.ip || '127.0.0.1',
      req.headers['user-agent'] || '',
      res,
      dto.rememberMe,
    );
    return { token };
  }

  @Get('profile')
  @RequireLogin()
  profile() {
    return { message: 'profile' };
  }

  @Get('admin')
  @RequireLogin()
  @RequireRoles('admin')
  adminOnly() {
    return { message: 'admin area' };
  }

  @Get('write')
  @RequireLogin()
  @RequirePermissions('profile:write')
  writePermission() {
    return { message: 'write allowed' };
  }

  @Post('logout')
  @RequireLogin()
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const token = this.extractToken(req);
    await this.authService.logout(token, res);
    return { message: 'logged out' };
  }

  @Get('sessions')
  @RequireLogin()
  async listSessions(@Req() req: Request) {
    const token = this.extractToken(req);
    const session = await this.authService.validateToken(token);
    const online = await this.authService.getOnlineSessions(session.userId);
    return { online };
  }

  @Get('accounts')
  @RequireLogin()
  async listAccounts(@Req() req: Request) {
    const token = this.extractToken(req);
    const session = await this.authService.validateToken(token);
    const accounts = await this.authService.listAccounts(
      session.device || 'unknown',
    );
    return { accounts };
  }

  @Post('switch')
  @RequireLogin()
  async switchAccount(@Req() req: Request, @Body() dto: SwitchDto) {
    const token = this.extractToken(req);
    const newToken = await this.authService.switchAccount(
      token,
      dto.targetUserId,
    );
    return { token: newToken };
  }

  private extractToken(req: Request): string {
    const authHeader = req.headers.authorization;
    if (authHeader?.startsWith('Bearer ')) {
      return authHeader.slice(7);
    }
    const cookieHeader = req.headers.cookie;
    if (cookieHeader) {
      const match = cookieHeader.match(/sample-auth-token=([^;]+)/);
      if (match) {
        return decodeURIComponent(match[1]);
      }
    }
    return '';
  }
}
