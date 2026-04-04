import {
  Controller,
  Get,
  Post,
  Param,
  Query,
  Body,
  Req,
  Res,
  Inject,
  BadRequestException,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { AuthService } from '../../auth/auth.service';
import { OAuth2ClientService } from './oauth2-client.service';
import type { ThirdPartyLoginHandler } from './interfaces';

/**
 * 第三方登录控制器
 * 提供 /auth/third-party/:provider/login 重定向
 * 与 /auth/third-party/:provider/callback 回调处理
 * 支持 GET (query) 与 POST (form_post，如 Apple) 两种回调方式
 */
@Controller('auth/third-party')
export class ThirdPartyAuthController {
  constructor(
    private readonly oauth2Client: OAuth2ClientService,
    private readonly authService: AuthService,
    @Inject('THIRD_PARTY_LOGIN_HANDLER')
    private readonly loginHandler: ThirdPartyLoginHandler,
  ) {}

  /**
   * 跳转至第三方授权页
   */
  @Get(':provider/login')
  login(@Param('provider') provider: string, @Res() res: Response): void {
    const url = this.oauth2Client.buildAuthorizationUrl(provider);
    res.redirect(url);
  }

  /**
   * 第三方授权回调（GET / query 模式）
   */
  @Get(':provider/callback')
  async callbackGet(
    @Param('provider') provider: string,
    @Query('code') code: string,
    @Query('state') state: string,
    @Query('error') error: string,
    @Query('error_description') errorDescription: string,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    await this.handleCallback(
      provider,
      code,
      state,
      error,
      errorDescription,
      req,
      res,
      undefined,
    );
  }

  /**
   * 第三方授权回调（POST / form_post 模式，如 Apple）
   */
  @Post(':provider/callback')
  async callbackPost(
    @Param('provider') provider: string,
    @Body('code') code: string,
    @Body('state') state: string,
    @Body('error') error: string,
    @Body('error_description') errorDescription: string,
    @Body() body: Record<string, unknown>,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    await this.handleCallback(
      provider,
      code,
      state,
      error,
      errorDescription,
      req,
      res,
      body,
    );
  }

  private async handleCallback(
    provider: string,
    code: string,
    state: string,
    error: string,
    errorDescription: string,
    req: Request,
    res: Response,
    body?: Record<string, unknown>,
  ): Promise<void> {
    if (error) {
      throw new BadRequestException(
        `OAuth2 provider error: ${error} - ${errorDescription || 'no details'}`,
      );
    }

    if (!code || !state) {
      throw new BadRequestException('Missing code or state');
    }

    const userInfo = await this.oauth2Client.handleCallback(
      provider,
      code,
      state,
      body,
    );
    const localUser = await this.loginHandler(userInfo, req, res);

    const token = await this.authService.login(
      localUser.userId,
      provider,
      localUser.roles,
      localUser.permissions,
      req.ip,
      req.headers['user-agent'],
      res,
    );

    // 默认把 token 以 JSON 形式返回，业务方可通过自定义 loginHandler 改写响应
    res.json({ token, provider, userInfo });
  }
}
