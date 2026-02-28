import {
  Controller,
  Get,
  Param,
  Query,
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
 */
@Controller('auth/third-party')
export class ThirdPartyAuthController {
  constructor(
    private readonly oauth2Client: OAuth2ClientService,
    private readonly authService: AuthService,
    @Inject('THIRD_PARTY_LOGIN_HANDLER')
    private readonly loginHandler: ThirdPartyLoginHandler
  ) {}

  /**
   * 跳转至第三方授权页
   */
  @Get(':provider/login')
  async login(
    @Param('provider') provider: string,
    @Res() res: Response,
  ): Promise<void> {
    const url = this.oauth2Client.buildAuthorizationUrl(provider);
    res.redirect(url);
  }

  /**
   * 第三方授权回调
   * 换取用户信息后，调用业务方 loginHandler 获取本地用户，再执行 luoluo-auth 登录
   */
  @Get(':provider/callback')
  async callback(
    @Param('provider') provider: string,
    @Query('code') code: string,
    @Query('state') state: string,
    @Query('error') error: string,
    @Query('error_description') errorDescription: string,
    @Req() req: Request,
    @Res() res: Response,
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
