import {
  Controller,
  Get,
  Param,
  Req,
  Res,
  Next,
  Inject,
  BadRequestException,
} from '@nestjs/common';
import type { Request, Response, NextFunction } from 'express';
import { AuthService } from '../../auth/auth.service';
import type {
  PassportInstance,
  PassportStrategyLike,
  ThirdPartyLoginHandler,
  ThirdPartyUserInfo,
} from './interfaces';

/**
 * Passport Bridge 控制器
 * 复用 Passport 策略完成第三方登录，成功后接入 luoluo-auth 会话体系
 */
@Controller('auth/passport')
export class PassportBridgeController {
  constructor(
    private readonly authService: AuthService,
    @Inject('PASSPORT_INSTANCE')
    private readonly passport: PassportInstance,
    @Inject('PASSPORT_STRATEGIES')
    private readonly strategies: Record<string, PassportStrategyLike>,
    @Inject('PASSPORT_LOGIN_HANDLER')
    private readonly loginHandler: ThirdPartyLoginHandler,
  ) {}

  /**
   * 跳转至 Passport 策略授权页
   */
  @Get(':strategy/login')
  login(
    @Param('strategy') strategy: string,
    @Req() req: Request,
    @Res() res: Response,
    @Next() next: NextFunction,
  ): void {
    this.ensureStrategy(strategy);
    this.passport.authenticate(strategy)(req, res, next);
  }

  /**
   * Passport 策略回调
   * 验证成功后归一化 profile，调用 loginHandler 获取本地用户，再执行 luoluo-auth 登录
   */
  @Get(':strategy/callback')
  callback(
    @Param('strategy') strategy: string,
    @Req() req: Request,
    @Res() res: Response,
    @Next() next: NextFunction,
  ): void {
    this.ensureStrategy(strategy);
    this.passport.authenticate(
      strategy,
      { session: false },
      async (err: Error | null, profile?: unknown) => {
        if (err || !profile) {
          return res.status(400).json({
            error: err?.message || 'Passport authentication failed',
          });
        }

        try {
          const userInfo = this.normalizeProfile(
            profile as Record<string, unknown>,
            strategy,
          );
          const localUser = await this.loginHandler(userInfo, req, res);
          const token = await this.authService.login(
            localUser.userId,
            strategy,
            localUser.roles,
            localUser.permissions,
            req.ip,
            req.headers['user-agent'],
            res,
          );
          res.json({ token, provider: strategy, userInfo });
        } catch (error: unknown) {
          const message =
            error instanceof Error ? error.message : 'Login handler failed';
          res.status(400).json({ error: message });
        }
      },
    )(req, res, next);
  }

  private ensureStrategy(strategy: string): void {
    if (!this.strategies[strategy]) {
      throw new BadRequestException(`Unknown Passport strategy: ${strategy}`);
    }
  }

  private normalizeProfile(
    profile: Record<string, unknown>,
    provider: string,
  ): ThirdPartyUserInfo {
    const emails = (profile.emails as { value?: string }[]) || [];
    const photos = (profile.photos as { value?: string }[]) || [];
    const nameObj = profile.name as Record<string, string> | undefined;

    return {
      provider,
      providerUserId: String(
        profile.id || profile.sub || profile.oid || profile.openid,
      ),
      email:
        (profile.email as string) ||
        emails[0]?.value ||
        (profile.upn as string),
      username:
        (profile.displayName as string) ||
        (profile.username as string) ||
        nameObj?.displayName ||
        nameObj?.formatted,
      avatar:
        (profile.picture as string) ||
        photos[0]?.value ||
        (profile.avatar_url as string),
      raw: profile,
    };
  }
}
