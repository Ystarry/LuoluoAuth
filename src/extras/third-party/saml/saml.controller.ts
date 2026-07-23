import {
  Controller,
  Get,
  Post,
  Param,
  Body,
  Req,
  Res,
  Inject,
  BadRequestException,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { AuthService } from '../../../auth/auth.service';
import { SamlService } from './saml.service';
import type { ThirdPartyLoginHandler } from '../interfaces';

/**
 * SAML 控制器
 * 提供 /auth/saml/:idp/login 与 /auth/saml/:idp/acs
 */
@Controller('auth/saml')
export class SamlController {
  constructor(
    private readonly samlService: SamlService,
    private readonly authService: AuthService,
    @Inject('SAML_LOGIN_HANDLER')
    private readonly loginHandler: ThirdPartyLoginHandler,
  ) {}

  /**
   * 跳转至 IdP 登录页
   * redirect 绑定直接 302 跳转；post 绑定返回 HTML 自动提交表单
   */
  @Get(':idp/login')
  login(@Param('idp') idp: string, @Res() res: Response): void {
    const request = this.samlService.createLoginRequest(idp);

    if (request.redirectUrl) {
      res.redirect(request.redirectUrl);
      return;
    }

    if (request.postForm) {
      const { action, samlRequest, relayState } = request.postForm;
      const relayStateInput = relayState
        ? `<input type="hidden" name="RelayState" value="${this.escapeHtml(relayState)}" />`
        : '';

      res.setHeader('Content-Type', 'text/html');
      res.send(
        `<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit()">
  <form method="post" action="${this.escapeHtml(action)}">
    <input type="hidden" name="SAMLRequest" value="${this.escapeHtml(samlRequest)}" />
    ${relayStateInput}
    <noscript><button type="submit">Continue</button></noscript>
  </form>
</body>
</html>`,
      );
      return;
    }

    throw new BadRequestException('Unable to create SAML login request');
  }

  /**
   * ACS 回调端点（POST）
   * 解析 SAMLResponse 后调用 loginHandler，再执行 luoluo-auth 登录
   */
  @Post(':idp/acs')
  async acs(
    @Param('idp') idp: string,
    @Body('SAMLResponse') samlResponse: string,
    @Body('RelayState') relayState: string,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    if (!samlResponse) {
      throw new BadRequestException('Missing SAMLResponse');
    }

    const userInfo = await this.samlService.parseLoginResponse(
      idp,
      samlResponse,
      relayState,
    );
    const localUser = await this.loginHandler(userInfo, req, res);

    const token = await this.authService.login(
      localUser.userId,
      `saml_${idp}`,
      localUser.roles,
      localUser.permissions,
      req.ip,
      req.headers['user-agent'],
      res,
    );

    res.json({ token, provider: `saml_${idp}`, userInfo });
  }

  /**
   * SP metadata 端点，供 IdP 配置使用
   */
  @Get('metadata')
  metadata(@Res() res: Response): void {
    const xml = this.samlService.getServiceProviderMetadata();
    res.setHeader('Content-Type', 'application/xml');
    res.send(xml);
  }

  private escapeHtml(value: string): string {
    return value
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
}
