import { Controller, Get } from '@nestjs/common';
import { OidcService } from './oidc.service';
import type { OidcDiscoveryMetadata } from './oidc.service';

/**
 * OIDC 发现端点控制器
 * 提供 /.well-known/openid-configuration
 */
@Controller('.well-known')
export class OidcController {
  constructor(private readonly oidcService: OidcService) {}

  /**
   * OpenID Connect Discovery 端点
   * GET /.well-known/openid-configuration
   */
  @Get('openid-configuration')
  discovery(): OidcDiscoveryMetadata {
    return this.oidcService.getDiscoveryMetadata();
  }
}
