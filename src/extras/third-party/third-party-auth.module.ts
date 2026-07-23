import { DynamicModule, Module } from '@nestjs/common';
import { AuthModule } from '../../auth/auth.module';
import { OAuth2ClientService } from './oauth2-client.service';
import { ThirdPartyAuthController } from './third-party-auth.controller';
import type { ThirdPartyAuthModuleOptions } from './interfaces';

/**
 * 第三方认证扩展模块
 * 提供 OAuth2 / OIDC 通用协议层 + 头部 Provider 配置能力
 */
@Module({})
export class ThirdPartyAuthModule {
  /**
   * 同步注册第三方认证模块
   * @param options 模块配置
   */
  static register(options: ThirdPartyAuthModuleOptions): DynamicModule {
    const providersMap = new Map();
    for (const provider of options.providers) {
      providersMap.set(provider.id, provider);
    }

    return {
      module: ThirdPartyAuthModule,
      imports: [AuthModule],
      controllers: [ThirdPartyAuthController],
      providers: [
        OAuth2ClientService,
        {
          provide: 'THIRD_PARTY_PROVIDERS',
          useValue: providersMap,
        },
        {
          provide: 'THIRD_PARTY_STATE_SECRET',
          useValue: options.stateSecret,
        },
        {
          provide: 'THIRD_PARTY_LOGIN_HANDLER',
          useValue: options.loginHandler,
        },
      ],
      exports: [OAuth2ClientService],
    };
  }
}
