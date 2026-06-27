import { DynamicModule, Module } from '@nestjs/common';
import { AuthModule } from '../../auth/auth.module';
import { SsoService, SsoServiceConfig } from './sso.service';

/**
 * SSO 扩展模块
 * 封装 SSO 服务，提供统一注册入口
 */
@Module({})
export class SsoModule {
  /**
   * 同步注册 SSO 模块
   * @param config - SSO 服务配置
   * @returns 动态模块定义
   */
  static register(config: SsoServiceConfig = {}): DynamicModule {
    return {
      module: SsoModule,
      imports: [AuthModule],
      providers: [
        {
          provide: 'SSO_CONFIG',
          useValue: config,
        },
        SsoService,
      ],
      exports: [SsoService],
    };
  }
}
