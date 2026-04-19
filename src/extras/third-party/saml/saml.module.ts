import { DynamicModule, Module } from '@nestjs/common';
import { AuthModule } from '../../../auth/auth.module';
import { SamlService } from './saml.service';
import { SamlController } from './saml.controller';
import type { SamlAuthModuleOptions } from './interfaces';

/**
 * SAML 单点登录可选模块
 * 依赖 samlify（可选 peer dependency），未安装时模块加载不报错，运行时提示安装
 */
@Module({})
export class SamlAuthModule {
  /**
   * 同步注册 SAML 模块
   * @param options 模块配置
   */
  static register(options: SamlAuthModuleOptions): DynamicModule {
    return {
      module: SamlAuthModule,
      imports: [AuthModule],
      controllers: [SamlController],
      providers: [
        SamlService,
        {
          provide: 'SAML_MODULE_OPTIONS',
          useValue: options,
        },
        {
          provide: 'SAML_LOGIN_HANDLER',
          useValue: options.loginHandler,
        },
      ],
      exports: [SamlService],
    };
  }
}
