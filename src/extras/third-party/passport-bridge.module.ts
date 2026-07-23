import { DynamicModule, Module } from '@nestjs/common';
import { AuthModule } from '../../auth/auth.module';
import { PassportBridgeController } from './passport-bridge.controller';
import type { PassportBridgeOptions } from './interfaces';

/**
 * Passport Bridge 可选模块
 * 允许业务方传入 passport 实例与 strategy，复用 Passport 生态完成第三方登录，
 * 验证成功后自动接入 luoluo-auth 的会话与权限体系。
 */
@Module({})
export class PassportBridgeModule {
  /**
   * 同步注册 Passport Bridge 模块
   * @param options 模块配置
   */
  static register(options: PassportBridgeOptions): DynamicModule {
    // 将策略注册到 passport 实例
    for (const [name, strategy] of Object.entries(options.strategies)) {
      options.passport.use(name, strategy);
    }

    return {
      module: PassportBridgeModule,
      imports: [AuthModule],
      controllers: [PassportBridgeController],
      providers: [
        {
          provide: 'PASSPORT_INSTANCE',
          useValue: options.passport,
        },
        {
          provide: 'PASSPORT_STRATEGIES',
          useValue: options.strategies,
        },
        {
          provide: 'PASSPORT_LOGIN_HANDLER',
          useValue: options.loginHandler,
        },
      ],
    };
  }
}
