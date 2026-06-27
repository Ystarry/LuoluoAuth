import { DynamicModule, Module, Provider } from '@nestjs/common';
import { AuthModule } from '../../auth/auth.module';
import {
  MicroserviceAuthInterceptor,
  MicroserviceAuthInterceptorConfig,
  RpcTokenResolver,
} from './auth.interceptor';

/**
 * 微服务认证扩展模块
 * 封装微服务认证拦截器，提供统一注册入口
 */
@Module({})
export class MicroserviceModule {
  /**
   * 同步注册微服务认证模块
   * @param options - 微服务认证模块配置
   * @returns 动态模块定义
   */
  static register(
    options: {
      /** 自定义 Token 解析函数 */
      tokenResolver?: RpcTokenResolver;
      /** 拦截器配置 */
      interceptorConfig?: MicroserviceAuthInterceptorConfig;
    } = {},
  ): DynamicModule {
    const providers: Provider[] = [
      {
        provide: 'RPC_TOKEN_RESOLVER',
        useValue: options.tokenResolver,
      },
      {
        provide: 'RPC_AUTH_INTERCEPTOR_CONFIG',
        useValue: options.interceptorConfig,
      },
      MicroserviceAuthInterceptor,
    ];

    return {
      module: MicroserviceModule,
      imports: [AuthModule],
      providers,
      exports: [MicroserviceAuthInterceptor],
    };
  }
}
