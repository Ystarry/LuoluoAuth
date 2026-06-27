import { DynamicModule, Module, Provider, Type } from '@nestjs/common';
import { AuthModule } from '../../auth/auth.module';
import {
  OAUTH2_CLIENT_STORE,
  OAuth2AuthorizeConfig,
  OAuth2Controller,
} from './oauth2.controller';
import {
  InMemoryOAuth2ClientStore,
  OAuth2Client,
  OAuth2ClientStore,
  UserValidator,
} from './client-store';
import { RedisOAuth2ClientStore } from './redis-client-store';
import { OidcConfig, OidcService } from './oidc.service';
import { OidcController } from './oidc.controller';

/**
 * OAuth2 模块配置选项
 */
export interface OAuth2ModuleOptions {
  /** 初始注册的 OAuth2 客户端列表 */
  clients?: OAuth2Client[];
  /** 自定义 ClientStore（默认内存实现） */
  store?: OAuth2ClientStore;
  /** 用户名密码校验器（password 模式必需） */
  userValidator?: UserValidator;
  /** OpenID Connect 配置（启用后才会签发 id_token） */
  oidc?: OidcConfig;
  /** authorize 端点登录态检查配置 */
  authorize?: OAuth2AuthorizeConfig;
}

/**
 * OAuth2 扩展模块
 * 封装 OAuth2 控制器和客户端存储，提供统一注册入口
 */
@Module({})
export class OAuth2Module {
  /**
   * 同步注册 OAuth2 模块
   * @param options - OAuth2 模块配置选项
   * @returns 动态模块定义
   */
  static register(options: OAuth2ModuleOptions = {}): DynamicModule {
    const providers: Provider[] = [
      {
        provide: OAUTH2_CLIENT_STORE,
        useFactory: () => {
          const store = options.store ?? new InMemoryOAuth2ClientStore();
          for (const client of options.clients || []) {
            void store.registerClient(client);
          }
          return store;
        },
      },
      {
        provide: 'OAUTH2_USER_VALIDATOR',
        useValue: options.userValidator,
      },
      {
        provide: 'OAUTH2_AUTHORIZE_CONFIG',
        useValue: options.authorize,
      },
    ];
    const controllers: Type<unknown>[] = [OAuth2Controller];

    if (options.oidc) {
      providers.push({
        provide: OidcService,
        useValue: new OidcService(options.oidc),
      });
      controllers.push(OidcController);
    }

    return {
      module: OAuth2Module,
      imports: [AuthModule],
      controllers,
      providers,
      exports: [OAUTH2_CLIENT_STORE],
    };
  }
}

// 显式引用 Redis 实现，避免 isolatedModules 下被 tree-shake
void RedisOAuth2ClientStore;
