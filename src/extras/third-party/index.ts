// 协议层
export { ThirdPartyAuthModule } from './third-party-auth.module';
export { OAuth2ClientService } from './oauth2-client.service';
export { ThirdPartyAuthController } from './third-party-auth.controller';

// Passport 桥接
export { PassportBridgeModule } from './passport-bridge.module';
export { PassportBridgeController } from './passport-bridge.controller';

// 类型
export type {
  OAuth2ProviderConfig,
  ThirdPartyUserInfo,
  ThirdPartyLoginHandler,
  ThirdPartyAuthModuleOptions,
  PassportBridgeOptions,
  PassportInstance,
  PassportStrategyLike,
} from './interfaces';

// 内置 Provider 配置
export {
  createGoogleProvider,
  createGitHubProvider,
  createWeChatProvider,
  createMicrosoftProvider,
} from './providers';

export type {
  GoogleProviderOptions,
  GitHubProviderOptions,
  WeChatProviderOptions,
  MicrosoftProviderOptions,
} from './providers';
