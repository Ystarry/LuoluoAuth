// 协议层
export { ThirdPartyAuthModule } from './third-party-auth.module';
export { OAuth2ClientService } from './oauth2-client.service';
export { ThirdPartyAuthController } from './third-party-auth.controller';

// Passport 桥接
export { PassportBridgeModule } from './passport-bridge.module';
export { PassportBridgeController } from './passport-bridge.controller';

// SAML
export { SamlAuthModule, SamlService, SamlController } from './saml';

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

export type {
  SamlAuthModuleOptions,
  SamlServiceProviderConfig,
  SamlIdentityProviderConfig,
  SamlLoginRequest,
} from './saml/interfaces';

// 内置 Provider 配置
export {
  createGoogleProvider,
  createGitHubProvider,
  createWeChatProvider,
  createMicrosoftProvider,
  createAppleProvider,
} from './providers';

export type {
  GoogleProviderOptions,
  GitHubProviderOptions,
  WeChatProviderOptions,
  MicrosoftProviderOptions,
  AppleProviderOptions,
} from './providers';
