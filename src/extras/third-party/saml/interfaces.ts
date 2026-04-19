import type { ThirdPartyLoginHandler } from '../interfaces';

/**
 * SAML 服务提供方（SP）配置
 */
export interface SamlServiceProviderConfig {
  /** SP 实体 ID */
  entityId: string;
  /** ACS 回调地址，对应控制器 /auth/saml/:idp/acs */
  assertEndpoint: string;
  /** 用于签发 AuthnRequest 的私钥（PEM） */
  privateKey?: string;
  /** SP 证书（PEM），可选 */
  certificate?: string;
}

/**
 * SAML 身份提供方（IdP）配置
 */
export interface SamlIdentityProviderConfig {
  /** IdP 标识 */
  id: string;
  /** 显示名称 */
  name: string;
  /**
   * IdP metadata XML 内容或 URL
   * 若提供，ssoLoginUrl / certificate 将被忽略
   */
  metadata?: string;
  /** 登录端点 */
  ssoLoginUrl?: string;
  /** IdP 签名证书（PEM） */
  certificate?: string;
  /** 绑定方式，默认 redirect */
  binding?: 'redirect' | 'post';
}

/**
 * SAML 模块配置
 */
export interface SamlAuthModuleOptions {
  serviceProvider: SamlServiceProviderConfig;
  identityProviders: SamlIdentityProviderConfig[];
  /** 登录成功后的业务处理函数 */
  loginHandler: ThirdPartyLoginHandler;
}

/**
 * SAML 登录请求结果
 */
export interface SamlLoginRequest {
  /** redirect 模式下的跳转 URL */
  redirectUrl?: string;
  /** post 模式下的表单 action 与隐藏字段 */
  postForm?: {
    action: string;
    samlRequest: string;
    relayState?: string;
  };
}
