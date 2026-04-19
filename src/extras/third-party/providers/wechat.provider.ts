import type { OAuth2ProviderConfig } from '../interfaces';

export interface WeChatProviderOptions {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scopes?: string[];
}

/**
 * 微信开放平台（网站应用）OAuth2 Provider 配置
 * 如需微信内网页授权，请使用 snsapi_userinfo / snsapi_base 并调整 endpoint
 */
export function createWeChatProvider(
  options: WeChatProviderOptions,
): OAuth2ProviderConfig {
  return {
    id: 'wechat',
    name: 'WeChat',
    authorizationEndpoint: 'https://open.weixin.qq.com/connect/qrconnect',
    tokenEndpoint: 'https://api.weixin.qq.com/sns/oauth2/access_token',
    userInfoEndpoint: 'https://api.weixin.qq.com/sns/userinfo',
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    redirectUri: options.redirectUri,
    scopes: options.scopes ?? ['snsapi_login'],
    extraAuthorizationParams: { response_type: 'code', appid: options.clientId },
    tokenExtractor: (response) => String(response.access_token),
    userInfoExtractor: (response) => ({
      provider: 'wechat',
      providerUserId: String(response.unionid || response.openid),
      username: response.nickname as string,
      avatar: response.headimgurl as string,
      raw: response,
    }),
  };
}