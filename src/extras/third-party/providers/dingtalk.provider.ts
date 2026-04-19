import type { OAuth2ProviderConfig } from '../interfaces';

export interface DingTalkProviderOptions {
  /** 钉钉应用的 Client ID（原 AppKey） */
  clientId: string;
  /** 钉钉应用的 Client Secret（原 AppSecret） */
  clientSecret: string;
  /** 回调地址 */
  redirectUri: string;
  /** 请求 scope，默认 openid */
  scopes?: string[];
}

/**
 * 钉钉 Provider 配置
 * 适用于钉钉扫码登录 / 企业内部应用登录
 */
export function createDingTalkProvider(
  options: DingTalkProviderOptions,
): OAuth2ProviderConfig {
  return {
    id: 'dingtalk',
    name: 'DingTalk',
    authorizationEndpoint: 'https://login.dingtalk.com/oauth2/auth',
    tokenEndpoint: 'https://api.dingtalk.com/v1.0/oauth2/userAccessToken',
    userInfoEndpoint: 'https://api.dingtalk.com/v1.0/contact/users/me',
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    redirectUri: options.redirectUri,
    scopes: options.scopes ?? ['openid'],
    extraAuthorizationParams: {
      response_type: 'code',
    },
    tokenExtractor: (response) => {
      const data = response.data as Record<string, unknown> | undefined;
      return String(data?.accessToken ?? response.access_token);
    },
    exchangeCode: async (provider, code) => {
      const response = await fetch(provider.tokenEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          clientId: provider.clientId,
          clientSecret: provider.clientSecret,
          code,
          grantType: 'authorization_code',
        }),
      });

      if (!response.ok) {
        const text = await response.text();
        throw new Error(
          `DingTalk token exchange failed: ${response.status} ${text}`,
        );
      }
      return (await response.json()) as Record<string, unknown>;
    },
    fetchUserInfo: async (provider, accessToken) => {
      const response = await fetch(provider.userInfoEndpoint!, {
        headers: {
          'x-acs-dingtalk-access-token': accessToken,
        },
      });

      if (!response.ok) {
        const text = await response.text();
        throw new Error(
          `DingTalk user info fetch failed: ${response.status} ${text}`,
        );
      }
      return (await response.json()) as Record<string, unknown>;
    },
    userInfoExtractor: (response) => {
      const data =
        (response.data as Record<string, unknown> | undefined) ?? response;
      return {
        provider: 'dingtalk',
        providerUserId: String(data.unionId ?? data.openId ?? data.userid),
        email: data.email as string,
        username: data.nick as string,
        phone: data.mobile as string,
        avatar: data.avatarUrl as string,
        raw: response,
      };
    },
  };
}
