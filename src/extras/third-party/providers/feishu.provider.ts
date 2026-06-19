import type { OAuth2ProviderConfig } from '../interfaces';

export interface FeishuProviderOptions {
  /** 飞书应用的 App ID */
  clientId: string;
  /** 飞书应用的 App Secret */
  clientSecret: string;
  /** 回调地址 */
  redirectUri: string;
  /** 应用类型：enterprise 企业自建（默认），marketplace 应用商店应用 */
  appType?: 'enterprise' | 'marketplace';
}

/**
 * 飞书 Provider 配置
 * 适用于飞书企业自建应用 / 应用商店应用登录
 */
export function createFeishuProvider(
  options: FeishuProviderOptions,
): OAuth2ProviderConfig {
  const appType = options.appType ?? 'enterprise';
  const tokenEndpoint =
    appType === 'marketplace'
      ? 'https://open.feishu.cn/open-apis/authen/v1/oidc/access_token'
      : 'https://open.feishu.cn/open-apis/authen/v1/access_token';

  return {
    id: 'feishu',
    name: 'Feishu',
    authorizationEndpoint: 'https://open.feishu.cn/open-apis/authen/v1/index',
    tokenEndpoint,
    userInfoEndpoint: 'https://open.feishu.cn/open-apis/authen/v1/user_info',
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    redirectUri: options.redirectUri,
    scopes: [''],
    extraAuthorizationParams: {
      app_id: options.clientId,
    },
    tokenExtractor: (response) => {
      const data = response.data as Record<string, unknown> | undefined;
      return String(data?.access_token ?? response.access_token);
    },
    exchangeCode: async (provider, code) => {
      const credentials = Buffer.from(
        `${provider.clientId}:${provider.clientSecret}`,
      ).toString('base64');

      const response = await fetch(provider.tokenEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Basic ${credentials}`,
        },
        body: JSON.stringify({
          grant_type: 'authorization_code',
          code,
        }),
      });

      if (!response.ok) {
        const text = await response.text();
        throw new Error(
          `Feishu token exchange failed: ${response.status} ${text}`,
        );
      }
      return (await response.json()) as Record<string, unknown>;
    },
    fetchUserInfo: async (provider, accessToken) => {
      const response = await fetch(provider.userInfoEndpoint!, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });

      if (!response.ok) {
        const text = await response.text();
        throw new Error(
          `Feishu user info fetch failed: ${response.status} ${text}`,
        );
      }
      return (await response.json()) as Record<string, unknown>;
    },
    userInfoExtractor: (response) => {
      const data =
        (response.data as Record<string, unknown> | undefined) ?? response;
      return {
        provider: 'feishu',
        providerUserId: String(data.union_id ?? data.open_id ?? data.user_id),
        email: data.email as string,
        username: data.name as string,
        phone: data.mobile as string,
        avatar: data.avatar_url as string,
        raw: response,
      };
    },
  };
}
