import type { OAuth2ProviderConfig } from '../interfaces';

export interface QqProviderOptions {
  /** QQ 互联分配的 App ID */
  clientId: string;
  /** QQ 互联分配的 App Key */
  clientSecret: string;
  /** 回调地址 */
  redirectUri: string;
  /** 请求 scope，默认 get_user_info */
  scopes?: string[];
}

/**
 * QQ 互联 OAuth2 Provider 配置
 * QQ token 端点返回 URL-encoded 字符串，并需要额外请求 openid
 */
export function createQqProvider(
  options: QqProviderOptions,
): OAuth2ProviderConfig {
  return {
    id: 'qq',
    name: 'QQ',
    authorizationEndpoint: 'https://graph.qq.com/oauth2.0/authorize',
    tokenEndpoint: 'https://graph.qq.com/oauth2.0/token',
    userInfoEndpoint: 'https://graph.qq.com/user/get_user_info',
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    redirectUri: options.redirectUri,
    scopes: options.scopes ?? ['get_user_info'],
    extraAuthorizationParams: {
      response_type: 'code',
    },
    tokenExtractor: (response) => String(response.access_token),
    exchangeCode: async (provider, code) => {
      const url = new URL(provider.tokenEndpoint);
      url.searchParams.set('grant_type', 'authorization_code');
      url.searchParams.set('client_id', provider.clientId);
      url.searchParams.set('client_secret', provider.clientSecret);
      url.searchParams.set('code', code);
      url.searchParams.set('redirect_uri', provider.redirectUri);

      const response = await fetch(url.toString());
      if (!response.ok) {
        const text = await response.text();
        throw new Error(`QQ token exchange failed: ${response.status} ${text}`);
      }

      const text = await response.text();
      const params = new URLSearchParams(text);
      const result: Record<string, unknown> = {};
      params.forEach((value, key) => {
        result[key] = value;
      });
      return result;
    },
    fetchUserInfo: async (provider, accessToken) => {
      // 1. 获取 openid（JSONP 格式）
      const openidUrl = new URL('https://graph.qq.com/oauth2.0/me');
      openidUrl.searchParams.set('access_token', accessToken);

      const openidResponse = await fetch(openidUrl.toString());
      if (!openidResponse.ok) {
        const text = await openidResponse.text();
        throw new Error(
          `QQ openid fetch failed: ${openidResponse.status} ${text}`,
        );
      }
      const openidText = await openidResponse.text();
      const openidData = parseJsonp(openidText);
      const openid = openidData.openid;
      if (typeof openid !== 'string' || !openid) {
        throw new Error('QQ failed to obtain openid');
      }

      // 2. 获取用户信息
      const userInfoUrl = new URL(provider.userInfoEndpoint!);
      userInfoUrl.searchParams.set('access_token', accessToken);
      userInfoUrl.searchParams.set('oauth_consumer_key', provider.clientId);
      userInfoUrl.searchParams.set('openid', openid);

      const userInfoResponse = await fetch(userInfoUrl.toString());
      if (!userInfoResponse.ok) {
        const text = await userInfoResponse.text();
        throw new Error(
          `QQ user info fetch failed: ${userInfoResponse.status} ${text}`,
        );
      }
      const userInfo = (await userInfoResponse.json()) as Record<
        string,
        unknown
      >;
      return {
        ...userInfo,
        openid,
      };
    },
    userInfoExtractor: (response) => ({
      provider: 'qq',
      providerUserId: String(response.openid),
      username: response.nickname as string,
      avatar: (response.figureurl_qq_2 ?? response.figureurl_qq_1) as string,
      raw: response,
    }),
  };
}

function parseJsonp(text: string): Record<string, unknown> {
  const match = text.match(/\((.*)\)/s);
  if (!match || !match[1]) {
    throw new Error('Invalid QQ JSONP response');
  }
  return JSON.parse(match[1]) as Record<string, unknown>;
}
