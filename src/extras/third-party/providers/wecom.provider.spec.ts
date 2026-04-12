import type { OAuth2ProviderConfig } from '../interfaces';

export interface WeComProviderOptions {
  /** 企业微信 CorpID */
  clientId: string;
  /** 企业微信应用的 CorpSecret */
  clientSecret: string;
  /** 应用 AgentID */
  agentId: string;
  /** 回调地址 */
  redirectUri: string;
  /** 请求 scope，企业微信扫码登录固定 snsapi_base */
  scopes?: string[];
}

/**
 * 企业微信 Provider 配置
 * 适用于企业自建应用 / 内部应用扫码登录
 */
export function createWeComProvider(
  options: WeComProviderOptions,
): OAuth2ProviderConfig {
  return {
    id: 'wecom',
    name: 'WeCom',
    authorizationEndpoint:
      'https://open.work.weixin.qq.com/wwopen/sso/qrConnect',
    tokenEndpoint: 'https://qyapi.weixin.qq.com/cgi-bin/gettoken',
    userInfoEndpoint: 'https://qyapi.weixin.qq.com/cgi-bin/user/get',
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    redirectUri: options.redirectUri,
    scopes: options.scopes ?? ['snsapi_base'],
    extraAuthorizationParams: {
      agentid: options.agentId,
      response_type: 'code',
    },
    tokenExtractor: (response) => String(response.access_token),
    exchangeCode: async (provider) => {
      // 企业微信的 access_token 是企业级，与当前登录用户无关
      const url = new URL(provider.tokenEndpoint);
      url.searchParams.set('corpid', provider.clientId);
      url.searchParams.set('corpsecret', provider.clientSecret);

      const response = await fetch(url.toString());
      if (!response.ok) {
        const text = await response.text();
        throw new Error(
          `WeCom token exchange failed: ${response.status} ${text}`,
        );
      }
      return (await response.json()) as Record<string, unknown>;
    },
    fetchUserInfo: async (provider, accessToken, code) => {
      // 1. 用 code 换取 userid
      const userIdUrl = new URL(
        'https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo',
      );
      userIdUrl.searchParams.set('access_token', accessToken);
      userIdUrl.searchParams.set('code', code ?? '');

      const userIdResponse = await fetch(userIdUrl.toString());
      if (!userIdResponse.ok) {
        const text = await userIdResponse.text();
        throw new Error(
          `WeCom getuserinfo failed: ${userIdResponse.status} ${text}`,
        );
      }
      const userIdData = (await userIdResponse.json()) as Record<
        string,
        unknown
      >;
      const userId = userIdData.UserId ?? userIdData.userid;
      if (typeof userId !== 'string' || !userId) {
        throw new Error('WeCom failed to obtain user id');
      }

      // 2. 用 userid 换取用户详情
      const detailUrl = new URL(provider.userInfoEndpoint!);
      detailUrl.searchParams.set('access_token', accessToken);
      detailUrl.searchParams.set('userid', userId);

      const detailResponse = await fetch(detailUrl.toString());
      if (!detailResponse.ok) {
        const text = await detailResponse.text();
        throw new Error(
          `WeCom user detail failed: ${detailResponse.status} ${text}`,
        );
      }
      return (await detailResponse.json()) as Record<string, unknown>;
    },
    userInfoExtractor: (response) => ({
      provider: 'wecom',
      providerUserId: String(response.userid),
      email: response.email as string,
      username: response.name as string,
      phone: response.mobile as string,
      avatar: response.avatar as string,
      raw: response,
    }),
  };
}
