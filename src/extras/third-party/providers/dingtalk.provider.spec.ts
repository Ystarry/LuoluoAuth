import { createDingTalkProvider } from './dingtalk.provider';

describe('createDingTalkProvider', () => {
  const options = {
    clientId: 'ding-client-id',
    clientSecret: 'ding-client-secret',
    redirectUri: 'https://app.example.com/auth/third-party/dingtalk/callback',
  };

  it('should create DingTalk provider config', () => {
    const provider = createDingTalkProvider(options);

    expect(provider.id).toBe('dingtalk');
    expect(provider.name).toBe('DingTalk');
    expect(provider.authorizationEndpoint).toBe(
      'https://login.dingtalk.com/oauth2/auth',
    );
    expect(provider.tokenEndpoint).toBe(
      'https://api.dingtalk.com/v1.0/oauth2/userAccessToken',
    );
    expect(provider.scopes).toEqual(['openid']);
  });

  it('should exchange code with JSON body', async () => {
    const provider = createDingTalkProvider(options);

    jest.spyOn(global, 'fetch').mockResolvedValueOnce({
      ok: true,
      json: () =>
        Promise.resolve({
          code: 0,
          msg: 'ok',
          data: {
            accessToken: 'ding-access-token',
            refreshToken: 'ding-refresh-token',
            expireIn: 7200,
          },
        }),
    } as Response);

    const tokenResponse = await provider.exchangeCode!(provider, 'auth-code');
    expect(tokenResponse.data).toEqual({
      accessToken: 'ding-access-token',
      refreshToken: 'ding-refresh-token',
      expireIn: 7200,
    });
  });

  it('should fetch user info with dingtalk access token header', async () => {
    const provider = createDingTalkProvider(options);

    jest.spyOn(global, 'fetch').mockResolvedValueOnce({
      ok: true,
      json: () =>
        Promise.resolve({
          code: 0,
          msg: 'ok',
          data: {
            unionId: 'union-123',
            openId: 'open-123',
            nick: '钉钉用户',
            email: 'user@example.com',
            mobile: '13800138000',
            avatarUrl: 'https://example.com/avatar.png',
          },
        }),
    } as Response);

    const userInfo = await provider.fetchUserInfo!(
      provider,
      'ding-access-token',
    );
    expect(userInfo.data).toEqual({
      unionId: 'union-123',
      openId: 'open-123',
      nick: '钉钉用户',
      email: 'user@example.com',
      mobile: '13800138000',
      avatarUrl: 'https://example.com/avatar.png',
    });
  });

  it('should extract normalized user info', () => {
    const provider = createDingTalkProvider(options);
    const user = provider.userInfoExtractor!({
      code: 0,
      data: {
        unionId: 'union-123',
        openId: 'open-123',
        nick: '钉钉用户',
        email: 'user@example.com',
        mobile: '13800138000',
        avatarUrl: 'https://example.com/avatar.png',
      },
    });

    expect(user.provider).toBe('dingtalk');
    expect(user.providerUserId).toBe('union-123');
    expect(user.username).toBe('钉钉用户');
    expect(user.email).toBe('user@example.com');
  });
});
