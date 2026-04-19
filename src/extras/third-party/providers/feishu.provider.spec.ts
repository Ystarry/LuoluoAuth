import { createFeishuProvider } from './feishu.provider';

describe('createFeishuProvider', () => {
  const options = {
    clientId: 'feishu-app-id',
    clientSecret: 'feishu-app-secret',
    redirectUri: 'https://app.example.com/auth/third-party/feishu/callback',
  };

  it('should create Feishu provider config', () => {
    const provider = createFeishuProvider(options);

    expect(provider.id).toBe('feishu');
    expect(provider.name).toBe('Feishu');
    expect(provider.authorizationEndpoint).toBe(
      'https://open.feishu.cn/open-apis/authen/v1/index',
    );
    expect(provider.tokenEndpoint).toBe(
      'https://open.feishu.cn/open-apis/authen/v1/access_token',
    );
    expect(provider.extraAuthorizationParams?.app_id).toBe('feishu-app-id');
  });

  it('should use marketplace token endpoint when appType is marketplace', () => {
    const provider = createFeishuProvider({
      ...options,
      appType: 'marketplace',
    });

    expect(provider.tokenEndpoint).toBe(
      'https://open.feishu.cn/open-apis/authen/v1/oidc/access_token',
    );
  });

  it('should exchange code with Basic auth', async () => {
    const provider = createFeishuProvider(options);

    jest.spyOn(global, 'fetch').mockResolvedValueOnce({
      ok: true,
      json: () =>
        Promise.resolve({
          code: 0,
          msg: 'ok',
          data: {
            access_token: 'feishu-access-token',
            token_type: 'Bearer',
            expire_in: 7200,
          },
        }),
    } as Response);

    const tokenResponse = await provider.exchangeCode!(provider, 'auth-code');
    expect(tokenResponse.data).toEqual({
      access_token: 'feishu-access-token',
      token_type: 'Bearer',
      expire_in: 7200,
    });
  });

  it('should fetch user info with Bearer token', async () => {
    const provider = createFeishuProvider(options);

    jest.spyOn(global, 'fetch').mockResolvedValueOnce({
      ok: true,
      json: () =>
        Promise.resolve({
          code: 0,
          msg: 'ok',
          data: {
            union_id: 'union-123',
            open_id: 'open-123',
            user_id: 'user-123',
            name: '飞书用户',
            email: 'user@example.com',
            mobile: '13800138000',
            avatar_url: 'https://example.com/avatar.png',
          },
        }),
    } as Response);

    const userInfo = await provider.fetchUserInfo!(
      provider,
      'feishu-access-token',
    );
    expect(userInfo.data).toEqual({
      union_id: 'union-123',
      open_id: 'open-123',
      user_id: 'user-123',
      name: '飞书用户',
      email: 'user@example.com',
      mobile: '13800138000',
      avatar_url: 'https://example.com/avatar.png',
    });
  });

  it('should extract normalized user info', () => {
    const provider = createFeishuProvider(options);
    const user = provider.userInfoExtractor!({
      code: 0,
      data: {
        union_id: 'union-123',
        open_id: 'open-123',
        user_id: 'user-123',
        name: '飞书用户',
        email: 'user@example.com',
        mobile: '13800138000',
        avatar_url: 'https://example.com/avatar.png',
      },
    });

    expect(user.provider).toBe('feishu');
    expect(user.providerUserId).toBe('union-123');
    expect(user.username).toBe('飞书用户');
    expect(user.email).toBe('user@example.com');
  });
});
