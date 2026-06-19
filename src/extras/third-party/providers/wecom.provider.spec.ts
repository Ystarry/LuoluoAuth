import { createWeComProvider } from './wecom.provider';

describe('createWeComProvider', () => {
  const options = {
    clientId: 'corp-id',
    clientSecret: 'corp-secret',
    agentId: '1000002',
    redirectUri: 'https://app.example.com/auth/third-party/wecom/callback',
  };

  it('should create WeCom provider config', () => {
    const provider = createWeComProvider(options);

    expect(provider.id).toBe('wecom');
    expect(provider.name).toBe('WeCom');
    expect(provider.authorizationEndpoint).toBe(
      'https://open.work.weixin.qq.com/wwopen/sso/qrConnect',
    );
    expect(provider.tokenEndpoint).toBe(
      'https://qyapi.weixin.qq.com/cgi-bin/gettoken',
    );
    expect(provider.extraAuthorizationParams?.agentid).toBe('1000002');
  });

  it('should exchange code for corp access_token', async () => {
    const provider = createWeComProvider(options);

    jest.spyOn(global, 'fetch').mockResolvedValueOnce({
      ok: true,
      json: () =>
        Promise.resolve({
          access_token: 'corp-access-token',
          expires_in: 7200,
        }),
    } as Response);

    const tokenResponse = await provider.exchangeCode!(provider, 'auth-code');
    expect(tokenResponse.access_token).toBe('corp-access-token');
  });

  it('should fetch user info through userid', async () => {
    const provider = createWeComProvider(options);

    jest
      .spyOn(global, 'fetch')
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ UserId: 'ZhangSan' }),
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            userid: 'ZhangSan',
            name: '张三',
            email: 'zhangsan@example.com',
            mobile: '13800138000',
            avatar: 'https://example.com/avatar.png',
          }),
      } as Response);

    const userInfo = await provider.fetchUserInfo!(
      provider,
      'corp-access-token',
      'auth-code',
    );
    expect(userInfo.userid).toBe('ZhangSan');
    expect(userInfo.name).toBe('张三');
  });

  it('should extract normalized user info', () => {
    const provider = createWeComProvider(options);
    const user = provider.userInfoExtractor!({
      userid: 'ZhangSan',
      name: '张三',
      email: 'zhangsan@example.com',
      mobile: '13800138000',
      avatar: 'https://example.com/avatar.png',
    });

    expect(user.provider).toBe('wecom');
    expect(user.providerUserId).toBe('ZhangSan');
    expect(user.username).toBe('张三');
    expect(user.email).toBe('zhangsan@example.com');
  });
});
