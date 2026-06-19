import { createQqProvider } from './qq.provider';

describe('createQqProvider', () => {
  const options = {
    clientId: 'qq-app-id',
    clientSecret: 'qq-app-key',
    redirectUri: 'https://app.example.com/auth/third-party/qq/callback',
  };

  it('should create QQ provider config', () => {
    const provider = createQqProvider(options);

    expect(provider.id).toBe('qq');
    expect(provider.name).toBe('QQ');
    expect(provider.authorizationEndpoint).toBe(
      'https://graph.qq.com/oauth2.0/authorize',
    );
    expect(provider.tokenEndpoint).toBe('https://graph.qq.com/oauth2.0/token');
    expect(provider.scopes).toEqual(['get_user_info']);
  });

  it('should parse URL-encoded token response', async () => {
    const provider = createQqProvider(options);

    jest.spyOn(global, 'fetch').mockResolvedValueOnce({
      ok: true,
      text: () =>
        Promise.resolve(
          'access_token=qq-access-token&expires_in=7776000&refresh_token=qq-refresh-token',
        ),
    } as Response);

    const tokenResponse = await provider.exchangeCode!(provider, 'auth-code');
    expect(tokenResponse.access_token).toBe('qq-access-token');
    expect(tokenResponse.expires_in).toBe('7776000');
  });

  it('should fetch user info through openid', async () => {
    const provider = createQqProvider(options);

    jest
      .spyOn(global, 'fetch')
      .mockResolvedValueOnce({
        ok: true,
        text: () =>
          Promise.resolve(
            'callback({"client_id":"qq-app-id","openid":"qq-openid-123"});',
          ),
      } as Response)
      .mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            ret: 0,
            msg: '',
            nickname: 'QQ用户',
            figureurl_qq_1: 'http://example.com/avatar-1.png',
            figureurl_qq_2: 'http://example.com/avatar-2.png',
          }),
      } as Response);

    const userInfo = await provider.fetchUserInfo!(provider, 'qq-access-token');
    expect(userInfo.openid).toBe('qq-openid-123');
    expect(userInfo.nickname).toBe('QQ用户');
    expect(userInfo.figureurl_qq_2).toBe('http://example.com/avatar-2.png');
  });

  it('should extract normalized user info', () => {
    const provider = createQqProvider(options);
    const user = provider.userInfoExtractor!({
      openid: 'qq-openid-123',
      nickname: 'QQ用户',
      figureurl_qq_2: 'http://example.com/avatar-2.png',
    });

    expect(user.provider).toBe('qq');
    expect(user.providerUserId).toBe('qq-openid-123');
    expect(user.username).toBe('QQ用户');
    expect(user.avatar).toBe('http://example.com/avatar-2.png');
  });
});
