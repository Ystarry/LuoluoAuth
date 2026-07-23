import { createWeChatProvider } from './wechat.provider';

describe('createWeChatProvider', () => {
  const options = {
    clientId: 'wechat-app-id',
    clientSecret: 'wechat-app-secret',
    redirectUri: 'https://app.example.com/auth/third-party/wechat/callback',
  };

  it('should create WeChat provider config with default scope', () => {
    const provider = createWeChatProvider(options);

    expect(provider.id).toBe('wechat');
    expect(provider.name).toBe('WeChat');
    expect(provider.authorizationEndpoint).toBe(
      'https://open.weixin.qq.com/connect/qrconnect',
    );
    expect(provider.tokenEndpoint).toBe(
      'https://api.weixin.qq.com/sns/oauth2/access_token',
    );
    expect(provider.userInfoEndpoint).toBe(
      'https://api.weixin.qq.com/sns/userinfo',
    );
    expect(provider.scopes).toEqual(['snsapi_login']);
  });

  it('should use custom scopes when provided', () => {
    const provider = createWeChatProvider({
      ...options,
      scopes: ['snsapi_login', 'snsapi_userinfo'],
    });

    expect(provider.scopes).toEqual(['snsapi_login', 'snsapi_userinfo']);
  });

  it('should include appid as extra authorization param', () => {
    const provider = createWeChatProvider(options);

    expect(provider.extraAuthorizationParams).toEqual({
      response_type: 'code',
      appid: 'wechat-app-id',
    });
  });

  it('should extract access token', () => {
    const provider = createWeChatProvider(options);
    const token = provider.tokenExtractor!({ access_token: 'wx-token' });
    expect(token).toBe('wx-token');
  });

  it('should extract normalized user info from unionid', () => {
    const provider = createWeChatProvider(options);
    const user = provider.userInfoExtractor!({
      unionid: 'wx-union-123',
      openid: 'wx-open-123',
      nickname: 'WeChat User',
      headimgurl: 'https://wechat.png',
    });

    expect(user.provider).toBe('wechat');
    expect(user.providerUserId).toBe('wx-union-123');
    expect(user.username).toBe('WeChat User');
    expect(user.avatar).toBe('https://wechat.png');
  });

  it('should fallback to openid when unionid is missing', () => {
    const provider = createWeChatProvider(options);
    const user = provider.userInfoExtractor!({
      openid: 'wx-open-456',
      nickname: 'Other User',
      headimgurl: 'https://other.png',
    });

    expect(user.providerUserId).toBe('wx-open-456');
  });
});
