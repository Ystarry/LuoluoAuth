import { createGoogleProvider } from './google.provider';

describe('createGoogleProvider', () => {
  const options = {
    clientId: 'google-client-id',
    clientSecret: 'google-client-secret',
    redirectUri: 'https://app.example.com/auth/third-party/google/callback',
  };

  it('should create Google provider config with default scopes', () => {
    const provider = createGoogleProvider(options);

    expect(provider.id).toBe('google');
    expect(provider.name).toBe('Google');
    expect(provider.authorizationEndpoint).toBe(
      'https://accounts.google.com/o/oauth2/v2/auth',
    );
    expect(provider.tokenEndpoint).toBe('https://oauth2.googleapis.com/token');
    expect(provider.userInfoEndpoint).toBe(
      'https://openidconnect.googleapis.com/v1/userinfo',
    );
    expect(provider.scopes).toEqual(['openid', 'email', 'profile']);
  });

  it('should use custom scopes when provided', () => {
    const provider = createGoogleProvider({
      ...options,
      scopes: ['openid'],
    });

    expect(provider.scopes).toEqual(['openid']);
  });

  it('should extract user info from id_token payload', () => {
    const provider = createGoogleProvider(options);
    const user = provider.idTokenExtractor!({
      sub: 'google-123',
      email: 'user@gmail.com',
      name: 'Google User',
      picture: 'https://google.png',
    });

    expect(user.provider).toBe('google');
    expect(user.providerUserId).toBe('google-123');
    expect(user.email).toBe('user@gmail.com');
    expect(user.username).toBe('Google User');
    expect(user.avatar).toBe('https://google.png');
  });

  it('should extract user info from userinfo response', () => {
    const provider = createGoogleProvider(options);
    const user = provider.userInfoExtractor!({
      sub: 'google-456',
      email: 'other@gmail.com',
      name: 'Other User',
      picture: 'https://other.png',
    });

    expect(user.provider).toBe('google');
    expect(user.providerUserId).toBe('google-456');
    expect(user.email).toBe('other@gmail.com');
    expect(user.username).toBe('Other User');
    expect(user.avatar).toBe('https://other.png');
  });
});
