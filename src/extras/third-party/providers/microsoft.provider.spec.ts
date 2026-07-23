import { createMicrosoftProvider } from './microsoft.provider';

describe('createMicrosoftProvider', () => {
  const options = {
    clientId: 'microsoft-client-id',
    clientSecret: 'microsoft-client-secret',
    redirectUri: 'https://app.example.com/auth/third-party/microsoft/callback',
  };

  it('should create Microsoft provider config with default tenant and scopes', () => {
    const provider = createMicrosoftProvider(options);

    expect(provider.id).toBe('microsoft');
    expect(provider.name).toBe('Microsoft');
    expect(provider.authorizationEndpoint).toBe(
      'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    );
    expect(provider.tokenEndpoint).toBe(
      'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    );
    expect(provider.scopes).toEqual(['openid', 'email', 'profile']);
  });

  it('should use custom tenant when provided', () => {
    const provider = createMicrosoftProvider({
      ...options,
      tenant: 'contoso.onmicrosoft.com',
    });

    expect(provider.authorizationEndpoint).toBe(
      'https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/authorize',
    );
    expect(provider.tokenEndpoint).toBe(
      'https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token',
    );
  });

  it('should use custom scopes when provided', () => {
    const provider = createMicrosoftProvider({
      ...options,
      scopes: ['openid', 'User.Read'],
    });

    expect(provider.scopes).toEqual(['openid', 'User.Read']);
  });

  it('should extract user info from id_token payload using oid', () => {
    const provider = createMicrosoftProvider(options);
    const user = provider.idTokenExtractor!({
      oid: 'ms-oid-123',
      sub: 'ms-sub-123',
      email: 'user@contoso.com',
      name: 'Microsoft User',
    });

    expect(user.provider).toBe('microsoft');
    expect(user.providerUserId).toBe('ms-oid-123');
    expect(user.email).toBe('user@contoso.com');
    expect(user.username).toBe('Microsoft User');
  });

  it('should fallback to sub when oid is missing', () => {
    const provider = createMicrosoftProvider(options);
    const user = provider.idTokenExtractor!({
      sub: 'ms-sub-456',
      email: 'other@contoso.com',
      name: 'Other User',
    });

    expect(user.providerUserId).toBe('ms-sub-456');
  });
});
