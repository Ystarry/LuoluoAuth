import { createGitHubProvider } from './github.provider';

describe('createGitHubProvider', () => {
  const options = {
    clientId: 'github-client-id',
    clientSecret: 'github-client-secret',
    redirectUri: 'https://app.example.com/auth/third-party/github/callback',
  };

  it('should create GitHub provider config with default scopes', () => {
    const provider = createGitHubProvider(options);

    expect(provider.id).toBe('github');
    expect(provider.name).toBe('GitHub');
    expect(provider.authorizationEndpoint).toBe(
      'https://github.com/login/oauth/authorize',
    );
    expect(provider.tokenEndpoint).toBe(
      'https://github.com/login/oauth/access_token',
    );
    expect(provider.userInfoEndpoint).toBe('https://api.github.com/user');
    expect(provider.scopes).toEqual(['read:user', 'user:email']);
  });

  it('should use custom scopes when provided', () => {
    const provider = createGitHubProvider({
      ...options,
      scopes: ['user'],
    });

    expect(provider.scopes).toEqual(['user']);
  });

  it('should extract access token', () => {
    const provider = createGitHubProvider(options);
    const token = provider.tokenExtractor!({ access_token: 'gh-token' });
    expect(token).toBe('gh-token');
  });

  it('should extract normalized user info', () => {
    const provider = createGitHubProvider(options);
    const user = provider.userInfoExtractor!({
      id: 123,
      login: 'octocat',
      email: 'octocat@example.com',
      avatar_url: 'https://avatars.githubusercontent.com/u/123',
    });

    expect(user.provider).toBe('github');
    expect(user.providerUserId).toBe('123');
    expect(user.username).toBe('octocat');
    expect(user.email).toBe('octocat@example.com');
    expect(user.avatar).toBe('https://avatars.githubusercontent.com/u/123');
  });
});
