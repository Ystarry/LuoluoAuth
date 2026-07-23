import type { OAuth2ProviderConfig } from '../interfaces';

export interface GitHubProviderOptions {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scopes?: string[];
}

/**
 * GitHub OAuth2 Provider 配置
 */
export function createGitHubProvider(
  options: GitHubProviderOptions,
): OAuth2ProviderConfig {
  return {
    id: 'github',
    name: 'GitHub',
    authorizationEndpoint: 'https://github.com/login/oauth/authorize',
    tokenEndpoint: 'https://github.com/login/oauth/access_token',
    userInfoEndpoint: 'https://api.github.com/user',
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    redirectUri: options.redirectUri,
    scopes: options.scopes ?? ['read:user', 'user:email'],
    tokenExtractor: (response) => String(response.access_token),
    userInfoExtractor: (response) => ({
      provider: 'github',
      providerUserId: String(response.id),
      email: response.email as string,
      username: response.login as string,
      avatar: response.avatar_url as string,
      raw: response,
    }),
  };
}
