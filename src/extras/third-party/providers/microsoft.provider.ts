import type { OAuth2ProviderConfig } from '../interfaces';

export interface MicrosoftProviderOptions {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  tenant?: string;
  scopes?: string[];
}

/**
 * Microsoft / Entra ID (Azure AD) OIDC Provider 配置
 */
export function createMicrosoftProvider(
  options: MicrosoftProviderOptions,
): OAuth2ProviderConfig {
  const tenant = options.tenant ?? 'common';
  return {
    id: 'microsoft',
    name: 'Microsoft',
    authorizationEndpoint: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`,
    tokenEndpoint: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    redirectUri: options.redirectUri,
    scopes: options.scopes ?? ['openid', 'email', 'profile'],
    idTokenExtractor: (payload) => ({
      provider: 'microsoft',
      providerUserId: String(payload.oid || payload.sub),
      email: payload.email as string,
      username: payload.name as string,
      raw: payload,
    }),
  };
}
