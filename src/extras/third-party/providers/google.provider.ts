import type { OAuth2ProviderConfig } from '../interfaces';

export interface GoogleProviderOptions {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scopes?: string[];
}

/**
 * Google OAuth2 / OIDC Provider 配置
 */
export function createGoogleProvider(
  options: GoogleProviderOptions,
): OAuth2ProviderConfig {
  return {
    id: 'google',
    name: 'Google',
    authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenEndpoint: 'https://oauth2.googleapis.com/token',
    userInfoEndpoint: 'https://openidconnect.googleapis.com/v1/userinfo',
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    redirectUri: options.redirectUri,
    scopes: options.scopes ?? ['openid', 'email', 'profile'],
    idTokenExtractor: (payload) => ({
      provider: 'google',
      providerUserId: String(payload.sub),
      email: payload.email as string,
      username: payload.name as string,
      avatar: payload.picture as string,
      raw: payload,
    }),
    userInfoExtractor: (response) => ({
      provider: 'google',
      providerUserId: String(response.sub),
      email: response.email as string,
      username: response.name as string,
      avatar: response.picture as string,
      raw: response,
    }),
  };
}
