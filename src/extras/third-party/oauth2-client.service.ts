import { Injectable, Inject } from '@nestjs/common';
import { createHmac, randomBytes, timingSafeEqual } from 'crypto';
import type { OAuth2ProviderConfig, ThirdPartyUserInfo } from './interfaces';

/**
 * OAuth2 / OIDC 通用客户端服务
 * 负责生成授权链接、换取 Token、拉取用户信息
 */
@Injectable()
export class OAuth2ClientService {
  constructor(
    @Inject('THIRD_PARTY_PROVIDERS')
    private readonly providers: Map<string, OAuth2ProviderConfig>,
    @Inject('THIRD_PARTY_STATE_SECRET')
    private readonly stateSecret: string,
  ) {}

  /**
   * 生成第三方登录授权 URL
   * @param providerId 提供商标识
   * @returns 授权 URL
   */
  buildAuthorizationUrl(providerId: string): string {
    const provider = this.getProvider(providerId);
    const state = this.signState(providerId);

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: provider.clientId,
      redirect_uri: provider.redirectUri,
      scope: provider.scopes.join(' '),
      state,
      ...(provider.extraAuthorizationParams || {}),
    });

    if (provider.responseMode) {
      params.set('response_mode', provider.responseMode);
    }

    return `${provider.authorizationEndpoint}?${params.toString()}`;
  }

  /**
   * 使用授权码换取 access_token，并拉取用户信息
   * @param providerId 提供商标识
   * @param code 授权码
   * @param state 回调带回的 state
   * @param callbackBody form_post 回调体（如 Apple 登录）
   */
  async handleCallback(
    providerId: string,
    code: string,
    state: string,
    callbackBody?: Record<string, unknown>,
  ): Promise<ThirdPartyUserInfo> {
    const verifiedProviderId = this.verifyState(state);
    if (!verifiedProviderId || verifiedProviderId !== providerId) {
      throw new Error('Invalid or expired OAuth2 state');
    }

    const provider = this.getProvider(providerId);
    const tokenResponse = provider.exchangeCode
      ? await provider.exchangeCode(provider, code)
      : await this.exchangeCode(provider, code);

    // OIDC 模式：优先从 id_token 解析用户信息，无需 access_token
    if (provider.idTokenExtractor && tokenResponse.id_token) {
      const payload = this.parseJwt(tokenResponse.id_token as string);
      const user = provider.idTokenExtractor(payload);
      user.provider = provider.id;
      return this.mergeCallbackBody(provider, user, callbackBody);
    }

    const accessToken = provider.tokenExtractor
      ? provider.tokenExtractor(tokenResponse)
      : (tokenResponse.access_token as string);

    if (!accessToken) {
      throw new Error('Failed to obtain access token');
    }

    if (!provider.userInfoEndpoint) {
      throw new Error(
        `Provider ${providerId} missing userInfoEndpoint and idTokenExtractor`,
      );
    }

    if (!provider.userInfoExtractor) {
      throw new Error(`Provider ${providerId} missing userInfoExtractor`);
    }

    const userInfoResponse = provider.fetchUserInfo
      ? await provider.fetchUserInfo(provider, accessToken, code)
      : await this.fetchUserInfo(provider.userInfoEndpoint, accessToken);
    const user = provider.userInfoExtractor(userInfoResponse);
    user.provider = provider.id;
    return this.mergeCallbackBody(provider, user, callbackBody);
  }

  private getProvider(providerId: string): OAuth2ProviderConfig {
    const provider = this.providers.get(providerId);
    if (!provider) {
      throw new Error(`Unknown third-party provider: ${providerId}`);
    }
    return provider;
  }

  private signState(providerId: string): string {
    const nonce = randomBytes(16).toString('hex');
    const payload = `${providerId}:${nonce}`;
    const signature = createHmac('sha256', this.stateSecret)
      .update(payload)
      .digest('base64url');
    return `${payload}:${signature}`;
  }

  private verifyState(state: string): string | null {
    const parts = state.split(':');
    if (parts.length !== 3) {
      return null;
    }
    const [providerId, nonce, signature] = parts;
    const payload = `${providerId}:${nonce}`;
    const expected = createHmac('sha256', this.stateSecret)
      .update(payload)
      .digest('base64url');
    const valid = timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expected),
    );
    return valid ? providerId : null;
  }

  private async exchangeCode(
    provider: OAuth2ProviderConfig,
    code: string,
  ): Promise<Record<string, unknown>> {
    const clientSecret = provider.clientSecretGenerator
      ? await provider.clientSecretGenerator()
      : provider.clientSecret;

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: provider.redirectUri,
      client_id: provider.clientId,
      client_secret: clientSecret,
    });

    const response = await fetch(provider.tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: body.toString(),
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Token exchange failed: ${response.status} ${text}`);
    }

    return (await response.json()) as Record<string, unknown>;
  }

  private async fetchUserInfo(
    endpoint: string,
    accessToken: string,
  ): Promise<Record<string, unknown>> {
    const response = await fetch(endpoint, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`UserInfo fetch failed: ${response.status} ${text}`);
    }

    return (await response.json()) as Record<string, unknown>;
  }

  private mergeCallbackBody(
    provider: OAuth2ProviderConfig,
    user: ThirdPartyUserInfo,
    callbackBody?: Record<string, unknown>,
  ): ThirdPartyUserInfo {
    if (!provider.callbackBodyExtractor || !callbackBody) {
      return user;
    }
    const extra = provider.callbackBodyExtractor(callbackBody);
    return {
      ...user,
      ...extra,
      raw: { ...user.raw, callbackBody: extra },
    };
  }

  private parseJwt(token: string): Record<string, unknown> {
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT token');
    }
    const payload = Buffer.from(parts[1], 'base64url').toString('utf8');
    return JSON.parse(payload) as Record<string, unknown>;
  }
}
