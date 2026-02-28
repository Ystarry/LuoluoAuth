import { Injectable, Inject } from '@nestjs/common';
import { randomBytes } from 'crypto';
import type {
  OAuth2ProviderConfig,
  ThirdPartyUserInfo,
  StateStore,
} from './interfaces';

/**
 * OAuth2 / OIDC 通用客户端服务
 * 负责生成授权链接、换取 Token、拉取用户信息
 */
@Injectable()
export class OAuth2ClientService {
  constructor(
    @Inject('THIRD_PARTY_PROVIDERS')
    private readonly providers: Map<string, OAuth2ProviderConfig>,
    @Inject('THIRD_PARTY_STATE_STORE')
    private readonly stateStore: StateStore,
  ) {}

  /**
   * 生成第三方登录授权 URL
   * @param providerId 提供商标识
   * @returns 授权 URL 与 state key
   */
  async buildAuthorizationUrl(
    providerId: string,
  ): Promise<{ url: string; stateKey: string }> {
    const provider = this.getProvider(providerId);
    const state = this.generateState();
    const stateKey = await this.stateStore.save(state, 600);

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: provider.clientId,
      redirect_uri: provider.redirectUri,
      scope: provider.scopes.join(' '),
      state,
      ...(provider.extraAuthorizationParams || {}),
    });

    const url = `${provider.authorizationEndpoint}?${params.toString()}`;
    return { url, stateKey };
  }

  /**
   * 使用授权码换取 access_token，并拉取用户信息
   * @param providerId 提供商标识
   * @param code 授权码
   * @param state 回调带回的 state
   * @param stateKey 登录时返回的 state key
   */
  async handleCallback(
    providerId: string,
    code: string,
    state: string,
    stateKey: string,
  ): Promise<ThirdPartyUserInfo> {
    const provider = this.getProvider(providerId);

    if (provider.useState !== false) {
      const valid = await this.stateStore.verify(stateKey, state);
      if (!valid) {
        throw new Error('Invalid or expired OAuth2 state');
      }
    }

    const tokenResponse = await this.exchangeCode(provider, code);
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
      throw new Error(
        `Provider ${providerId} missing userInfoExtractor`,
      );
    }

    const userInfoResponse = await this.fetchUserInfo(
      provider.userInfoEndpoint,
      accessToken,
    );
    const user = provider.userInfoExtractor(userInfoResponse);
    user.provider = provider.id;
    return user;
  }

  private getProvider(providerId: string): OAuth2ProviderConfig {
    const provider = this.providers.get(providerId);
    if (!provider) {
      throw new Error(`Unknown third-party provider: ${providerId}`);
    }
    return provider;
  }

  private generateState(): string {
    return randomBytes(16).toString('hex');
  }

  private async exchangeCode(
    provider: OAuth2ProviderConfig,
    code: string,
  ): Promise<Record<string, unknown>> {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: provider.redirectUri,
      client_id: provider.clientId,
      client_secret: provider.clientSecret,
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

  private parseJwt(token: string): Record<string, unknown> {
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT token');
    }
    const payload = Buffer.from(parts[1], 'base64url').toString('utf8');
    return JSON.parse(payload) as Record<string, unknown>;
  }
}
