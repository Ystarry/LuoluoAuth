import { Test, TestingModule } from '@nestjs/testing';
import { OAuth2ClientService } from './oauth2-client.service';
import type { OAuth2ProviderConfig } from './interfaces';

describe('OAuth2ClientService', () => {
  let service: OAuth2ClientService;
  const stateSecret = 'test-state-secret';

  const provider: OAuth2ProviderConfig = {
    id: 'test',
    name: 'Test Provider',
    authorizationEndpoint: 'https://example.com/oauth/authorize',
    tokenEndpoint: 'https://example.com/oauth/token',
    userInfoEndpoint: 'https://example.com/oauth/userinfo',
    clientId: 'client-id',
    clientSecret: 'client-secret',
    redirectUri: 'https://app.example.com/callback',
    scopes: ['profile'],
    userInfoExtractor: (response) => ({
      provider: 'test',
      providerUserId: String(response.id),
      email: response.email as string,
      username: response.name as string,
    }),
  };

  beforeEach(async () => {
    const providersMap = new Map<string, OAuth2ProviderConfig>();
    providersMap.set(provider.id, provider);

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        OAuth2ClientService,
        { provide: 'THIRD_PARTY_PROVIDERS', useValue: providersMap },
        { provide: 'THIRD_PARTY_STATE_SECRET', useValue: stateSecret },
      ],
    }).compile();

    service = module.get<OAuth2ClientService>(OAuth2ClientService);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('should build authorization url with signed state', () => {
    const url = service.buildAuthorizationUrl('test');
    expect(url).toContain(provider.authorizationEndpoint);
    expect(url).toContain(`client_id=${provider.clientId}`);
    expect(url).toContain('state=');
  });

  it('should reject unknown provider', () => {
    expect(() => service.buildAuthorizationUrl('unknown')).toThrow(
      'Unknown third-party provider: unknown',
    );
  });

  it('should exchange code and fetch user info', async () => {
    const authorizationUrl = service.buildAuthorizationUrl('test');
    const stateMatch = authorizationUrl.match(/state=([^&]+)/);
    const state = decodeURIComponent(stateMatch![1]);

    jest.spyOn(global, 'fetch').mockImplementation(async (url) => {
      if (url === provider.tokenEndpoint) {
        return {
          ok: true,
          json: async () => ({ access_token: 'access-token' }),
        } as Response;
      }
      if (url === provider.userInfoEndpoint) {
        return {
          ok: true,
          json: async () => ({ id: '123', email: 'a@b.com', name: 'Alice' }),
        } as Response;
      }
      throw new Error('Unexpected fetch call');
    });

    const user = await service.handleCallback('test', 'code', state);
    expect(user.providerUserId).toBe('123');
    expect(user.email).toBe('a@b.com');
    expect(user.username).toBe('Alice');
    expect(user.provider).toBe('test');
  });

  it('should reject invalid state', async () => {
    await expect(
      service.handleCallback('test', 'code', 'invalid-state'),
    ).rejects.toThrow('Invalid or expired OAuth2 state');
  });

  it('should support id_token extraction for OIDC', async () => {
    const oidcProvider: OAuth2ProviderConfig = {
      ...provider,
      id: 'oidc',
      userInfoEndpoint: undefined,
      idTokenExtractor: (payload) => ({
        provider: 'oidc',
        providerUserId: String(payload.sub),
        email: payload.email as string,
        username: payload.name as string,
      }),
    };

    const providersMap = new Map<string, OAuth2ProviderConfig>();
    providersMap.set(oidcProvider.id, oidcProvider);

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        OAuth2ClientService,
        { provide: 'THIRD_PARTY_PROVIDERS', useValue: providersMap },
        { provide: 'THIRD_PARTY_STATE_SECRET', useValue: stateSecret },
      ],
    }).compile();

    const oidcService = module.get<OAuth2ClientService>(OAuth2ClientService);
    const authorizationUrl = oidcService.buildAuthorizationUrl('oidc');
    const stateMatch = authorizationUrl.match(/state=([^&]+)/);
    const state = decodeURIComponent(stateMatch![1]);

    const header = Buffer.from('{"alg":"none"}').toString('base64url');
    const payload = Buffer.from(
      JSON.stringify({ sub: 'oidc-123', email: 'oidc@example.com', name: 'Oidc' }),
    ).toString('base64url');
    const idToken = `${header}.${payload}.`;

    jest.spyOn(global, 'fetch').mockImplementation(async (url) => {
      if (url === oidcProvider.tokenEndpoint) {
        return {
          ok: true,
          json: async () => ({ id_token: idToken }),
        } as Response;
      }
      throw new Error('Unexpected fetch call');
    });

    const user = await oidcService.handleCallback('oidc', 'code', state);
    expect(user.providerUserId).toBe('oidc-123');
    expect(user.email).toBe('oidc@example.com');
  });
});
