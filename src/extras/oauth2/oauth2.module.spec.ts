import { OAuth2Module } from './oauth2.module';
import { OAuth2Controller, OAUTH2_CLIENT_STORE } from './oauth2.controller';
import { OidcController } from './oidc.controller';
import { OidcService } from './oidc.service';
import type { OAuth2ClientStore } from './client-store';

describe('OAuth2Module', () => {
  describe('register', () => {
    it('should create a dynamic module with default options', () => {
      const module = OAuth2Module.register();

      expect(module.module).toBe(OAuth2Module);
      expect(module.imports).toBeDefined();
      expect(module.controllers).toContain(OAuth2Controller);
      expect(module.exports).toEqual([OAUTH2_CLIENT_STORE]);
    });

    it('should create a dynamic module with initial clients', () => {
      const module = OAuth2Module.register({
        clients: [
          {
            clientId: 'test-client',
            redirectUris: ['http://localhost/callback'],
            grants: ['authorization_code'],
          },
        ],
      });

      expect(module.controllers).toContain(OAuth2Controller);
      const storeProvider = module.providers?.find(
        (p) =>
          typeof p === 'object' &&
          'provide' in p &&
          (p as Record<string, unknown>).provide === OAUTH2_CLIENT_STORE,
      );
      expect(storeProvider).toBeDefined();
    });

    it('should create a dynamic module with userValidator', () => {
      const validator = jest.fn();
      const module = OAuth2Module.register({ userValidator: validator });

      const validatorProvider = module.providers?.find(
        (p) =>
          typeof p === 'object' &&
          'provide' in p &&
          (p as Record<string, unknown>).provide === 'OAUTH2_USER_VALIDATOR',
      );
      expect(validatorProvider).toBeDefined();
      expect((validatorProvider as Record<string, unknown>).useValue).toBe(
        validator,
      );
    });

    it('should create a dynamic module with authorize config', () => {
      const authorize = { authCheckMode: 'cookie' as const, cookieName: 'my' };
      const module = OAuth2Module.register({ authorize });

      const configProvider = module.providers?.find(
        (p) =>
          typeof p === 'object' &&
          'provide' in p &&
          (p as Record<string, unknown>).provide === 'OAUTH2_AUTHORIZE_CONFIG',
      );
      expect(configProvider).toBeDefined();
      expect((configProvider as Record<string, unknown>).useValue).toBe(
        authorize,
      );
    });

    it('should include OIDC controller and service when oidc config is provided', () => {
      const module = OAuth2Module.register({
        oidc: {
          issuer: 'http://localhost:3000',
          secret: 'oidc-secret-sufficient-length',
        },
      });

      expect(module.controllers).toContain(OidcController);

      const oidcProvider = module.providers?.find(
        (p) =>
          typeof p === 'object' &&
          'provide' in p &&
          (p as Record<string, unknown>).provide === OidcService,
      );
      expect(oidcProvider).toBeDefined();
    });

    it('should not include OIDC controller when oidc config is not provided', () => {
      const module = OAuth2Module.register();

      expect(module.controllers).not.toContain(OidcController);
    });
  });

  describe('useFactory', () => {
    /**
     * 直接测试 useFactory 闭包，覆盖 for 循环注册 client 和自定义 store 的分支
     */
    it('should initialize store with clients via useFactory', async () => {
      const module = OAuth2Module.register({
        clients: [
          {
            clientId: 'factory-client',
            redirectUris: ['http://localhost/callback'],
            grants: ['authorization_code'],
          },
        ],
      });

      const storeProvider = module.providers?.find(
        (p) =>
          typeof p === 'object' &&
          'provide' in p &&
          (p as Record<string, unknown>).provide === OAUTH2_CLIENT_STORE,
      ) as { useFactory: () => OAuth2ClientStore } | undefined;

      expect(storeProvider).toBeDefined();
      const store = storeProvider!.useFactory();
      const client = await store.getClient('factory-client');
      expect(client).toBeDefined();
      expect(client!.clientId).toBe('factory-client');
    });

    it('should initialize store with multiple clients', async () => {
      const module = OAuth2Module.register({
        clients: [
          {
            clientId: 'multi-1',
            redirectUris: ['http://localhost/callback'],
            grants: ['authorization_code'],
          },
          {
            clientId: 'multi-2',
            redirectUris: ['http://localhost/callback'],
            grants: ['password'],
          },
        ],
      });

      const storeProvider = module.providers?.find(
        (p) =>
          typeof p === 'object' &&
          'provide' in p &&
          (p as Record<string, unknown>).provide === OAUTH2_CLIENT_STORE,
      ) as { useFactory: () => OAuth2ClientStore } | undefined;

      const store = storeProvider!.useFactory();
      const client1 = await store.getClient('multi-1');
      const client2 = await store.getClient('multi-2');
      expect(client1).toBeDefined();
      expect(client2).toBeDefined();
    });

    it('should use custom store when provided', () => {
      const customStore = {
        getClient: jest.fn().mockResolvedValue(null),
        registerClient: jest.fn().mockResolvedValue(undefined),
        verifyRedirectUri: jest.fn().mockResolvedValue(true),
        supportsGrant: jest.fn().mockResolvedValue(true),
        verifyClientSecret: jest.fn().mockResolvedValue(true),
        saveAuthorizationCode: jest.fn(),
        consumeAuthorizationCode: jest.fn(),
        saveToken: jest.fn(),
        getToken: jest.fn().mockResolvedValue(null),
        consumeRefreshToken: jest.fn().mockResolvedValue(undefined),
        revokeTokenFamily: jest.fn(),
      };

      const module = OAuth2Module.register({
        store: customStore as unknown as OAuth2ClientStore,
        clients: [
          {
            clientId: 'custom-store-client',
            redirectUris: ['http://localhost/callback'],
            grants: ['authorization_code'],
          },
        ],
      });

      const storeProvider = module.providers?.find(
        (p) =>
          typeof p === 'object' &&
          'provide' in p &&
          (p as Record<string, unknown>).provide === OAUTH2_CLIENT_STORE,
      ) as { useFactory: () => OAuth2ClientStore } | undefined;

      const store = storeProvider!.useFactory();
      expect(store).toBe(customStore);
      expect(customStore.registerClient).toHaveBeenCalledWith(
        expect.objectContaining({ clientId: 'custom-store-client' }),
      );
    });
  });
});
