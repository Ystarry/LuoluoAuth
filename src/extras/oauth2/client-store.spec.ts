import {
  InMemoryOAuth2ClientStore,
  OAuth2Token,
  OAuth2Client,
} from './client-store';

describe('OAuth2ClientStore', () => {
  let store: InMemoryOAuth2ClientStore;

  beforeEach(() => {
    store = new InMemoryOAuth2ClientStore();
  });

  describe('registerClient / getClient', () => {
    it('should register and retrieve a client', () => {
      const client: OAuth2Client = {
        clientId: 'app-1',
        clientSecret: 'secret-1',
        redirectUris: ['http://localhost/callback'],
        grants: ['authorization_code'],
      };

      store.registerClient(client);
      expect(store.getClient('app-1')).toEqual(client);
    });

    it('should return undefined for unknown client', () => {
      expect(store.getClient('unknown')).toBeUndefined();
    });
  });

  describe('verifyClientSecret', () => {
    it('should verify correct secret', () => {
      store.registerClient({
        clientId: 'app-2',
        clientSecret: 'secret-2',
        redirectUris: [],
        grants: [],
      });
      expect(store.verifyClientSecret('app-2', 'secret-2')).toBe(true);
      expect(store.verifyClientSecret('app-2', 'wrong')).toBe(false);
    });

    it('should reject unknown client or empty secret', () => {
      expect(store.verifyClientSecret('unknown', 'secret')).toBe(false);
      store.registerClient({
        clientId: 'app-no-secret',
        clientSecret: '',
        redirectUris: [],
        grants: [],
      });
      expect(store.verifyClientSecret('app-no-secret', '')).toBe(false);
    });
  });

  describe('verifyRedirectUri', () => {
    it('should verify allowed redirect uri', () => {
      store.registerClient({
        clientId: 'app-3',
        clientSecret: 'secret-3',
        redirectUris: ['http://localhost/callback', 'http://example.com/cb'],
        grants: [],
      });
      expect(
        store.verifyRedirectUri('app-3', 'http://localhost/callback'),
      ).toBe(true);
      expect(store.verifyRedirectUri('app-3', 'http://evil.com')).toBe(false);
    });
  });

  describe('supportsGrant', () => {
    it('should verify supported grant types', () => {
      store.registerClient({
        clientId: 'app-4',
        clientSecret: 'secret-4',
        redirectUris: [],
        grants: ['authorization_code', 'refresh_token'],
      });
      expect(store.supportsGrant('app-4', 'authorization_code')).toBe(true);
      expect(store.supportsGrant('app-4', 'refresh_token')).toBe(true);
      expect(store.supportsGrant('app-4', 'password')).toBe(false);
    });
  });

  describe('saveToken / getToken', () => {
    it('should save and retrieve token without refresh token', () => {
      const token: OAuth2Token = {
        accessToken: 'at-1',
        tokenType: 'Bearer',
        expiresIn: 3600,
      };

      store.saveToken(token);
      expect(store.getToken('at-1')).toEqual(token);
    });

    it('should save token with refresh token and create a new family', () => {
      const token: OAuth2Token = {
        accessToken: 'at-2',
        refreshToken: 'rt-2',
        tokenType: 'Bearer',
        expiresIn: 3600,
        userId: 'user-1',
      };

      store.saveToken(token);
      const retrieved = store.getToken('at-2');
      expect(retrieved).toEqual(token);
    });

    it('should reuse family when family parameter provided', () => {
      const token: OAuth2Token = {
        accessToken: 'at-3',
        refreshToken: 'rt-3',
        tokenType: 'Bearer',
        expiresIn: 3600,
        userId: 'user-1',
      };

      const family = 'family-abc';
      store.saveToken(token, family);

      // 消费旧 refresh token 后生成新 token，复用同一 family
      const newToken: OAuth2Token = {
        accessToken: 'at-4',
        refreshToken: 'rt-4',
        tokenType: 'Bearer',
        expiresIn: 3600,
        userId: 'user-1',
      };
      store.saveToken(newToken, family);

      // family 应该包含两个 refresh token
      // 验证通过 reuse detection 测试间接验证
      expect(store.getToken('at-3')).toEqual(token);
      expect(store.getToken('at-4')).toEqual(newToken);
    });
  });

  describe('consumeRefreshToken', () => {
    it('should return undefined for unknown refresh token', () => {
      expect(store.consumeRefreshToken('unknown')).toBeUndefined();
    });

    it('should consume refresh token and mark it used', () => {
      const token: OAuth2Token = {
        accessToken: 'at-5',
        refreshToken: 'rt-5',
        tokenType: 'Bearer',
        expiresIn: 3600,
        userId: 'user-1',
      };

      store.saveToken(token);
      const result = store.consumeRefreshToken('rt-5') as {
        token: OAuth2Token;
        family: string;
        reuseDetected: false;
      };

      expect(result).toBeDefined();
      expect(result.reuseDetected).toBe(false);
      expect(result.token).toEqual(token);
      expect(result.family).toBeDefined();
    });

    it('should detect reuse on second consumption (refresh token rotation attack)', () => {
      const token: OAuth2Token = {
        accessToken: 'at-6',
        refreshToken: 'rt-6',
        tokenType: 'Bearer',
        expiresIn: 3600,
        userId: 'user-1',
      };

      store.saveToken(token);
      const first = store.consumeRefreshToken('rt-6');
      expect(first!.reuseDetected).toBe(false);

      // 攻击者窃取了旧 refresh token 并尝试再次使用
      const second = store.consumeRefreshToken('rt-6');
      expect(second).toBeDefined();
      expect(second!.reuseDetected).toBe(true);
      expect(second!.family).toEqual(first!.family);
    });
  });

  describe('revokeTokenFamily', () => {
    it('should revoke all tokens in the family', () => {
      const family = 'family-x';
      const token1: OAuth2Token = {
        accessToken: 'at-7',
        refreshToken: 'rt-7',
        tokenType: 'Bearer',
        expiresIn: 3600,
        userId: 'user-1',
      };
      const token2: OAuth2Token = {
        accessToken: 'at-8',
        refreshToken: 'rt-8',
        tokenType: 'Bearer',
        expiresIn: 3600,
        userId: 'user-1',
      };

      store.saveToken(token1, family);
      store.saveToken(token2, family);

      store.revokeTokenFamily(family);

      expect(store.getToken('at-7')).toBeUndefined();
      expect(store.getToken('at-8')).toBeUndefined();
      expect(store.consumeRefreshToken('rt-7')).toBeUndefined();
      expect(store.consumeRefreshToken('rt-8')).toBeUndefined();
    });
  });

  describe('revokeRefreshToken', () => {
    it('should revoke a single refresh token and its access token', () => {
      const token: OAuth2Token = {
        accessToken: 'at-9',
        refreshToken: 'rt-9',
        tokenType: 'Bearer',
        expiresIn: 3600,
        userId: 'user-1',
      };

      store.saveToken(token);
      store.revokeRefreshToken('rt-9');

      expect(store.getToken('at-9')).toBeUndefined();
      expect(store.consumeRefreshToken('rt-9')).toBeUndefined();
    });

    it('should not affect other tokens in the same family', () => {
      const family = 'family-y';
      const token1: OAuth2Token = {
        accessToken: 'at-10',
        refreshToken: 'rt-10',
        tokenType: 'Bearer',
        expiresIn: 3600,
        userId: 'user-1',
      };
      const token2: OAuth2Token = {
        accessToken: 'at-11',
        refreshToken: 'rt-11',
        tokenType: 'Bearer',
        expiresIn: 3600,
        userId: 'user-1',
      };

      store.saveToken(token1, family);
      store.saveToken(token2, family);

      store.revokeRefreshToken('rt-10');

      expect(store.getToken('at-10')).toBeUndefined();
      expect(store.getToken('at-11')).toEqual(token2);
    });
  });

  describe('removeToken', () => {
    it('should remove access token and associated refresh token', () => {
      const token: OAuth2Token = {
        accessToken: 'at-12',
        refreshToken: 'rt-12',
        tokenType: 'Bearer',
        expiresIn: 3600,
        userId: 'user-1',
      };

      store.saveToken(token);
      store.removeToken('at-12');

      expect(store.getToken('at-12')).toBeUndefined();
      expect(store.consumeRefreshToken('rt-12')).toBeUndefined();
    });
  });

  describe('authorization code', () => {
    it('should save and consume authorization code', () => {
      const code = {
        code: 'ac-1',
        clientId: 'app-5',
        userId: 'user-1',
        redirectUri: 'http://localhost/callback',
        expiresAt: Date.now() + 60000,
      };

      store.saveAuthorizationCode(code);
      const consumed = store.consumeAuthorizationCode('ac-1');
      expect(consumed).toEqual(code);

      // 授权码只能使用一次
      expect(store.consumeAuthorizationCode('ac-1')).toBeUndefined();
    });

    it('should return undefined for expired authorization code', () => {
      const code = {
        code: 'ac-2',
        clientId: 'app-5',
        userId: 'user-1',
        redirectUri: 'http://localhost/callback',
        expiresAt: Date.now() - 1,
      };

      store.saveAuthorizationCode(code);
      expect(store.consumeAuthorizationCode('ac-2')).toBeUndefined();
    });
  });
});
