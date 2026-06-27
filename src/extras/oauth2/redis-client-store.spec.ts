import { RedisOAuth2ClientStore } from './redis-client-store';
import type {
  ConsumeRefreshTokenSuccess,
  OAuth2Client,
  OAuth2Token,
} from './client-store';

class MockPipeline {
  private commands: Array<{ name: string; args: unknown[] }> = [];

  set(...args: unknown[]) {
    this.commands.push({ name: 'set', args });
    return this;
  }
  sadd(...args: unknown[]) {
    this.commands.push({ name: 'sadd', args });
    return this;
  }
  srem(...args: unknown[]) {
    this.commands.push({ name: 'srem', args });
    return this;
  }
  expire(...args: unknown[]) {
    this.commands.push({ name: 'expire', args });
    return this;
  }
  del(...args: unknown[]) {
    this.commands.push({ name: 'del', args });
    return this;
  }
  get(...args: unknown[]) {
    this.commands.push({ name: 'get', args });
    return this;
  }

  async exec(): Promise<[null, unknown][]> {
    const results: [null, unknown][] = [];
    for (const cmd of this.commands) {
      const result = await this.mockRedis.execute(cmd.name, cmd.args);
      results.push([null, result]);
    }
    return results;
  }

  constructor(private readonly mockRedis: MockRedis) {}
}

class MockRedis {
  private readonly store = new Map<string, string>();
  private readonly sets = new Map<string, Set<string>>();

  pipeline() {
    return new MockPipeline(this);
  }

  set(key: string, value: string, ...args: unknown[]): Promise<unknown> {
    void args;
    this.store.set(key, value);
    return Promise.resolve('OK');
  }

  del(key: string): Promise<number> {
    this.store.delete(key);
    this.sets.delete(key);
    return Promise.resolve(1);
  }

  get(key: string): Promise<string | null> {
    return Promise.resolve(this.store.get(key) ?? null);
  }

  smembers(key: string): Promise<string[]> {
    const set = this.sets.get(key);
    return Promise.resolve(set ? Array.from(set) : []);
  }

  eval(script: string, numKeys: number, ...keys: string[]): Promise<unknown> {
    void script;
    if (numKeys === 1) {
      const key = keys[0];
      const value = this.store.get(key);
      if (!value) return Promise.resolve(null);
      const entry = JSON.parse(value) as {
        accessToken: string;
        family: string;
        used: boolean;
      };
      if (entry.used) {
        return Promise.resolve(
          JSON.stringify({ reuseDetected: true, family: entry.family }),
        );
      }
      entry.used = true;
      this.store.set(key, JSON.stringify(entry));
      return Promise.resolve(
        JSON.stringify({
          accessToken: entry.accessToken,
          family: entry.family,
          reuseDetected: false,
        }),
      );
    }
    return Promise.resolve(null);
  }

  /** 内部方法：模拟设置值 */
  setValue(key: string, value: string): void {
    this.store.set(key, value);
  }

  /** 内部方法：模拟删除值 */
  deleteValue(key: string): void {
    this.store.delete(key);
  }

  /** 内部方法：直接操作集合 */
  addToSet(key: string, member: string): void {
    if (!this.sets.has(key)) {
      this.sets.set(key, new Set<string>());
    }
    this.sets.get(key)!.add(member);
  }

  /** 内部方法：执行 pipeline 命令 */
  execute(name: string, args: unknown[]): Promise<unknown> {
    switch (name) {
      case 'set': {
        const [key, value] = args as [string, string];
        this.store.set(key, value);
        return Promise.resolve('OK');
      }
      case 'sadd': {
        const [key, member] = args as [string, string];
        this.addToSet(key, member);
        return Promise.resolve(1);
      }
      case 'srem': {
        const [key, member] = args as [string, string];
        const set = this.sets.get(key);
        if (set) {
          const had = set.delete(member);
          if (set.size === 0) {
            this.sets.delete(key);
          }
          return Promise.resolve(had ? 1 : 0);
        }
        return Promise.resolve(0);
      }
      case 'expire': {
        return Promise.resolve(1);
      }
      case 'del': {
        const [key] = args as [string];
        const count = this.store.has(key) ? 1 : 0;
        this.store.delete(key);
        this.sets.delete(key);
        return Promise.resolve(count);
      }
      case 'get': {
        const [key] = args as [string];
        return Promise.resolve(this.store.get(key) ?? null);
      }
      default:
        return Promise.resolve(null);
    }
  }
}

describe('RedisOAuth2ClientStore', () => {
  let store: RedisOAuth2ClientStore;
  let mockRedis: MockRedis;

  beforeEach(() => {
    mockRedis = new MockRedis();
    store = new RedisOAuth2ClientStore(
      mockRedis as unknown as import('ioredis').default,
      3600,
      600,
    );
  });

  const createClient = (): OAuth2Client => ({
    clientId: 'app-1',
    clientSecret: 'secret-1',
    redirectUris: ['http://localhost/callback'],
    grants: ['authorization_code', 'refresh_token'],
  });

  describe('client management', () => {
    it('should register and retrieve a client', async () => {
      const client = createClient();
      await store.registerClient(client);
      const retrieved = await store.getClient('app-1');
      expect(retrieved).toEqual(client);
    });

    it('should verify client secret', async () => {
      await store.registerClient(createClient());
      expect(await store.verifyClientSecret('app-1', 'secret-1')).toBe(true);
      expect(await store.verifyClientSecret('app-1', 'wrong')).toBe(false);
    });

    it('should return false for unknown client in verifyClientSecret', async () => {
      expect(await store.verifyClientSecret('unknown', 'secret')).toBe(false);
    });

    it('should verify redirect uri', async () => {
      await store.registerClient(createClient());
      expect(
        await store.verifyRedirectUri('app-1', 'http://localhost/callback'),
      ).toBe(true);
      expect(await store.verifyRedirectUri('app-1', 'http://evil.com')).toBe(
        false,
      );
    });

    it('should return false for unknown client in verifyRedirectUri', async () => {
      expect(
        await store.verifyRedirectUri('unknown', 'http://localhost/callback'),
      ).toBe(false);
    });

    it('should verify supported grant types', async () => {
      await store.registerClient(createClient());
      expect(await store.supportsGrant('app-1', 'authorization_code')).toBe(
        true,
      );
      expect(await store.supportsGrant('app-1', 'password')).toBe(false);
    });

    it('should return false for unknown client in supportsGrant', async () => {
      expect(await store.supportsGrant('unknown', 'authorization_code')).toBe(
        false,
      );
    });
  });

  describe('authorization code', () => {
    it('should save and consume authorization code', async () => {
      const code = {
        code: 'ac-1',
        clientId: 'app-1',
        userId: 'user-1',
        redirectUri: 'http://localhost/callback',
        expiresAt: Date.now() + 60000,
      };

      await store.saveAuthorizationCode(code);
      const consumed = await store.consumeAuthorizationCode('ac-1');
      expect(consumed).toEqual(code);

      // 授权码只能使用一次
      expect(await store.consumeAuthorizationCode('ac-1')).toBeUndefined();
    });

    it('should return undefined for expired authorization code', async () => {
      const code = {
        code: 'ac-2',
        clientId: 'app-1',
        userId: 'user-1',
        redirectUri: 'http://localhost/callback',
        expiresAt: Date.now() - 1,
      };

      await store.saveAuthorizationCode(code);
      expect(await store.consumeAuthorizationCode('ac-2')).toBeUndefined();
    });

    it('should return undefined for non-existent authorization code', async () => {
      expect(
        await store.consumeAuthorizationCode('no-such-code'),
      ).toBeUndefined();
    });
  });

  describe('token management', () => {
    it('should save and retrieve token', async () => {
      const token: OAuth2Token = {
        accessToken: 'at-1',
        refreshToken: 'rt-1',
        tokenType: 'Bearer',
        expiresIn: 3600,
        userId: 'user-1',
      };

      await store.saveToken(token);
      const retrieved = await store.getToken('at-1');
      expect(retrieved).toEqual(token);
    });

    it('should reuse family when family parameter provided', async () => {
      const family = 'family-abc';
      const token1: OAuth2Token = {
        accessToken: 'at-2',
        refreshToken: 'rt-2',
        tokenType: 'Bearer',
        expiresIn: 3600,
        userId: 'user-1',
      };
      const token2: OAuth2Token = {
        accessToken: 'at-3',
        refreshToken: 'rt-3',
        tokenType: 'Bearer',
        expiresIn: 3600,
        userId: 'user-1',
      };

      await store.saveToken(token1, family);
      await store.saveToken(token2, family);

      expect(await store.getToken('at-2')).toEqual(token1);
      expect(await store.getToken('at-3')).toEqual(token2);
    });
  });

  describe('consumeRefreshToken', () => {
    it('should return undefined for unknown refresh token', async () => {
      expect(await store.consumeRefreshToken('unknown')).toBeUndefined();
    });

    it('should consume refresh token and mark it used', async () => {
      const token: OAuth2Token = {
        accessToken: 'at-4',
        refreshToken: 'rt-4',
        tokenType: 'Bearer',
        expiresIn: 3600,
        userId: 'user-1',
      };

      await store.saveToken(token);
      const result = (await store.consumeRefreshToken(
        'rt-4',
      )) as ConsumeRefreshTokenSuccess;

      expect(result).toBeDefined();
      expect(result.reuseDetected).toBe(false);
      expect(result.token).toEqual(token);
      expect(result.family).toBeDefined();
    });

    it('should detect reuse on second consumption', async () => {
      const token: OAuth2Token = {
        accessToken: 'at-5',
        refreshToken: 'rt-5',
        tokenType: 'Bearer',
        expiresIn: 3600,
        userId: 'user-1',
      };

      await store.saveToken(token);
      const first = await store.consumeRefreshToken('rt-5');
      expect(first).toBeDefined();
      expect(first!.reuseDetected).toBe(false);

      const second = await store.consumeRefreshToken('rt-5');
      expect(second).toBeDefined();
      expect(second!.reuseDetected).toBe(true);
      expect(second!.family).toEqual(first!.family);
    });

    it('should return undefined when access token is missing after refresh', async () => {
      // Save a refresh token entry pointing to a non-existent access token
      const refreshTokenKey = 'oauth2:refresh-tokens:rt-orphan';
      mockRedis.setValue(
        refreshTokenKey,
        JSON.stringify({
          accessToken: 'at-orphan',
          family: 'family-orphan',
          used: false,
        }),
      );

      const result = await store.consumeRefreshToken('rt-orphan');
      expect(result).toBeUndefined();
    });
  });

  describe('revokeTokenFamily', () => {
    it('should revoke all tokens in the family', async () => {
      const family = 'family-x';
      const token1: OAuth2Token = {
        accessToken: 'at-6',
        refreshToken: 'rt-6',
        tokenType: 'Bearer',
        expiresIn: 3600,
        userId: 'user-1',
      };
      const token2: OAuth2Token = {
        accessToken: 'at-7',
        refreshToken: 'rt-7',
        tokenType: 'Bearer',
        expiresIn: 3600,
        userId: 'user-1',
      };

      await store.saveToken(token1, family);
      await store.saveToken(token2, family);

      await store.revokeTokenFamily(family);

      expect(await store.getToken('at-6')).toBeUndefined();
      expect(await store.getToken('at-7')).toBeUndefined();
      expect(await store.consumeRefreshToken('rt-6')).toBeUndefined();
      expect(await store.consumeRefreshToken('rt-7')).toBeUndefined();
    });

    it('should handle empty family gracefully', async () => {
      await expect(
        store.revokeTokenFamily('empty-family'),
      ).resolves.toBeUndefined();
    });
  });

  describe('revokeRefreshToken', () => {
    it('should revoke a single refresh token and its access token', async () => {
      const token: OAuth2Token = {
        accessToken: 'at-8',
        refreshToken: 'rt-8',
        tokenType: 'Bearer',
        expiresIn: 3600,
        userId: 'user-1',
      };

      await store.saveToken(token);
      await store.revokeRefreshToken('rt-8');

      expect(await store.getToken('at-8')).toBeUndefined();
      expect(await store.consumeRefreshToken('rt-8')).toBeUndefined();
    });

    it('should not affect other tokens in the same family', async () => {
      const family = 'family-y';
      const token1: OAuth2Token = {
        accessToken: 'at-9',
        refreshToken: 'rt-9',
        tokenType: 'Bearer',
        expiresIn: 3600,
        userId: 'user-1',
      };
      const token2: OAuth2Token = {
        accessToken: 'at-10',
        refreshToken: 'rt-10',
        tokenType: 'Bearer',
        expiresIn: 3600,
        userId: 'user-1',
      };

      await store.saveToken(token1, family);
      await store.saveToken(token2, family);

      await store.revokeRefreshToken('rt-9');

      expect(await store.getToken('at-9')).toBeUndefined();
      expect(await store.getToken('at-10')).toEqual(token2);
    });

    it('should be no-op for non-existent refresh token', async () => {
      await expect(
        store.revokeRefreshToken('non-existent-rt'),
      ).resolves.toBeUndefined();
    });
  });

  describe('removeToken', () => {
    it('should remove access token and associated refresh token', async () => {
      const token: OAuth2Token = {
        accessToken: 'at-11',
        refreshToken: 'rt-11',
        tokenType: 'Bearer',
        expiresIn: 3600,
        userId: 'user-1',
      };

      await store.saveToken(token);
      await store.removeToken('at-11');

      expect(await store.getToken('at-11')).toBeUndefined();
      expect(await store.consumeRefreshToken('rt-11')).toBeUndefined();
    });
  });
});
