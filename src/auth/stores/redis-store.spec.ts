import { RedisStore } from './redis-store';
import type { SessionData } from '../interfaces/session-store.interface';

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

  get(key: string): Promise<string | null> {
    return Promise.resolve(this.store.get(key) ?? null);
  }

  smembers(key: string): Promise<string[]> {
    const set = this.sets.get(key);
    return Promise.resolve(set ? Array.from(set) : []);
  }

  expire(key: string): Promise<void> {
    // no-op in mock (no real TTL)
    void key;
    return Promise.resolve();
  }

  del(key: string): Promise<number> {
    const count = this.store.has(key) || this.sets.has(key) ? 1 : 0;
    this.store.delete(key);
    this.sets.delete(key);
    return Promise.resolve(count);
  }

  /** 内部方法：模拟设置值 */
  setValue(key: string, value: string): void {
    this.store.set(key, value);
  }

  /** 内部方法：模拟删除值（如 TTL 过期） */
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

describe('RedisStore', () => {
  let store: RedisStore;
  let mockRedis: MockRedis;

  beforeEach(() => {
    mockRedis = new MockRedis();
    store = new RedisStore(mockRedis as unknown as import('ioredis').default);
  });

  describe('set / get', () => {
    it('should store and retrieve session data', async () => {
      const sessionId = 'session-1';
      const data: SessionData = {
        userId: 'user-1',
        createTime: Date.now(),
      };

      await store.set(sessionId, data, 60000);
      const result = await store.get(sessionId);

      expect(result).toEqual(data);
    });

    it('should return null for non-existent session', async () => {
      const result = await store.get('non-existent');
      expect(result).toBeNull();
    });

    it('should maintain user index after set', async () => {
      const sessionId = 'session-2';
      const data: SessionData = { userId: 'user-2', createTime: Date.now() };

      await store.set(sessionId, data, 60000);
      const members = await mockRedis.smembers('auth:user-sessions:user-2');
      expect(members).toContain(sessionId);
    });

    it('should set session without TTL', async () => {
      const sessionId = 'session-no-ttl';
      const data: SessionData = {
        userId: 'user-no-ttl',
        createTime: Date.now(),
      };

      await store.set(sessionId, data);
      const result = await store.get(sessionId);
      expect(result).toEqual(data);
    });

    it('should maintain device index when device is set', async () => {
      const sessionId = 'session-device';
      const data: SessionData = {
        userId: 'user-device',
        device: 'web',
        createTime: Date.now(),
      };

      await store.set(sessionId, data, 60000);
      const members = await mockRedis.smembers('auth:device-sessions:web');
      expect(members).toContain(sessionId);
    });
  });

  describe('delete', () => {
    it('should delete specific session and clean up index', async () => {
      const sessionId = 'session-3';
      const data: SessionData = { userId: 'user-3', createTime: Date.now() };

      await store.set(sessionId, data, 60000);
      await store.delete(sessionId);

      expect(await store.get(sessionId)).toBeNull();
      const members = await mockRedis.smembers('auth:user-sessions:user-3');
      expect(members).not.toContain(sessionId);
    });

    it('should clean up device index on delete', async () => {
      const sessionId = 'session-device-del';
      const data: SessionData = {
        userId: 'user-device-del',
        device: 'mobile',
        createTime: Date.now(),
      };

      await store.set(sessionId, data, 60000);
      await store.delete(sessionId);

      const members = await mockRedis.smembers('auth:device-sessions:mobile');
      expect(members).not.toContain(sessionId);
    });

    it('should handle delete of already expired session', async () => {
      const sessionId = 'session-expired';
      const data: SessionData = {
        userId: 'user-expired',
        createTime: Date.now(),
      };

      await store.set(sessionId, data, 60000);
      // Simulate Redis TTL expiration
      mockRedis.deleteValue('auth:sessions:' + sessionId);

      // Should not throw
      await expect(store.delete(sessionId)).resolves.toBeUndefined();
    });
  });

  describe('deleteByUserId', () => {
    it('should delete all sessions for a user', async () => {
      const userId = 'user-4';

      await store.set('s1', { userId, createTime: Date.now() }, 60000);
      await store.set('s2', { userId, createTime: Date.now() }, 60000);
      await store.set('s3', { userId: 'other', createTime: Date.now() }, 60000);

      await store.deleteByUserId(userId);

      expect(await store.get('s1')).toBeNull();
      expect(await store.get('s2')).toBeNull();
      expect(await store.get('s3')).not.toBeNull();
    });

    it('should handle empty user index', async () => {
      await expect(
        store.deleteByUserId('non-existent-user'),
      ).resolves.toBeUndefined();
    });

    it('should clean up device index on deleteByUserId', async () => {
      const userId = 'user-device-bulk';

      await store.set(
        's1',
        { userId, device: 'web', createTime: Date.now() },
        60000,
      );

      // Verify device index has the session
      const before = await mockRedis.smembers('auth:device-sessions:web');
      expect(before).toContain('s1');

      await store.deleteByUserId(userId);

      // Device index should be cleaned up
      const after = await mockRedis.smembers('auth:device-sessions:web');
      expect(after).not.toContain('s1');
    });
  });

  describe('deleteByUserIdAndDevice', () => {
    it('should delete sessions matching device', async () => {
      const userId = 'user-5';

      await store.set(
        's1',
        { userId, device: 'web', createTime: Date.now() },
        60000,
      );
      await store.set(
        's2',
        { userId, device: 'mobile', createTime: Date.now() },
        60000,
      );

      await store.deleteByUserIdAndDevice(userId, 'web');

      expect(await store.get('s1')).toBeNull();
      expect(await store.get('s2')).not.toBeNull();
    });

    it('should clean up zombie session ids from index when session already expired', async () => {
      const userId = 'user-6';
      const sessionId = 'expired-session';

      // 先写入 session 和索引
      await store.set(
        sessionId,
        { userId, device: 'web', createTime: Date.now() },
        60000,
      );

      // 模拟 Redis TTL 自动清理了 session 数据，但索引中仍残留
      mockRedis.deleteValue('auth:sessions:' + sessionId);
      // 确认索引中仍然有该 sessionId
      expect(
        await mockRedis.smembers('auth:user-sessions:' + userId),
      ).toContain(sessionId);

      // 调用 deleteByUserIdAndDevice，应清理僵尸索引
      await store.deleteByUserIdAndDevice(userId, 'web');

      // 僵尸索引被清理
      const members = await mockRedis.smembers('auth:user-sessions:' + userId);
      expect(members).not.toContain(sessionId);
      // 其他正常 session 不受影响（此例中没有其他 session）
    });

    it('should handle empty user index', async () => {
      await expect(
        store.deleteByUserIdAndDevice('non-existent', 'web'),
      ).resolves.toBeUndefined();
    });
  });

  describe('listByUserId', () => {
    it('should return all sessions for a user', async () => {
      const userId = 'user-all';

      await store.set('s1', { userId, device: 'web', createTime: 1 }, 60000);
      await store.set('s2', { userId, device: 'mobile', createTime: 2 }, 60000);
      await store.set('s3', { userId: 'user-other', createTime: 3 }, 60000);

      const result = await store.listByUserId(userId);

      expect(result).toHaveLength(2);
      expect(result.map((s) => s.createTime).sort()).toEqual([1, 2]);
    });

    it('should return empty array when user has no sessions', async () => {
      const result = await store.listByUserId('user-none');
      expect(result).toEqual([]);
    });
  });

  describe('listByUserIdAndDevice', () => {
    it('should return session ids sorted by create time', async () => {
      const userId = 'user-list';
      const device = 'web';

      await store.set('s1', { userId, device, createTime: 200 }, 60000);
      await store.set('s2', { userId, device, createTime: 100 }, 60000);
      await store.set(
        's3',
        { userId, device: 'mobile', createTime: 50 },
        60000,
      );

      const result = await store.listByUserIdAndDevice(userId, device);

      expect(result).toEqual(['s2', 's1']);
    });

    it('should return empty array when no sessions match', async () => {
      const result = await store.listByUserIdAndDevice('user-none', 'web');
      expect(result).toEqual([]);
    });
  });

  describe('listByDevice', () => {
    it('should return session ids for a device', async () => {
      await store.set(
        's1',
        { userId: 'user-1', device: 'web', createTime: 1 },
        60000,
      );
      await store.set(
        's2',
        { userId: 'user-2', device: 'web', createTime: 2 },
        60000,
      );
      await store.set(
        's3',
        { userId: 'user-1', device: 'mobile', createTime: 3 },
        60000,
      );

      const result = await store.listByDevice('web');

      expect(result.sort()).toEqual(['s1', 's2']);
    });

    it('should return empty array when device has no sessions', async () => {
      const result = await store.listByDevice('unknown');
      expect(result).toEqual([]);
    });
  });

  describe('renew', () => {
    it('should renew session ttl', async () => {
      const sessionId = 'session-4';
      const data: SessionData = { userId: 'user-7', createTime: Date.now() };

      await store.set(sessionId, data, 60000);
      await store.renew(sessionId, 120000);

      // mock 中 expire 是 no-op，只需确认不抛异常即可
      expect(await store.get(sessionId)).toEqual(data);
    });

    it('should be no-op when renew without ttl', async () => {
      const sessionId = 'session-renew-no-ttl';
      const data: SessionData = { userId: 'user-8', createTime: Date.now() };

      await store.set(sessionId, data, 60000);
      await store.renew(sessionId);

      expect(await store.get(sessionId)).toEqual(data);
    });
  });

  describe('blacklist', () => {
    it('should ban and check user', async () => {
      await store.ban('user-8', 60);
      expect(await store.isBanned('user-8')).toBe(true);
      expect(await store.isBanned('user-9')).toBe(false);
    });

    it('should unban user', async () => {
      await store.ban('user-8', 60);
      expect(await store.isBanned('user-8')).toBe(true);

      await store.unban('user-8');
      expect(await store.isBanned('user-8')).toBe(false);
    });
  });
});
