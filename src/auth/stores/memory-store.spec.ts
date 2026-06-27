import { MemoryStore } from './memory-store';

describe('MemoryStore', () => {
  let store: MemoryStore;

  beforeEach(() => {
    store = new MemoryStore();
  });

  afterEach(async () => {
    await store.clear();
  });

  describe('set / get', () => {
    it('should store and retrieve session data', async () => {
      const sessionId = 'session-1';
      const data = {
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

    it('should expire session after TTL', async () => {
      const sessionId = 'session-2';
      const data = { userId: 'user-1', createTime: Date.now() };

      await store.set(sessionId, data, 50);
      expect(await store.get(sessionId)).toEqual(data);

      await new Promise((resolve) => setTimeout(resolve, 100));
      expect(await store.get(sessionId)).toBeNull();
    });
  });

  describe('delete', () => {
    it('should delete specific session', async () => {
      const sessionId = 'session-3';
      const data = { userId: 'user-1', createTime: Date.now() };

      await store.set(sessionId, data, 60000);
      await store.delete(sessionId);

      expect(await store.get(sessionId)).toBeNull();
    });
  });

  describe('deleteByUserId', () => {
    it('should delete all sessions for a user', async () => {
      const userId = 'user-1';

      await store.set('s1', { userId, createTime: Date.now() }, 60000);
      await store.set('s2', { userId, createTime: Date.now() }, 60000);
      await store.set(
        's3',
        { userId: 'user-2', createTime: Date.now() },
        60000,
      );

      await store.deleteByUserId(userId);

      expect(await store.get('s1')).toBeNull();
      expect(await store.get('s2')).toBeNull();
      expect(await store.get('s3')).not.toBeNull();
    });
  });

  describe('listByUserId', () => {
    it('should return all sessions for a user', async () => {
      const userId = 'user-1';

      await store.set('s1', { userId, createTime: 1 }, 60000);
      await store.set('s2', { userId, createTime: 2 }, 60000);
      await store.set('s3', { userId: 'user-2', createTime: 3 }, 60000);

      const result = await store.listByUserId(userId);

      expect(result).toHaveLength(2);
      expect(result.map((s) => s.createTime).sort()).toEqual([1, 2]);
    });

    it('should return empty array when user has no sessions', async () => {
      const result = await store.listByUserId('unknown');
      expect(result).toEqual([]);
    });
  });

  describe('listByUserIdAndDevice', () => {
    it('should return session ids sorted by create time', async () => {
      const userId = 'user-1';
      const device = 'web';

      await store.set('s1', { userId, device, createTime: 100 }, 60000);
      await store.set('s2', { userId, device, createTime: 50 }, 60000);
      await store.set(
        's3',
        { userId, device: 'mobile', createTime: 30 },
        60000,
      );
      await store.set(
        's4',
        { userId: 'user-2', device, createTime: 10 },
        60000,
      );

      const result = await store.listByUserIdAndDevice(userId, device);

      expect(result).toEqual(['s2', 's1']);
    });

    it('should return empty array when no sessions match', async () => {
      const result = await store.listByUserIdAndDevice('user-1', 'web');
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

  describe('LRU eviction', () => {
    it('should evict oldest session when maxSize exceeded', async () => {
      const limitedStore = new MemoryStore({ maxSize: 2 });

      await limitedStore.set('s1', { userId: 'u1', createTime: 1 }, 60000);
      await limitedStore.set('s2', { userId: 'u2', createTime: 2 }, 60000);
      await limitedStore.set('s3', { userId: 'u3', createTime: 3 }, 60000);

      // s1 should be evicted (LRU)
      expect(await limitedStore.get('s1')).toBeNull();
      expect(await limitedStore.get('s2')).not.toBeNull();
      expect(await limitedStore.get('s3')).not.toBeNull();

      await limitedStore.clear();
    });

    it('should update LRU order on get', async () => {
      const limitedStore = new MemoryStore({ maxSize: 2 });

      await limitedStore.set('s1', { userId: 'u1', createTime: 1 }, 60000);
      await limitedStore.set('s2', { userId: 'u2', createTime: 2 }, 60000);

      // Access s1 to make it recently used
      await limitedStore.get('s1');

      await limitedStore.set('s3', { userId: 'u3', createTime: 3 }, 60000);

      // s2 should be evicted (s1 was accessed more recently)
      expect(await limitedStore.get('s1')).not.toBeNull();
      expect(await limitedStore.get('s2')).toBeNull();
      expect(await limitedStore.get('s3')).not.toBeNull();

      await limitedStore.clear();
    });
  });

  describe('blacklist', () => {
    it('should ban and check user', async () => {
      await store.ban('user-1', 60);
      expect(await store.isBanned('user-1')).toBe(true);
      expect(await store.isBanned('user-2')).toBe(false);
    });

    it('should auto expire ban after duration', async () => {
      await store.ban('user-1', 0);
      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(await store.isBanned('user-1')).toBe(false);
    });

    it('should support unban explicitly', async () => {
      await store.ban('user-1', 60);
      expect(await store.isBanned('user-1')).toBe(true);

      await store.unban('user-1');
      expect(await store.isBanned('user-1')).toBe(false);
    });

    it('should return false for never banned user', async () => {
      expect(await store.isBanned('unknown')).toBe(false);
    });

    it('should extend ban by resetting timer', async () => {
      await store.ban('user-1', 0);
      await store.ban('user-1', 60);
      expect(await store.isBanned('user-1')).toBe(true);
    });
  });

  describe('renew', () => {
    it('should renew session ttl', async () => {
      const sessionId = 'renew-session';
      const data = { userId: 'user-1', createTime: Date.now() };

      await store.set(sessionId, data, 100);
      await store.renew(sessionId, 200);

      // Should still be accessible after original TTL
      await new Promise((resolve) => setTimeout(resolve, 120));
      expect(await store.get(sessionId)).toEqual(data);
    });

    it('should be no-op for non-existent session', async () => {
      await expect(store.renew('non-existent', 60000)).resolves.toBeUndefined();
    });
  });

  describe('size', () => {
    it('should return current session count', async () => {
      expect(store.size).toBe(0);

      await store.set('s1', { userId: 'u1', createTime: Date.now() }, 60000);
      expect(store.size).toBe(1);

      await store.set('s2', { userId: 'u2', createTime: Date.now() }, 60000);
      expect(store.size).toBe(2);

      await store.delete('s1');
      expect(store.size).toBe(1);
    });
  });

  describe('scheduleExpiry - segmented scheduling', () => {
    it('should handle expiry with very long TTL (segmented scheduling)', async () => {
      const sessionId = 'long-ttl-session';
      const data = { userId: 'user-1', createTime: Date.now() };

      // TTL longer than MAX_TIMEOUT_MS (2^31 - 1 = ~24.8 days) to trigger segmented scheduling
      // We use a very large TTL to trigger the internal scheduling logic
      const extraLongTtl = 2147483647 + 1000; // Just over MAX_TIMEOUT_MS
      await store.set(sessionId, data, extraLongTtl);

      // Session should be accessible immediately
      const result = await store.get(sessionId);
      expect(result).toEqual(data);
    });
  });
});
