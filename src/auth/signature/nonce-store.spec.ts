import { MemoryNonceStore, RedisNonceStore } from './nonce-store';

describe('MemoryNonceStore', () => {
  let store: MemoryNonceStore;

  beforeEach(() => {
    store = new MemoryNonceStore(3);
  });

  it('should return false for unknown nonce', async () => {
    expect(await store.has('nonce-1')).toBe(false);
  });

  it('should return true after nonce is set', async () => {
    await store.set('nonce-1', 1000);
    expect(await store.has('nonce-1')).toBe(true);
  });

  it('should expire nonce after ttl', async () => {
    await store.set('nonce-1', 50);
    expect(await store.has('nonce-1')).toBe(true);
    await new Promise((resolve) => setTimeout(resolve, 80));
    expect(await store.has('nonce-1')).toBe(false);
  });

  it('should evict least recently used item when capacity is full', async () => {
    await store.set('nonce-1', 1000);
    await store.set('nonce-2', 1000);
    await store.set('nonce-3', 1000);

    // access nonce-1 to make it recently used
    await store.has('nonce-1');

    // add nonce-4, should evict nonce-2 (least recently used)
    await store.set('nonce-4', 1000);

    expect(await store.has('nonce-1')).toBe(true);
    expect(await store.has('nonce-2')).toBe(false);
    expect(await store.has('nonce-3')).toBe(true);
    expect(await store.has('nonce-4')).toBe(true);
  });

  it('should update position when setting existing nonce', async () => {
    await store.set('nonce-1', 1000);
    await store.set('nonce-2', 1000);
    await store.set('nonce-3', 1000);

    // re-set nonce-1 to update its position
    await store.set('nonce-1', 1000);

    await store.set('nonce-4', 1000);
    expect(await store.has('nonce-1')).toBe(true);
    expect(await store.has('nonce-2')).toBe(false);
  });
});

describe('RedisNonceStore', () => {
  let store: RedisNonceStore;
  const mockRedis = {
    get: jest.fn(),
    set: jest.fn(),
  };

  beforeEach(() => {
    store = new RedisNonceStore(
      mockRedis as unknown as import('ioredis').default,
    );
    jest.clearAllMocks();
  });

  it('should return true when nonce exists in redis', async () => {
    mockRedis.get.mockResolvedValue('1');
    expect(await store.has('nonce-1')).toBe(true);
    expect(mockRedis.get).toHaveBeenCalledWith('auth:nonce:nonce-1');
  });

  it('should return false when nonce does not exist', async () => {
    mockRedis.get.mockResolvedValue(null);
    expect(await store.has('nonce-1')).toBe(false);
  });

  it('should set nonce with px ttl', async () => {
    await store.set('nonce-1', 5000);
    expect(mockRedis.set).toHaveBeenCalledWith(
      'auth:nonce:nonce-1',
      '1',
      'PX',
      5000,
    );
  });
});
