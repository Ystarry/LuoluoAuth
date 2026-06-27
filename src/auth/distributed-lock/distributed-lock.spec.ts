import { MemoryDistributedLock } from './memory-distributed-lock';
import { RedisDistributedLock } from './redis-distributed-lock';

describe('MemoryDistributedLock', () => {
  let lock: MemoryDistributedLock;

  beforeEach(() => {
    lock = new MemoryDistributedLock();
  });

  it('should acquire and release lock', async () => {
    const token = await lock.acquire('user:1', 1000);

    expect(token).toBeDefined();
    expect(token?.key).toBe('user:1');
    expect(token?.token).toBeDefined();

    await lock.release(token!);

    const token2 = await lock.acquire('user:1', 1000);
    expect(token2).toBeDefined();
  });

  it('should fail to acquire when lock is held', async () => {
    const token = await lock.acquire('user:1', 1000);
    expect(token).toBeDefined();

    const token2 = await lock.acquire('user:1', 1000);
    expect(token2).toBeUndefined();

    await lock.release(token!);
  });

  it('should allow different keys to lock concurrently', async () => {
    const token1 = await lock.acquire('user:1', 1000);
    const token2 = await lock.acquire('user:2', 1000);

    expect(token1).toBeDefined();
    expect(token2).toBeDefined();

    await lock.release(token1!);
    await lock.release(token2!);
  });

  it('should auto expire lock after ttl', async () => {
    const token = await lock.acquire('user:1', 50);
    expect(token).toBeDefined();

    await new Promise((resolve) => setTimeout(resolve, 80));

    const token2 = await lock.acquire('user:1', 1000);
    expect(token2).toBeDefined();
  });

  it('should not release lock with wrong token', async () => {
    const token = await lock.acquire('user:1', 1000);
    expect(token).toBeDefined();

    await lock.release({ key: token!.key, token: 'wrong-token' });

    const token2 = await lock.acquire('user:1', 1000);
    expect(token2).toBeUndefined();

    await lock.release(token!);
  });
});

describe('RedisDistributedLock', () => {
  let lock: RedisDistributedLock;
  const mockRedis = {
    set: jest.fn(),
    eval: jest.fn(),
  };

  beforeEach(() => {
    lock = new RedisDistributedLock(
      mockRedis as unknown as import('ioredis').default,
    );
    jest.clearAllMocks();
  });

  it('should acquire lock when redis returns OK', async () => {
    mockRedis.set.mockResolvedValue('OK');

    const token = await lock.acquire('user:1', 5000);

    expect(token).toBeDefined();
    expect(token?.key).toBe('auth:lock:user:1');
    expect(token?.token).toBeDefined();
    expect(mockRedis.set).toHaveBeenCalledWith(
      'auth:lock:user:1',
      expect.any(String),
      'PX',
      5000,
      'NX',
    );
  });

  it('should return undefined when lock is held', async () => {
    mockRedis.set.mockResolvedValue(null);

    const token = await lock.acquire('user:1', 5000);

    expect(token).toBeUndefined();
  });

  it('should release lock with lua script', async () => {
    mockRedis.set.mockResolvedValue('OK');
    mockRedis.eval.mockResolvedValue(1);

    const token = await lock.acquire('user:1', 5000);
    await lock.release(token!);

    expect(mockRedis.eval).toHaveBeenCalledWith(
      expect.stringContaining("redis.call('get', KEYS[1]) == ARGV[1]"),
      1,
      token?.key,
      token?.token,
    );
  });
});
