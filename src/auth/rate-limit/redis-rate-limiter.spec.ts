import { RedisRateLimiter } from './redis-rate-limiter';

describe('RedisRateLimiter', () => {
  let limiter: RedisRateLimiter;
  let mockRedis: {
    eval: jest.Mock;
    scan: jest.Mock;
    del: jest.Mock;
  };

  beforeEach(() => {
    mockRedis = {
      eval: jest.fn(),
      scan: jest.fn(),
      del: jest.fn(),
    };
    limiter = new RedisRateLimiter(
      mockRedis as unknown as import('ioredis').default,
      60,
      2,
    );
  });

  it('should allow requests within limit', async () => {
    mockRedis.eval.mockResolvedValue(1);

    const ctx = { ip: '127.0.0.1', action: 'login' };
    expect(await limiter.allow(ctx)).toBe(true);
  });

  it('should block requests exceeding limit', async () => {
    mockRedis.eval.mockResolvedValue(0);

    const ctx = { ip: '127.0.0.1', action: 'login' };
    expect(await limiter.allow(ctx)).toBe(false);
  });

  it('should clear keys by prefix', async () => {
    mockRedis.scan
      .mockResolvedValueOnce(['1', ['auth:rate-limit:login:127.0.0.1']])
      .mockResolvedValueOnce(['0', []]);
    mockRedis.del.mockResolvedValue(1);

    await limiter.clear();

    expect(mockRedis.scan).toHaveBeenCalledWith(
      '0',
      'MATCH',
      'auth:rate-limit:*',
      'COUNT',
      100,
    );
    expect(mockRedis.del).toHaveBeenCalledWith(
      'auth:rate-limit:login:127.0.0.1',
    );
  });
});
