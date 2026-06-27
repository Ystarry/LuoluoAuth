import { MemoryRateLimiter } from './memory-rate-limiter';

describe('MemoryRateLimiter', () => {
  let limiter: MemoryRateLimiter;

  beforeEach(() => {
    limiter = new MemoryRateLimiter(1, 2);
  });

  afterEach(async () => {
    await limiter.clear();
  });

  it('should allow requests within limit', async () => {
    const ctx = { ip: '127.0.0.1', action: 'login' };

    expect(await limiter.allow(ctx)).toBe(true);
    expect(await limiter.allow(ctx)).toBe(true);
  });

  it('should block requests exceeding limit', async () => {
    const ctx = { ip: '127.0.0.1', action: 'login' };

    await limiter.allow(ctx);
    await limiter.allow(ctx);

    expect(await limiter.allow(ctx)).toBe(false);
  });

  it('should isolate different keys', async () => {
    const ctxA = { ip: '127.0.0.1', action: 'login' };
    const ctxB = { ip: '127.0.0.2', action: 'login' };

    await limiter.allow(ctxA);
    await limiter.allow(ctxA);

    expect(await limiter.allow(ctxB)).toBe(true);
  });

  it('should reset window after expiration', async () => {
    const ctx = { ip: '127.0.0.1', action: 'login' };

    await limiter.allow(ctx);
    await limiter.allow(ctx);
    expect(await limiter.allow(ctx)).toBe(false);

    await new Promise((resolve) => setTimeout(resolve, 1100));
    expect(await limiter.allow(ctx)).toBe(true);
  });
});
