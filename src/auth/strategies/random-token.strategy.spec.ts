import { MemoryStore } from '../stores/memory-store';
import { RandomTokenStrategy } from './random-token.strategy';
import { AuthException } from '../errors/auth.exception';

describe('RandomTokenStrategy', () => {
  let store: MemoryStore;

  beforeEach(() => {
    store = new MemoryStore();
  });

  afterEach(async () => {
    await store.clear();
  });

  it('should generate uuid-v7 token', () => {
    const strategy = new RandomTokenStrategy(store, { style: 'uuid-v7' });
    const token = strategy.generate({
      sessionId: 'ignored',
      userId: 'u1',
    });
    expect(token).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
  });

  it('should generate ulid token', () => {
    const strategy = new RandomTokenStrategy(store, { style: 'ulid' });
    const token = strategy.generate({
      sessionId: 'ignored',
      userId: 'u1',
    });
    expect(token).toHaveLength(26);
    expect(token).toMatch(/^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{26}$/i);
  });

  it.each([
    ['random-32', 32],
    ['random-64', 64],
    ['random-128', 128],
  ] as const)('should generate %s token with length %i', (style, length) => {
    const strategy = new RandomTokenStrategy(store, { style });
    const token = strategy.generate({
      sessionId: 'ignored',
      userId: 'u1',
    });
    expect(token).toHaveLength(length);
    expect(token).toMatch(/^[0-9a-f]+$/i);
  });

  it('should support token prefix', () => {
    const strategy = new RandomTokenStrategy(store, {
      style: 'random-32',
      prefix: 'sa',
    });
    const token = strategy.generate({
      sessionId: 'ignored',
      userId: 'u1',
    });
    expect(token.startsWith('sa:')).toBe(true);
  });

  it('should verify token from session store', async () => {
    const strategy = new RandomTokenStrategy(store, { style: 'random-32' });
    const token = strategy.generate({
      sessionId: 'ignored',
      userId: 'u1',
      device: 'd1',
    });

    await store.set(
      token,
      { userId: 'u1', device: 'd1', createTime: Date.now() },
      3600000,
    );

    const payload = await strategy.verify(token);
    expect(payload.sessionId).toBe(token);
    expect(payload.userId).toBe('u1');
    expect(payload.device).toBe('d1');
  });

  it('should reject token not in session store', async () => {
    const strategy = new RandomTokenStrategy(store, { style: 'random-32' });
    await expect(strategy.verify('non-existent-token')).rejects.toThrow(
      AuthException,
    );
  });

  it('should extract session id as token itself', () => {
    const strategy = new RandomTokenStrategy(store, { style: 'random-32' });
    const token = strategy.generate({
      sessionId: 'ignored',
      userId: 'u1',
    });
    expect(strategy.extractSessionId?.(token)).toBe(token);
  });
});
