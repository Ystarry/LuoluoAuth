import { randomUUID } from 'crypto';
import type Redis from 'ioredis';
import { DistributedLock, LockToken } from './distributed-lock.interface';

/**
 * Redis 分布式锁
 * 基于 SET key value PX ttl NX + Lua 脚本安全释放
 */
export class RedisDistributedLock implements DistributedLock {
  private readonly prefix = 'auth:lock:';

  constructor(private readonly redis: Redis) {}

  async acquire(key: string, ttlMs: number): Promise<LockToken | undefined> {
    const token = randomUUID();
    const lockKey = this.prefix + key;

    const result = await this.redis.set(lockKey, token, 'PX', ttlMs, 'NX');

    if (result !== 'OK') {
      return undefined;
    }

    return { key: lockKey, token };
  }

  async release(lock: LockToken): Promise<void> {
    const script = `
      if redis.call('get', KEYS[1]) == ARGV[1] then
        return redis.call('del', KEYS[1])
      else
        return 0
      end
    `;
    await this.redis.eval(script, 1, lock.key, lock.token);
  }
}
