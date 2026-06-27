import { randomUUID } from 'crypto';
import { DistributedLock, LockToken } from './distributed-lock.interface';

/**
 * 内存分布式锁
 * 仅适用于单进程场景，作为 Redis 不可用时降级方案
 */
export class MemoryDistributedLock implements DistributedLock {
  private readonly locks = new Map<
    string,
    { token: string; expireAt: number; timer: NodeJS.Timeout }
  >();

  acquire(key: string, ttlMs: number): Promise<LockToken | undefined> {
    const now = Date.now();
    const existing = this.locks.get(key);

    // 清理已过期但尚未触发定时器的锁
    if (existing && now >= existing.expireAt) {
      clearTimeout(existing.timer);
      this.locks.delete(key);
    }

    if (this.locks.has(key)) {
      return Promise.resolve(undefined);
    }

    const token = randomUUID();
    const expireAt = now + ttlMs;
    const timer = setTimeout(() => {
      this.locks.delete(key);
    }, ttlMs);
    timer.unref();

    this.locks.set(key, { token, expireAt, timer });

    return Promise.resolve({ key, token });
  }

  release(lock: LockToken): Promise<void> {
    const existing = this.locks.get(lock.key);
    if (!existing || existing.token !== lock.token) {
      return Promise.resolve();
    }

    clearTimeout(existing.timer);
    this.locks.delete(lock.key);
    return Promise.resolve();
  }
}
