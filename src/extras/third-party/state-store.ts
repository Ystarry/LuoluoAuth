import { randomUUID } from 'crypto';
import type { StateStore } from './interfaces';

/**
 * 内存版 OAuth2 state 存储
 * 单实例场景可用，多实例部署时请替换为 Redis 实现
 */
export class MemoryStateStore implements StateStore {
  private readonly store = new Map<string, { state: string; expiresAt: number }>();

  async save(state: string, ttlSeconds: number): Promise<string> {
    const key = randomUUID();
    this.store.set(key, {
      state,
      expiresAt: Date.now() + ttlSeconds * 1000,
    });
    this.cleanup();
    return key;
  }

  async verify(key: string, state: string): Promise<boolean> {
    const record = this.store.get(key);
    if (!record) {
      return false;
    }
    this.store.delete(key);
    if (record.expiresAt < Date.now()) {
      return false;
    }
    return record.state === state;
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, record] of this.store.entries()) {
      if (record.expiresAt < now) {
        this.store.delete(key);
      }
    }
  }
}