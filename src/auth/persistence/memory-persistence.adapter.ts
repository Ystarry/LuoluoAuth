import type {
  PersistenceAdapter,
  PersistenceFilter,
} from './persistence.interface';

/**
 * 内存持久化适配器
 * 基于 Map 实现，适用于测试和无需持久化的场景
 */
export class MemoryPersistenceAdapter<
  T = unknown,
> implements PersistenceAdapter<T> {
  private readonly store = new Map<string, T>();

  create(id: string, data: T): Promise<void> {
    this.store.set(id, data);
    return Promise.resolve();
  }

  findById(id: string): Promise<T | null> {
    return Promise.resolve(this.store.get(id) ?? null);
  }

  find(filter?: PersistenceFilter): Promise<T[]> {
    const items = Array.from(this.store.values());
    if (!filter) {
      return Promise.resolve(items);
    }

    const entries = Object.entries(filter);
    const result = items.filter((item) =>
      entries.every(([key, value]) => {
        const record = item as Record<string, unknown>;
        return record[key] === value;
      }),
    );

    return Promise.resolve(result);
  }

  update(id: string, data: Partial<T>): Promise<void> {
    const existing = this.store.get(id);
    if (!existing) {
      return Promise.resolve();
    }
    this.store.set(id, { ...existing, ...data });
    return Promise.resolve();
  }

  delete(id: string): Promise<void> {
    this.store.delete(id);
    return Promise.resolve();
  }

  count(filter?: PersistenceFilter): Promise<number> {
    return this.find(filter).then((items) => items.length);
  }

  /**
   * 清空所有数据（测试辅助方法）
   */
  clear(): void {
    this.store.clear();
  }
}
