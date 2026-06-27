import type {
  PersistenceAdapter,
  PersistenceAdapterFactory,
} from './persistence.interface';
import { MemoryPersistenceAdapter } from './memory-persistence.adapter';

/**
 * 简单持久化适配器工厂
 * 默认返回内存适配器，可扩展为根据配置返回 SQL/MongoDB 适配器
 */
export class SimplePersistenceAdapterFactory implements PersistenceAdapterFactory {
  private readonly adapters = new Map<string, PersistenceAdapter<unknown>>();

  getAdapter<T>(entityName: string): PersistenceAdapter<T> {
    if (!this.adapters.has(entityName)) {
      this.adapters.set(entityName, new MemoryPersistenceAdapter<unknown>());
    }
    return this.adapters.get(entityName)! as PersistenceAdapter<T>;
  }

  /**
   * 注册自定义实体适配器
   * @param entityName - 实体名称
   * @param adapter - 适配器实例
   */
  registerAdapter<T>(entityName: string, adapter: PersistenceAdapter<T>): void {
    this.adapters.set(entityName, adapter);
  }
}
