import { DynamicModule, Module } from '@nestjs/common';
import type {
  PersistenceAdapter,
  PersistenceAdapterFactory,
} from './persistence.interface';
import { SimplePersistenceAdapterFactory } from './persistence.factory';

/**
 * 持久化模块配置
 */
export interface PersistenceModuleOptions {
  /** 自定义适配器工厂 */
  factory?: PersistenceAdapterFactory;
  /** 自定义实体适配器映射 */
  adapters?: Record<string, PersistenceAdapter<unknown>>;
}

/**
 * 持久化模块
 * 提供统一的 PersistenceAdapterFactory，支持内存/SQL/MongoDB 等多种后端。
 *
 * ## 使用示例
 * ```typescript
 * import { PersistenceModule } from 'luoluo-auth';
 *
 * @Module({
 *   imports: [PersistenceModule.register()],
 * })
 * export class AppModule {}
 * ```
 */
@Module({})
export class PersistenceModule {
  /**
   * 同步注册持久化模块
   * @param options - 持久化模块配置
   */
  static register(options: PersistenceModuleOptions = {}): DynamicModule {
    const factory = options.factory ?? new SimplePersistenceAdapterFactory();

    if (
      options.adapters &&
      factory instanceof SimplePersistenceAdapterFactory
    ) {
      for (const [entityName, adapter] of Object.entries(options.adapters)) {
        factory.registerAdapter(entityName, adapter);
      }
    }

    return {
      module: PersistenceModule,
      providers: [
        {
          provide: 'PERSISTENCE_ADAPTER_FACTORY',
          useValue: factory,
        },
      ],
      exports: ['PERSISTENCE_ADAPTER_FACTORY'],
      global: true,
    };
  }
}
