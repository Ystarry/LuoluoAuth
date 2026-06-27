/**
 * 通用过滤条件
 * 支持等值过滤，复杂条件由各适配器自行扩展
 */
export interface PersistenceFilter {
  [key: string]: unknown;
}

/**
 * 抽象持久化适配器接口
 * 为认证框架提供统一的 CRUD 能力，屏蔽底层存储差异。
 *
 * ## 设计说明
 * 本持久化层采用 **驱动无关 (driver-agnostic)** 设计：
 * - 框架提供完整的 CRUD 实现（`SqlPersistenceAdapter` / `MongoDbPersistenceAdapter` / `MemoryPersistenceAdapter`）
 * - 用户通过实现 `SqlExecutor` 接口（或 `MongoCollection` 接口）注入实际数据库驱动
 * - 非接口预留或示例代码，可直接用于生产环境
 */
export interface PersistenceAdapter<T = unknown> {
  /**
   * 创建记录
   * @param id - 记录唯一标识
   * @param data - 记录数据
   */
  create(id: string, data: T): Promise<void>;

  /**
   * 根据 ID 查询记录
   * @param id - 记录唯一标识
   * @returns 记录数据，不存在时返回 null
   */
  findById(id: string): Promise<T | null>;

  /**
   * 根据过滤条件查询记录列表
   * @param filter - 过滤条件
   * @returns 记录数组
   */
  find(filter?: PersistenceFilter): Promise<T[]>;

  /**
   * 更新记录
   * @param id - 记录唯一标识
   * @param data - 需要更新的字段
   */
  update(id: string, data: Partial<T>): Promise<void>;

  /**
   * 删除记录
   * @param id - 记录唯一标识
   */
  delete(id: string): Promise<void>;

  /**
   * 统计记录数量
   * @param filter - 过滤条件
   * @returns 记录数量
   */
  count(filter?: PersistenceFilter): Promise<number>;
}

/**
 * 持久化适配器工厂
 * 用于按实体名称获取对应的适配器实例
 */
export interface PersistenceAdapterFactory {
  getAdapter<T>(entityName: string): PersistenceAdapter<T>;
}
