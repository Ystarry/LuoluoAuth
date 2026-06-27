import type {
  PersistenceAdapter,
  PersistenceFilter,
} from './persistence.interface';

/**
 * SQL 执行器抽象
 * 屏蔽具体驱动差异（mysql2 / pg / oracledb / better-sqlite3 等）。
 *
 * ## 设计说明
 * 本持久化层采用 **驱动无关 (driver-agnostic)** 设计：
 * - `SqlPersistenceAdapter` 提供完整的 CRUD SQL 实现，不依赖任何特定数据库驱动
 * - 各数据库适配器（MySQL / PostgreSQL / Oracle / SQLite）仅需实现 `getPlaceholder()` 方法
 *   来提供对应数据库的占位符语法（`?` 或 `$1`）
 * - 用户需自行实现 `SqlExecutor` 接口，封装底层数据库驱动的 `query()` 和 `execute()` 方法
 *
 * ### 使用示例
 * ```typescript
 * import { createPool } from 'mysql2/promise';
 * import { MySqlPersistenceAdapter, SqlExecutor } from 'luoluo-auth';
 *
 * const pool = createPool({ host: 'localhost', user: 'root', database: 'auth' });
 *
 * const executor: SqlExecutor = {
 *   query: (sql, params) => pool.execute(sql, params),
 *   execute: (sql, params) => pool.execute(sql, params),
 * };
 *
 * const adapter = new MySqlPersistenceAdapter<User>(executor, 'users');
 * await adapter.create('1', { name: 'Alice' });
 * ```
 */
export interface SqlExecutor {
  /**
   * 执行查询并返回结果集
   * @param sql - SQL 语句
   * @param params - 占位符参数
   */
  query(sql: string, params: unknown[]): Promise<Record<string, unknown>[]>;

  /**
   * 执行写入操作
   * @param sql - SQL 语句
   * @param params - 占位符参数
   */
  execute(sql: string, params: unknown[]): Promise<{ affectedRows: number }>;
}

/**
 * SQL 持久化适配器抽象基类
 * 通过 JSON 序列化统一存储任意实体数据
 */
export abstract class SqlPersistenceAdapter<
  T = unknown,
> implements PersistenceAdapter<T> {
  constructor(
    protected readonly executor: SqlExecutor,
    protected readonly tableName: string,
  ) {}

  /**
   * 返回占位符
   * MySQL/Oracle/SQLite 返回 `?`，PostgreSQL 返回 `$1, $2, ...`
   */
  abstract getPlaceholder(index: number): string;

  protected serialize(data: T): string {
    return JSON.stringify(data);
  }

  protected deserialize(raw: string): T {
    return JSON.parse(raw) as T;
  }

  async create(id: string, data: T): Promise<void> {
    const sql = `INSERT INTO ${this.tableName} (id, data, created_at, updated_at) VALUES (${this.getPlaceholder(0)}, ${this.getPlaceholder(1)}, ${this.getPlaceholder(2)}, ${this.getPlaceholder(3)})`;
    const now = Date.now();
    await this.executor.execute(sql, [id, this.serialize(data), now, now]);
  }

  async findById(id: string): Promise<T | null> {
    const sql = `SELECT data FROM ${this.tableName} WHERE id = ${this.getPlaceholder(0)}`;
    const rows = await this.executor.query(sql, [id]);
    if (rows.length === 0) {
      return null;
    }
    return this.deserialize(rows[0].data as string);
  }

  async find(filter?: PersistenceFilter): Promise<T[]> {
    const sql = `SELECT data FROM ${this.tableName}`;
    const params: unknown[] = [];

    if (filter && Object.keys(filter).length > 0) {
      // 使用 JSON 字段过滤（各数据库 JSON 函数差异较大，基类提供简单实现）
      // 子类可重写以利用数据库原生 JSON 能力
      const rows = await this.executor.query(sql, params);
      return this.filterRows(rows, filter);
    }

    const rows = await this.executor.query(sql, params);
    return rows.map((row) => this.deserialize(row.data as string));
  }

  async update(id: string, data: Partial<T>): Promise<void> {
    const existing = await this.findById(id);
    const merged = existing ? { ...existing, ...data } : data;
    const sql = `UPDATE ${this.tableName} SET data = ${this.getPlaceholder(0)}, updated_at = ${this.getPlaceholder(1)} WHERE id = ${this.getPlaceholder(2)}`;
    await this.executor.execute(sql, [
      this.serialize(merged as T),
      Date.now(),
      id,
    ]);
  }

  async delete(id: string): Promise<void> {
    const sql = `DELETE FROM ${this.tableName} WHERE id = ${this.getPlaceholder(0)}`;
    await this.executor.execute(sql, [id]);
  }

  async count(filter?: PersistenceFilter): Promise<number> {
    const items = await this.find(filter);
    return items.length;
  }

  /**
   * 客户端过滤实现（兜底）
   * 子类可重写以使用数据库原生 JSON 过滤
   */
  protected filterRows(
    rows: Record<string, unknown>[],
    filter: PersistenceFilter,
  ): T[] {
    const entries = Object.entries(filter);
    return rows
      .map((row) => this.deserialize(row.data as string))
      .filter((item) =>
        entries.every(([key, value]) => {
          const record = item as Record<string, unknown>;
          return record[key] === value;
        }),
      );
  }
}
