import { SqlPersistenceAdapter } from './sql-persistence.adapter';
import type { SqlExecutor } from './sql-persistence.adapter';

/**
 * MySQL 持久化适配器
 */
export class MySqlPersistenceAdapter<
  T = unknown,
> extends SqlPersistenceAdapter<T> {
  constructor(executor: SqlExecutor, tableName: string) {
    super(executor, tableName);
  }

  getPlaceholder(): string {
    return '?';
  }
}
