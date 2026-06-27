import { SqlPersistenceAdapter } from './sql-persistence.adapter';
import type { SqlExecutor } from './sql-persistence.adapter';

/**
 * PostgreSQL 持久化适配器
 */
export class PostgresPersistenceAdapter<
  T = unknown,
> extends SqlPersistenceAdapter<T> {
  constructor(executor: SqlExecutor, tableName: string) {
    super(executor, tableName);
  }

  getPlaceholder(index: number): string {
    return `$${index + 1}`;
  }
}
