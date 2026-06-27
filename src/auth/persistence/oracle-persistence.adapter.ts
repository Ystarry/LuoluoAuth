import { SqlPersistenceAdapter } from './sql-persistence.adapter';
import type { SqlExecutor } from './sql-persistence.adapter';

/**
 * Oracle 持久化适配器
 */
export class OraclePersistenceAdapter<
  T = unknown,
> extends SqlPersistenceAdapter<T> {
  constructor(executor: SqlExecutor, tableName: string) {
    super(executor, tableName);
  }

  getPlaceholder(): string {
    return '?';
  }
}
