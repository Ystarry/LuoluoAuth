import { MemoryPersistenceAdapter } from './memory-persistence.adapter';
import { SqlExecutor } from './sql-persistence.adapter';
import { MySqlPersistenceAdapter } from './mysql-persistence.adapter';
import { PostgresPersistenceAdapter } from './postgres-persistence.adapter';
import { OraclePersistenceAdapter } from './oracle-persistence.adapter';
import { SqlitePersistenceAdapter } from './sqlite-persistence.adapter';
import {
  MongoDbPersistenceAdapter,
  MongoCollection,
} from './mongodb-persistence.adapter';
import { SimplePersistenceAdapterFactory } from './persistence.factory';
import { PersistenceModule } from './persistence.module';

interface TestRecord {
  name: string;
  age: number;
}

describe('MemoryPersistenceAdapter', () => {
  let adapter: MemoryPersistenceAdapter<TestRecord>;

  beforeEach(() => {
    adapter = new MemoryPersistenceAdapter<TestRecord>();
  });

  it('should create and find by id', async () => {
    await adapter.create('1', { name: 'Alice', age: 30 });
    const record = await adapter.findById('1');
    expect(record).toEqual({ name: 'Alice', age: 30 });
  });

  it('should return null for non-existent id', async () => {
    const record = await adapter.findById('missing');
    expect(record).toBeNull();
  });

  it('should update record', async () => {
    await adapter.create('1', { name: 'Alice', age: 30 });
    await adapter.update('1', { age: 31 });
    const record = await adapter.findById('1');
    expect(record).toEqual({ name: 'Alice', age: 31 });
  });

  it('should delete record', async () => {
    await adapter.create('1', { name: 'Alice', age: 30 });
    await adapter.delete('1');
    const record = await adapter.findById('1');
    expect(record).toBeNull();
  });

  it('should find with filter', async () => {
    await adapter.create('1', { name: 'Alice', age: 30 });
    await adapter.create('2', { name: 'Bob', age: 25 });
    await adapter.create('3', { name: 'Alice', age: 35 });

    const result = await adapter.find({ name: 'Alice' });
    expect(result).toHaveLength(2);
  });

  it('should count records', async () => {
    await adapter.create('1', { name: 'Alice', age: 30 });
    await adapter.create('2', { name: 'Bob', age: 25 });
    expect(await adapter.count()).toBe(2);
    expect(await adapter.count({ age: 25 })).toBe(1);
  });
});

describe('SqlPersistenceAdapter', () => {
  function createMockExecutor(): SqlExecutor {
    const storage = new Map<string, string>();
    return {
      query: jest.fn((sql: string, params: unknown[]) => {
        if (sql.includes('SELECT data FROM')) {
          if (sql.includes('WHERE id =')) {
            const id = params[0] as string;
            const data = storage.get(id);
            return Promise.resolve(data ? [{ data }] : []);
          }
          return Promise.resolve(
            Array.from(storage.values()).map((data) => ({ data })),
          );
        }
        return Promise.resolve([]);
      }),
      execute: jest.fn((sql: string, params: unknown[]) => {
        if (sql.includes('INSERT')) {
          const id = params[0] as string;
          const data = params[1] as string;
          storage.set(id, data);
        } else if (sql.includes('UPDATE')) {
          const data = params[0] as string;
          const id = params[2] as string;
          storage.set(id, data);
        } else if (sql.includes('DELETE')) {
          const id = params[0] as string;
          storage.delete(id);
        }
        return Promise.resolve({ affectedRows: 1 });
      }),
    };
  }

  it('should generate MySQL placeholders', async () => {
    const executor = createMockExecutor();
    const adapter = new MySqlPersistenceAdapter<TestRecord>(executor, 'users');
    await adapter.create('1', { name: 'Alice', age: 30 });
    const record = await adapter.findById('1');
    expect(record).toEqual({ name: 'Alice', age: 30 });
  });

  it('should generate Postgres placeholders', async () => {
    const executor = createMockExecutor();
    const adapter = new PostgresPersistenceAdapter<TestRecord>(
      executor,
      'users',
    );
    await adapter.create('1', { name: 'Alice', age: 30 });
    const record = await adapter.findById('1');
    expect(record).toEqual({ name: 'Alice', age: 30 });
    expect(adapter.getPlaceholder(0)).toBe('$1');
    expect(adapter.getPlaceholder(1)).toBe('$2');
  });

  it('should support Oracle placeholders', async () => {
    const executor = createMockExecutor();
    const adapter = new OraclePersistenceAdapter<TestRecord>(executor, 'users');
    await adapter.create('1', { name: 'Alice', age: 30 });
    expect(await adapter.count()).toBe(1);
  });

  it('should support SQLite placeholders', async () => {
    const executor = createMockExecutor();
    const adapter = new SqlitePersistenceAdapter<TestRecord>(executor, 'users');
    await adapter.create('1', { name: 'Alice', age: 30 });
    await adapter.delete('1');
    expect(await adapter.findById('1')).toBeNull();
  });

  it('should find with filter using client-side filtering', async () => {
    const executor = createMockExecutor();
    const adapter = new MySqlPersistenceAdapter<TestRecord>(executor, 'users');
    await adapter.create('1', { name: 'Alice', age: 30 });
    await adapter.create('2', { name: 'Bob', age: 25 });
    await adapter.create('3', { name: 'Alice', age: 35 });

    const result = await adapter.find({ name: 'Alice' });
    expect(result).toHaveLength(2);
    expect(result.map((r) => r.age)).toEqual([30, 35]);
  });

  it('should find all when no filter is provided', async () => {
    const executor = createMockExecutor();
    const adapter = new MySqlPersistenceAdapter<TestRecord>(executor, 'users');
    await adapter.create('1', { name: 'Alice', age: 30 });
    await adapter.create('2', { name: 'Bob', age: 25 });

    const result = await adapter.find();
    expect(result).toHaveLength(2);
  });

  it('should update non-existent record (create with partial data)', async () => {
    const executor = createMockExecutor();
    const adapter = new MySqlPersistenceAdapter<TestRecord>(executor, 'users');
    // Update a record that doesn't exist yet
    await adapter.update('new-id', { name: 'New User', age: 20 });
    const record = await adapter.findById('new-id');
    expect(record).toEqual({ name: 'New User', age: 20 });
  });

  it('should count with filter', async () => {
    const executor = createMockExecutor();
    const adapter = new MySqlPersistenceAdapter<TestRecord>(executor, 'users');
    await adapter.create('1', { name: 'Alice', age: 30 });
    await adapter.create('2', { name: 'Bob', age: 25 });
    await adapter.create('3', { name: 'Alice', age: 35 });

    expect(await adapter.count({ name: 'Alice' })).toBe(2);
    expect(await adapter.count({ name: 'Bob' })).toBe(1);
    expect(await adapter.count({ name: 'Charlie' })).toBe(0);
  });

  it('should count all without filter', async () => {
    const executor = createMockExecutor();
    const adapter = new MySqlPersistenceAdapter<TestRecord>(executor, 'users');
    await adapter.create('1', { name: 'Alice', age: 30 });
    await adapter.create('2', { name: 'Bob', age: 25 });

    expect(await adapter.count()).toBe(2);
  });
});

describe('MongoDbPersistenceAdapter', () => {
  function createMockCollection(): MongoCollection<TestRecord> {
    const docs = new Map<string, TestRecord>();
    return {
      insertOne: jest.fn((doc: unknown) => {
        const record = doc as Record<string, unknown>;
        docs.set(record._id as string, {
          name: record.name as string,
          age: record.age as number,
        });
        return Promise.resolve();
      }),
      findOne: jest.fn((filter: Record<string, unknown>) => {
        const id = filter._id as string;
        return Promise.resolve(id ? (docs.get(id) ?? null) : null);
      }),
      find: jest.fn((filter: Record<string, unknown>) => {
        return Promise.resolve(
          Array.from(docs.values()).filter((doc) =>
            Object.entries(filter).every(([key, value]) =>
              key === '_id'
                ? true
                : (doc as Record<string, unknown>)[key] === value,
            ),
          ),
        );
      }),
      updateOne: jest.fn(
        (filter: Record<string, unknown>, update: Record<string, unknown>) => {
          const id = filter._id as string;
          const existing = docs.get(id);
          if (existing && update.$set) {
            docs.set(id, { ...existing, ...(update.$set as TestRecord) });
          }
          return Promise.resolve();
        },
      ),
      deleteOne: jest.fn((filter: Record<string, unknown>) => {
        docs.delete(filter._id as string);
        return Promise.resolve();
      }),
      countDocuments: jest.fn((filter: Record<string, unknown>) => {
        const items = Array.from(docs.values()).filter((doc) =>
          Object.entries(filter).every(([key, value]) =>
            key === '_id'
              ? true
              : (doc as Record<string, unknown>)[key] === value,
          ),
        );
        return Promise.resolve(items.length);
      }),
    };
  }

  it('should create and find by id', async () => {
    const collection = createMockCollection();
    const adapter = new MongoDbPersistenceAdapter<TestRecord>(collection);
    await adapter.create('1', { name: 'Alice', age: 30 });
    const record = await adapter.findById('1');
    expect(record).toEqual({ name: 'Alice', age: 30 });
  });

  it('should update record', async () => {
    const collection = createMockCollection();
    const adapter = new MongoDbPersistenceAdapter<TestRecord>(collection);
    await adapter.create('1', { name: 'Alice', age: 30 });
    await adapter.update('1', { age: 31 });
    const record = await adapter.findById('1');
    expect(record).toEqual({ name: 'Alice', age: 31 });
  });

  it('should delete record', async () => {
    const collection = createMockCollection();
    const adapter = new MongoDbPersistenceAdapter<TestRecord>(collection);
    await adapter.create('1', { name: 'Alice', age: 30 });
    await adapter.delete('1');
    expect(await adapter.findById('1')).toBeNull();
  });

  it('should find all records', async () => {
    const collection = createMockCollection();
    const adapter = new MongoDbPersistenceAdapter<TestRecord>(collection);
    await adapter.create('1', { name: 'Alice', age: 30 });
    await adapter.create('2', { name: 'Bob', age: 25 });

    const result = await adapter.find();
    expect(result).toHaveLength(2);
  });

  it('should find with filter', async () => {
    const collection = createMockCollection();
    const adapter = new MongoDbPersistenceAdapter<TestRecord>(collection);
    await adapter.create('1', { name: 'Alice', age: 30 });
    await adapter.create('2', { name: 'Bob', age: 25 });

    const result = await adapter.find({ name: 'Alice' });
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('Alice');
  });

  it('should count records', async () => {
    const collection = createMockCollection();
    const adapter = new MongoDbPersistenceAdapter<TestRecord>(collection);
    await adapter.create('1', { name: 'Alice', age: 30 });
    await adapter.create('2', { name: 'Bob', age: 25 });

    expect(await adapter.count()).toBe(2);
    expect(await adapter.count({ name: 'Alice' })).toBe(1);
  });
});

describe('SimplePersistenceAdapterFactory', () => {
  let factory: SimplePersistenceAdapterFactory;

  beforeEach(() => {
    factory = new SimplePersistenceAdapterFactory();
  });

  it('should return a MemoryPersistenceAdapter by default', () => {
    const adapter = factory.getAdapter<TestRecord>('users');
    expect(adapter).toBeInstanceOf(MemoryPersistenceAdapter);
  });

  it('should return the same adapter instance for the same entity name', () => {
    const adapter1 = factory.getAdapter<TestRecord>('users');
    const adapter2 = factory.getAdapter<TestRecord>('users');
    expect(adapter1).toBe(adapter2);
  });

  it('should return different adapters for different entity names', () => {
    const usersAdapter = factory.getAdapter<TestRecord>('users');
    const postsAdapter = factory.getAdapter<TestRecord>('posts');
    expect(usersAdapter).not.toBe(postsAdapter);
  });

  it('should allow registering a custom adapter', () => {
    const customAdapter = new MemoryPersistenceAdapter<TestRecord>();
    factory.registerAdapter('custom', customAdapter);
    const adapter = factory.getAdapter<TestRecord>('custom');
    expect(adapter).toBe(customAdapter);
  });

  it('should use custom adapter for CRUD operations', async () => {
    const customAdapter = new MemoryPersistenceAdapter<TestRecord>();
    factory.registerAdapter('custom', customAdapter);

    const adapter = factory.getAdapter<TestRecord>('custom');
    await adapter.create('1', { name: 'Bob', age: 25 });
    const record = await adapter.findById('1');
    expect(record).toEqual({ name: 'Bob', age: 25 });
  });
});

describe('PersistenceModule', () => {
  describe('register', () => {
    it('should create a dynamic module with default options', () => {
      const module = PersistenceModule.register();

      expect(module.module).toBe(PersistenceModule);
      expect(module.global).toBe(true);
      expect(module.exports).toEqual(['PERSISTENCE_ADAPTER_FACTORY']);
    });

    it('should have a PERSISTENCE_ADAPTER_FACTORY provider', () => {
      const module = PersistenceModule.register();

      const factoryProvider = module.providers?.find(
        (p) =>
          typeof p === 'object' &&
          'provide' in p &&
          (p as Record<string, unknown>).provide ===
            'PERSISTENCE_ADAPTER_FACTORY',
      );
      expect(factoryProvider).toBeDefined();
      expect(
        (factoryProvider as Record<string, unknown>).useValue,
      ).toBeInstanceOf(SimplePersistenceAdapterFactory);
    });

    it('should create a module with a custom factory', () => {
      const customFactory = new SimplePersistenceAdapterFactory();
      const module = PersistenceModule.register({ factory: customFactory });

      const factoryProvider = module.providers?.find(
        (p) =>
          typeof p === 'object' &&
          'provide' in p &&
          (p as Record<string, unknown>).provide ===
            'PERSISTENCE_ADAPTER_FACTORY',
      );
      expect((factoryProvider as Record<string, unknown>).useValue).toBe(
        customFactory,
      );
    });

    it('should register custom adapters from options', () => {
      const customAdapter = new MemoryPersistenceAdapter<TestRecord>();
      const module = PersistenceModule.register({
        adapters: { users: customAdapter },
      });

      const factoryProvider = module.providers?.find(
        (p) =>
          typeof p === 'object' &&
          'provide' in p &&
          (p as Record<string, unknown>).provide ===
            'PERSISTENCE_ADAPTER_FACTORY',
      );
      const factory = (factoryProvider as Record<string, unknown>)
        .useValue as SimplePersistenceAdapterFactory;
      const adapter = factory.getAdapter<TestRecord>('users');
      expect(adapter).toBe(customAdapter);
    });

    it('should not register adapters when factory is not SimplePersistenceAdapterFactory', () => {
      const customFactory = {
        getAdapter: jest.fn(),
      };
      const customAdapter = new MemoryPersistenceAdapter<TestRecord>();
      const module = PersistenceModule.register({
        factory: customFactory as unknown as SimplePersistenceAdapterFactory,
        adapters: { users: customAdapter },
      });

      const factoryProvider = module.providers?.find(
        (p) =>
          typeof p === 'object' &&
          'provide' in p &&
          (p as Record<string, unknown>).provide ===
            'PERSISTENCE_ADAPTER_FACTORY',
      );
      expect((factoryProvider as Record<string, unknown>).useValue).toBe(
        customFactory,
      );
    });
  });
});
