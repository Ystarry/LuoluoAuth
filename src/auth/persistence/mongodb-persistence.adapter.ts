import type {
  PersistenceAdapter,
  PersistenceFilter,
} from './persistence.interface';

/**
 * MongoDB Collection 抽象
 * 屏蔽具体驱动（mongodb driver / mongoose）差异
 */
export interface MongoCollection<T = unknown> {
  insertOne(doc: unknown): Promise<void>;
  findOne(filter: Record<string, unknown>): Promise<T | null>;
  find(filter: Record<string, unknown>): Promise<T[]>;
  updateOne(
    filter: Record<string, unknown>,
    update: Record<string, unknown>,
  ): Promise<void>;
  deleteOne(filter: Record<string, unknown>): Promise<void>;
  countDocuments(filter: Record<string, unknown>): Promise<number>;
}

/**
 * MongoDB 持久化适配器
 */
export class MongoDbPersistenceAdapter<
  T = unknown,
> implements PersistenceAdapter<T> {
  constructor(private readonly collection: MongoCollection<T>) {}

  async create(id: string, data: T): Promise<void> {
    const doc = { _id: id, ...data } as Record<string, unknown>;
    await this.collection.insertOne(doc);
  }

  async findById(id: string): Promise<T | null> {
    return this.collection.findOne({ _id: id });
  }

  async find(filter?: PersistenceFilter): Promise<T[]> {
    return this.collection.find(filter || {});
  }

  async update(id: string, data: Partial<T>): Promise<void> {
    await this.collection.updateOne({ _id: id }, { $set: data });
  }

  async delete(id: string): Promise<void> {
    await this.collection.deleteOne({ _id: id });
  }

  async count(filter?: PersistenceFilter): Promise<number> {
    return this.collection.countDocuments(filter || {});
  }
}
