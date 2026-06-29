import type Redis from 'ioredis';

/**
 * Nonce 存储接口
 * 用于签名认证中的随机数去重，防止重放攻击
 */
export interface NonceStore {
  /**
   * 判断 nonce 是否已存在
   * @param nonce - 随机字符串
   * @returns true 表示已存在（重复）
   */
  has(nonce: string): Promise<boolean>;

  /**
   * 记录 nonce
   * @param nonce - 随机字符串
   * @param ttlMs - 过期时间（毫秒）
   */
  set(nonce: string, ttlMs: number): Promise<void>;

  /**
   * 原子地记录 nonce：仅当 nonce 不存在时才写入
   * @param nonce - 随机字符串
   * @param ttlMs - 过期时间（毫秒）
   * @returns true 表示写入成功（nonce 此前不存在），false 表示 nonce 已存在
   */
  setIfAbsent(nonce: string, ttlMs: number): Promise<boolean>;
}

/**
 * 基于 LRU 的内存 Nonce 存储
 * 无 Redis 时的兜底实现，自动清理过期条目并在容量满时驱逐最久未使用项
 */
export class MemoryNonceStore implements NonceStore {
  private readonly records = new Map<string, number>();

  /**
   * @param maxSize - 最大缓存条目数（默认 10000）
   */
  constructor(private readonly maxSize = 10000) {}

  /**
   * 判断 nonce 是否已存在
   * 存在时将该 nonce 移到队列尾部（最近使用）
   * @param nonce - 随机字符串
   */
  // eslint-disable-next-line @typescript-eslint/require-await
  async has(nonce: string): Promise<boolean> {
    this.evictExpired();

    const expireAt = this.records.get(nonce);
    if (!expireAt) {
      return false;
    }

    if (expireAt <= Date.now()) {
      this.records.delete(nonce);
      return false;
    }

    // LRU：移动到队尾表示最近使用
    this.records.delete(nonce);
    this.records.set(nonce, expireAt);
    return true;
  }

  /**
   * 记录 nonce
   * @param nonce - 随机字符串
   * @param ttlMs - 过期时间（毫秒）
   */
  // eslint-disable-next-line @typescript-eslint/require-await
  async set(nonce: string, ttlMs: number): Promise<void> {
    this.evictExpired();

    if (this.records.has(nonce)) {
      this.records.delete(nonce);
    } else if (this.records.size >= this.maxSize) {
      // Map 按插入顺序迭代，队首即为最久未使用
      const firstKey = this.records.keys().next().value as string;
      this.records.delete(firstKey);
    }

    this.records.set(nonce, Date.now() + ttlMs);
  }

  /**
   * 原子地记录 nonce（内存实现使用 Map 单线程语义）
   * @param nonce - 随机字符串
   * @param ttlMs - 过期时间（毫秒）
   * @returns true 表示写入成功，false 表示 nonce 已存在
   */
  // eslint-disable-next-line @typescript-eslint/require-await
  async setIfAbsent(nonce: string, ttlMs: number): Promise<boolean> {
    this.evictExpired();

    if (this.records.has(nonce)) {
      return false;
    }

    if (this.records.size >= this.maxSize) {
      const firstKey = this.records.keys().next().value as string;
      this.records.delete(firstKey);
    }

    this.records.set(nonce, Date.now() + ttlMs);
    return true;
  }

  /**
   * 清理已过期条目
   */
  private evictExpired(): void {
    const now = Date.now();
    for (const [key, expireAt] of this.records.entries()) {
      if (expireAt <= now) {
        this.records.delete(key);
      }
    }
  }
}

/**
 * 基于 Redis 的 Nonce 存储
 * 使用 SET PX 实现带过期时间的原子写入
 */
export class RedisNonceStore implements NonceStore {
  private readonly prefix: string;

  /**
   * @param redis - Redis 连接实例
   * @param prefix - key 前缀（默认 auth:nonce）
   */
  constructor(
    private readonly redis: Redis,
    prefix?: string,
  ) {
    this.prefix = prefix || 'auth:nonce';
  }

  /**
   * 判断 nonce 是否已存在
   * @param nonce - 随机字符串
   */
  async has(nonce: string): Promise<boolean> {
    const exists = await this.redis.get(`${this.prefix}:${nonce}`);
    return !!exists;
  }

  /**
   * 记录 nonce
   * @param nonce - 随机字符串
   * @param ttlMs - 过期时间（毫秒）
   */
  async set(nonce: string, ttlMs: number): Promise<void> {
    await this.redis.set(`${this.prefix}:${nonce}`, '1', 'PX', ttlMs);
  }

  /**
   * 原子地记录 nonce：仅当 key 不存在时才写入（SET ... PX NX）
   * @param nonce - 随机字符串
   * @param ttlMs - 过期时间（毫秒）
   * @returns true 表示写入成功，false 表示 nonce 已存在
   */
  async setIfAbsent(nonce: string, ttlMs: number): Promise<boolean> {
    const result = await this.redis.set(
      `${this.prefix}:${nonce}`,
      '1',
      'PX',
      ttlMs,
      'NX',
    );
    return result === 'OK';
  }
}
