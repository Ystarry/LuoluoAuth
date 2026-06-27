/**
 * 分布式锁返回的凭证
 */
export interface LockToken {
  /** 锁键 */
  key: string;
  /** 唯一凭证，释放锁时必须携带 */
  token: string;
}

/**
 * 分布式锁接口
 */
export interface DistributedLock {
  /**
   * 尝试获取锁
   * @param key - 锁键
   * @param ttlMs - 锁最大持有时间（毫秒）
   * @returns 获取成功返回 LockToken，失败返回 undefined
   */
  acquire(key: string, ttlMs: number): Promise<LockToken | undefined>;

  /**
   * 释放锁
   * @param lock - acquire 返回的凭证
   */
  release(lock: LockToken): Promise<void>;
}
