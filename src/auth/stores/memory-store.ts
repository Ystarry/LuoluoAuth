import {
  BlacklistStore,
  SessionData,
  SessionStore,
} from '../interfaces/session-store.interface';

/** setTimeout 最大延迟（2^31 - 1 毫秒），超过会导致溢出 */
const MAX_TIMEOUT_MS = 2147483647;

/**
 * 内存存储配置选项
 */
export interface MemoryStoreOptions {
  /** 最大存储会话数量，超过将触发 LRU 淘汰（默认 0 表示不限制） */
  maxSize?: number;
}

/**
 * 内存中的 Session 存储项
 */
interface StoreItem {
  /** 会话数据 */
  data: SessionData;
  /** 过期时间戳（毫秒） */
  expireAt: number;
  /** 清理定时器 */
  timer: NodeJS.Timeout;
}

/**
 * 黑名单条目
 */
interface BlacklistItem {
  /** 解封时间戳（毫秒） */
  expireAt: number;
  /** 清理定时器 */
  timer: NodeJS.Timeout;
}

/**
 * 基于内存的 Session 存储实现
 * 使用 Map 作为底层存储，支持 TTL 自动清理和 LRU 淘汰
 * 同时内置内存黑名单，无需 Redis 也能使用 banUser / isBanned
 */
export class MemoryStore implements SessionStore, BlacklistStore {
  private readonly store = new Map<string, StoreItem>();
  /** LRU 顺序表，最近访问的 key 在末尾 */
  private readonly lru = new Map<string, true>();
  private readonly maxSize: number;
  /** userId -> 黑名单条目 */
  private readonly blacklist = new Map<string, BlacklistItem>();

  /**
   * @param options - 内存存储配置选项
   */
  constructor(options: MemoryStoreOptions = {}) {
    this.maxSize = options.maxSize && options.maxSize > 0 ? options.maxSize : 0;
  }

  /**
   * 存储会话数据
   * @param sessionId - 会话唯一标识
   * @param data - 会话数据
   * @param ttl - 过期时间（毫秒）
   */
  set(sessionId: string, data: SessionData, ttl?: number): Promise<void> {
    // 如果已存在，先清除旧的定时器
    const existing = this.store.get(sessionId);
    if (existing) {
      clearTimeout(existing.timer);
    }

    const expireAt = ttl ? Date.now() + ttl : Number.MAX_SAFE_INTEGER;

    const timer = this.scheduleExpiry(() => {
      this.internalDelete(sessionId);
    }, expireAt);

    this.store.set(sessionId, { data, expireAt, timer });
    this.touchLru(sessionId);

    // 触发 LRU 淘汰
    this.evictIfNeeded();
    return Promise.resolve();
  }

  /**
   * 获取会话数据
   * @param sessionId - 会话唯一标识
   * @returns 会话数据，不存在或已过期则返回 null
   */
  get(sessionId: string): Promise<SessionData | null> {
    const item = this.store.get(sessionId);
    if (!item) {
      return Promise.resolve(null);
    }

    // 检查是否已过期（兜底清理）
    if (Date.now() > item.expireAt) {
      this.internalDelete(sessionId);
      return Promise.resolve(null);
    }

    this.touchLru(sessionId);
    return Promise.resolve(item.data);
  }

  /**
   * 删除指定会话
   * @param sessionId - 会话唯一标识
   */
  delete(sessionId: string): Promise<void> {
    this.internalDelete(sessionId);
    return Promise.resolve();
  }

  /**
   * 根据用户 ID 删除所有会话
   * @param userId - 用户 ID
   */
  deleteByUserId(userId: string): Promise<void> {
    for (const [sessionId, item] of this.store.entries()) {
      if (item.data.userId === userId) {
        this.internalDelete(sessionId);
      }
    }
    return Promise.resolve();
  }

  /**
   * 查询用户的所有在线会话
   * @param userId - 用户 ID
   * @returns 会话数据数组
   */
  listByUserId(userId: string): Promise<SessionData[]> {
    const sessions: SessionData[] = [];
    for (const item of this.store.values()) {
      if (item.data.userId === userId) {
        sessions.push(item.data);
      }
    }
    return Promise.resolve(sessions);
  }

  /**
   * 根据设备标识查询所有会话 ID
   * @param device - 设备标识
   * @returns 会话 ID 数组
   */
  listByDevice(device: string): Promise<string[]> {
    const sessionIds: string[] = [];
    for (const [sessionId, item] of this.store.entries()) {
      if (item.data.device === device) {
        sessionIds.push(sessionId);
      }
    }
    return Promise.resolve(sessionIds);
  }

  /**
   * 根据用户 ID 和设备标识查询会话 ID 列表
   * 按会话创建时间升序排列（最旧的在前），用于同端登录数量控制
   * @param userId - 用户 ID
   * @param device - 设备标识
   * @returns 会话 ID 数组
   */
  listByUserIdAndDevice(userId: string, device: string): Promise<string[]> {
    const sessions: { sessionId: string; createTime: number }[] = [];

    for (const [sessionId, item] of this.store.entries()) {
      const data = item.data;
      if (data.userId === userId && data.device === device) {
        sessions.push({ sessionId, createTime: data.createTime || 0 });
      }
    }

    sessions.sort((a, b) => a.createTime - b.createTime);
    return Promise.resolve(sessions.map((s) => s.sessionId));
  }

  /**
   * 刷新会话过期时间（滑动续签）
   * @param sessionId - 会话唯一标识
   * @param ttl - 新的过期时间（毫秒）
   */
  renew(sessionId: string, ttl?: number): Promise<void> {
    const item = this.store.get(sessionId);
    if (!item) {
      return Promise.resolve();
    }

    // 清除旧定时器
    clearTimeout(item.timer);

    const expireAt = ttl ? Date.now() + ttl : Number.MAX_SAFE_INTEGER;

    const timer = this.scheduleExpiry(() => {
      this.internalDelete(sessionId);
    }, expireAt);

    this.store.set(sessionId, { ...item, expireAt, timer });
    this.touchLru(sessionId);
    return Promise.resolve();
  }

  /**
   * 清空所有会话数据
   */
  clear(): Promise<void> {
    for (const [, item] of this.store.entries()) {
      clearTimeout(item.timer);
    }
    for (const item of this.blacklist.values()) {
      clearTimeout(item.timer);
    }
    this.store.clear();
    this.lru.clear();
    this.blacklist.clear();
    return Promise.resolve();
  }

  /**
   * 获取当前存储的会话数量
   * @returns 会话数量
   */
  get size(): number {
    return this.store.size;
  }

  /**
   * 封禁用户（内存实现）
   * @param userId - 用户 ID
   * @param duration - 封禁时长（秒）
   */
  ban(userId: string, duration: number): Promise<void> {
    // 若已存在，先清理旧定时器
    const existing = this.blacklist.get(userId);
    if (existing) {
      clearTimeout(existing.timer);
    }

    const expireAt = Date.now() + duration * 1000;
    const timer = this.scheduleExpiry(() => {
      this.blacklist.delete(userId);
    }, expireAt);

    this.blacklist.set(userId, { expireAt, timer });
    return Promise.resolve();
  }

  /**
   * 解除封禁用户
   * @param userId - 用户 ID
   */
  unban(userId: string): Promise<void> {
    const existing = this.blacklist.get(userId);
    if (existing) {
      clearTimeout(existing.timer);
      this.blacklist.delete(userId);
    }
    return Promise.resolve();
  }

  /**
   * 检查用户是否被封禁
   * @param userId - 用户 ID
   * @returns 是否被封禁
   */
  isBanned(userId: string): Promise<boolean> {
    const item = this.blacklist.get(userId);
    if (!item) {
      return Promise.resolve(false);
    }

    // 兜底：即使定时器未触发，也检查是否已过期
    if (Date.now() > item.expireAt) {
      this.blacklist.delete(userId);
      return Promise.resolve(false);
    }

    return Promise.resolve(true);
  }

  /**
   * 调度过期清理任务
   * 当过期时间超过 setTimeout 最大值时，分段调度避免溢出
   * @param callback - 过期时执行的回调
   * @param expireAt - 过期时间戳（毫秒）
   * @returns 定时器句柄
   */
  private scheduleExpiry(
    callback: () => void,
    expireAt: number,
  ): NodeJS.Timeout {
    const remaining = expireAt - Date.now();
    const delay =
      remaining > MAX_TIMEOUT_MS ? MAX_TIMEOUT_MS : Math.max(0, remaining);

    const timer = setTimeout(() => {
      if (Date.now() >= expireAt) {
        callback();
      } else {
        this.scheduleExpiry(callback, expireAt);
      }
    }, delay);
    timer.unref();
    return timer;
  }

  /**
   * 内部删除，同时清理定时器和 LRU 记录
   * @param sessionId - 会话唯一标识
   */
  private internalDelete(sessionId: string): void {
    const item = this.store.get(sessionId);
    if (item) {
      clearTimeout(item.timer);
      this.store.delete(sessionId);
    }
    this.lru.delete(sessionId);
  }

  /**
   * 更新 key 在 LRU 顺序表中的位置（移至末尾）
   * @param sessionId - 会话唯一标识
   */
  private touchLru(sessionId: string): void {
    this.lru.delete(sessionId);
    this.lru.set(sessionId, true);
  }

  /**
   * 如果超出最大容量，淘汰最久未访问的会话
   */
  private evictIfNeeded(): void {
    if (this.maxSize <= 0 || this.store.size <= this.maxSize) {
      return;
    }

    // 找到并淘汰最久未访问的 key（Map 中第一个 key）
    const iterator = this.lru.keys();
    const first = iterator.next();
    if (!first.done && first.value) {
      this.internalDelete(first.value);
    }
  }
}
