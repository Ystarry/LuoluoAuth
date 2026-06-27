import Redis from 'ioredis';
import {
  BlacklistStore,
  SessionData,
  SessionStore,
} from '../interfaces/session-store.interface';

/**
 * Redis Session 存储实现
 * 使用 ioredis 作为底层存储，支持 TTL 和 userId 索引
 *
 * Key 设计：
 * - 会话数据：auth:sessions:{sessionId}
 * - 用户索引：auth:user-sessions:{userId}（Set 集合，存储该用户所有 sessionId）
 */
export class RedisStore implements SessionStore, BlacklistStore {
  /** Redis key 前缀 */
  private readonly prefix = 'auth:sessions';
  /** 用户索引 key 前缀 */
  private readonly userIndexPrefix = 'auth:user-sessions';
  /** 设备索引 key 前缀 */
  private readonly deviceIndexPrefix = 'auth:device-sessions';
  /** 黑名单 key 前缀 */
  private readonly blacklistPrefix = 'auth:blacklist';

  /**
   * @param redis - ioredis 连接实例
   */
  constructor(private readonly redis: Redis) {}

  /**
   * 生成完整的 Redis key
   * @param sessionId - 会话 ID
   * @returns 完整的 key 字符串
   */
  private getKey(sessionId: string): string {
    return `${this.prefix}:${sessionId}`;
  }

  /**
   * 生成用户索引的 Redis key
   * @param userId - 用户 ID
   * @returns 完整的索引 key 字符串
   */
  private getUserIndexKey(userId: string): string {
    return `${this.userIndexPrefix}:${userId}`;
  }

  /**
   * 生成设备索引的 Redis key
   * @param device - 设备标识
   * @returns 完整的索引 key 字符串
   */
  private getDeviceIndexKey(device: string): string {
    return `${this.deviceIndexPrefix}:${device}`;
  }

  /**
   * 存储会话数据
   * 同时维护 userId -> sessionIds 的索引关系
   * @param sessionId - 会话唯一标识
   * @param data - 会话数据
   * @param ttl - 过期时间（毫秒）
   */
  async set(sessionId: string, data: SessionData, ttl?: number): Promise<void> {
    const key = this.getKey(sessionId);
    const userIndexKey = this.getUserIndexKey(data.userId);
    const deviceIndexKey = data.device
      ? this.getDeviceIndexKey(data.device)
      : undefined;
    const value = JSON.stringify(data);

    const ttlSeconds = ttl ? Math.ceil(ttl / 1000) : undefined;

    const pipeline = this.redis.pipeline();
    if (ttlSeconds) {
      pipeline.set(key, value, 'EX', ttlSeconds);
      pipeline.sadd(userIndexKey, sessionId);
      // 为索引也设置过期时间（稍长于 session TTL，用于兜底清理）
      pipeline.expire(userIndexKey, ttlSeconds + 60);
      if (deviceIndexKey) {
        pipeline.sadd(deviceIndexKey, sessionId);
        pipeline.expire(deviceIndexKey, ttlSeconds + 60);
      }
    } else {
      pipeline.set(key, value);
      pipeline.sadd(userIndexKey, sessionId);
      if (deviceIndexKey) {
        pipeline.sadd(deviceIndexKey, sessionId);
      }
    }
    await pipeline.exec();
  }

  /**
   * 获取会话数据
   * @param sessionId - 会话唯一标识
   * @returns 会话数据，不存在则返回 null
   */
  async get(sessionId: string): Promise<SessionData | null> {
    const key = this.getKey(sessionId);
    const value = await this.redis.get(key);

    if (!value) {
      return null;
    }

    return JSON.parse(value) as SessionData;
  }

  /**
   * 删除指定会话
   * 同时从用户索引中移除
   * @param sessionId - 会话唯一标识
   */
  async delete(sessionId: string): Promise<void> {
    const key = this.getKey(sessionId);

    // 先获取 userId / device 以清理索引
    const value = await this.redis.get(key);
    if (value) {
      const data = JSON.parse(value) as SessionData;
      const userIndexKey = this.getUserIndexKey(data.userId);
      const deviceIndexKey = data.device
        ? this.getDeviceIndexKey(data.device)
        : undefined;

      const pipeline = this.redis.pipeline();
      pipeline.del(key);
      pipeline.srem(userIndexKey, sessionId);
      if (deviceIndexKey) {
        pipeline.srem(deviceIndexKey, sessionId);
      }
      await pipeline.exec();
    } else {
      await this.redis.del(key);
    }
  }

  /**
   * 根据用户 ID 删除所有会话
   * 通过索引集合批量删除
   * @param userId - 用户 ID
   */
  async deleteByUserId(userId: string): Promise<void> {
    const userIndexKey = this.getUserIndexKey(userId);
    const sessionIds = await this.redis.smembers(userIndexKey);

    if (sessionIds.length === 0) {
      return;
    }

    const deviceIndexKeys = new Set<string>();
    const pipeline = this.redis.pipeline();

    // 批量获取会话数据以清理设备索引
    for (const sessionId of sessionIds) {
      pipeline.get(this.getKey(sessionId));
    }
    const results = await pipeline.exec();

    if (results) {
      for (let i = 0; i < sessionIds.length; i++) {
        const result = results[i];
        if (result && result[1]) {
          const data = JSON.parse(result[1] as string) as SessionData;
          if (data.device) {
            deviceIndexKeys.add(this.getDeviceIndexKey(data.device));
          }
        }
      }
    }

    const deletePipeline = this.redis.pipeline();

    // 删除所有会话数据
    for (const sessionId of sessionIds) {
      deletePipeline.del(this.getKey(sessionId));
    }

    // 删除索引集合
    deletePipeline.del(userIndexKey);
    for (const deviceIndexKey of deviceIndexKeys) {
      for (const sessionId of sessionIds) {
        deletePipeline.srem(deviceIndexKey, sessionId);
      }
    }

    await deletePipeline.exec();
  }

  /**
   * 根据用户 ID 和设备标识删除会话
   * 用于 mutual-exclusion 登录策略
   * 同时清理已过期但索引中残留的僵尸 sessionId
   * @param userId - 用户 ID
   * @param device - 设备标识
   */
  async deleteByUserIdAndDevice(userId: string, device: string): Promise<void> {
    const userIndexKey = this.getUserIndexKey(userId);
    const sessionIds = await this.redis.smembers(userIndexKey);

    if (sessionIds.length === 0) {
      return;
    }

    const pipeline = this.redis.pipeline();

    // 批量获取会话数据以筛选设备
    for (const sessionId of sessionIds) {
      pipeline.get(this.getKey(sessionId));
    }

    const results = await pipeline.exec();

    if (!results) {
      return;
    }

    const deviceIndexKey = this.getDeviceIndexKey(device);
    const deletePipeline = this.redis.pipeline();

    for (let i = 0; i < sessionIds.length; i++) {
      const result = results[i];
      if (result && result[1]) {
        const data = JSON.parse(result[1] as string) as SessionData;
        if (data.device === device) {
          deletePipeline.del(this.getKey(sessionIds[i]));
          deletePipeline.srem(userIndexKey, sessionIds[i]);
          deletePipeline.srem(deviceIndexKey, sessionIds[i]);
        }
      } else {
        // Session 已过期（TTL 自动清理），但索引中仍残留 → 清理僵尸索引
        deletePipeline.srem(userIndexKey, sessionIds[i]);
        deletePipeline.srem(deviceIndexKey, sessionIds[i]);
      }
    }

    await deletePipeline.exec();
  }

  /**
   * 查询用户的所有在线会话
   * @param userId - 用户 ID
   * @returns 会话数据数组
   */
  async listByUserId(userId: string): Promise<SessionData[]> {
    const userIndexKey = this.getUserIndexKey(userId);
    const sessionIds = await this.redis.smembers(userIndexKey);

    if (sessionIds.length === 0) {
      return [];
    }

    const pipeline = this.redis.pipeline();
    for (const sessionId of sessionIds) {
      pipeline.get(this.getKey(sessionId));
    }

    const results = await pipeline.exec();
    const sessions: SessionData[] = [];

    if (results) {
      for (let i = 0; i < sessionIds.length; i++) {
        const result = results[i];
        if (result && result[1]) {
          sessions.push(JSON.parse(result[1] as string) as SessionData);
        }
      }
    }

    return sessions;
  }

  /**
   * 根据设备标识查询所有会话 ID
   * @param device - 设备标识
   * @returns 会话 ID 数组
   */
  async listByDevice(device: string): Promise<string[]> {
    const deviceIndexKey = this.getDeviceIndexKey(device);
    return this.redis.smembers(deviceIndexKey);
  }

  /**
   * 根据用户 ID 和设备标识查询会话 ID 列表
   * 按会话创建时间升序排列（最旧的在前），用于同端登录数量控制
   * @param userId - 用户 ID
   * @param device - 设备标识
   * @returns 会话 ID 数组
   */
  async listByUserIdAndDevice(
    userId: string,
    device: string,
  ): Promise<string[]> {
    const userIndexKey = this.getUserIndexKey(userId);
    const sessionIds = await this.redis.smembers(userIndexKey);

    if (sessionIds.length === 0) {
      return [];
    }

    const pipeline = this.redis.pipeline();
    for (const sessionId of sessionIds) {
      pipeline.get(this.getKey(sessionId));
    }

    const results = await pipeline.exec();
    const sessions: { sessionId: string; createTime: number }[] = [];

    if (results) {
      for (let i = 0; i < sessionIds.length; i++) {
        const result = results[i];
        if (result && result[1]) {
          const data = JSON.parse(result[1] as string) as SessionData;
          if (data.device === device) {
            sessions.push({
              sessionId: sessionIds[i],
              createTime: data.createTime || 0,
            });
          }
        }
      }
    }

    sessions.sort((a, b) => a.createTime - b.createTime);
    return sessions.map((s) => s.sessionId);
  }

  /**
   * 刷新会话过期时间（滑动续签）
   * @param sessionId - 会话唯一标识
   * @param ttl - 新的过期时间（毫秒）
   */
  async renew(sessionId: string, ttl?: number): Promise<void> {
    const key = this.getKey(sessionId);
    const ttlSeconds = ttl ? Math.ceil(ttl / 1000) : undefined;

    if (ttlSeconds) {
      await this.redis.expire(key, ttlSeconds);
    }
  }

  /**
   * 生成黑名单的 Redis key
   * @param userId - 用户 ID
   * @returns 完整的黑名单 key 字符串
   */
  private getBlacklistKey(userId: string): string {
    return `${this.blacklistPrefix}:${userId}`;
  }

  /**
   * 封禁用户（Redis 实现）
   * @param userId - 用户 ID
   * @param duration - 封禁时长（秒）
   */
  async ban(userId: string, duration: number): Promise<void> {
    const key = this.getBlacklistKey(userId);
    await this.redis.set(key, '1', 'EX', duration);
  }

  /**
   * 解除封禁用户
   * @param userId - 用户 ID
   */
  async unban(userId: string): Promise<void> {
    const key = this.getBlacklistKey(userId);
    await this.redis.del(key);
  }

  /**
   * 检查用户是否被封禁
   * @param userId - 用户 ID
   * @returns 是否被封禁
   */
  async isBanned(userId: string): Promise<boolean> {
    const key = this.getBlacklistKey(userId);
    const result = await this.redis.get(key);
    return result !== null;
  }
}
