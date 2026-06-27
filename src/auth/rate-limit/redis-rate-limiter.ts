import type Redis from 'ioredis';
import type { RateLimitContext, RateLimiter } from './rate-limit.interface';

/**
 * Redis 滑动窗口限流器
 * 使用 Redis sorted set 存储请求时间戳，利用 TTL 自动清理过期 key
 */
export class RedisRateLimiter implements RateLimiter {
  /** Redis key 前缀 */
  private readonly prefix = 'auth:rate-limit';

  /**
   * @param redis - ioredis 连接实例
   * @param windowSeconds - 时间窗口大小（秒）
   * @param maxRequests - 窗口内最大请求次数
   */
  constructor(
    private readonly redis: Redis,
    private readonly windowSeconds: number,
    private readonly maxRequests: number,
  ) {}

  /**
   * 检查当前请求是否允许通过
   * 使用 Lua 脚本保证计数和清理的原子性
   * @param context - 限流上下文
   * @returns true 表示允许通过
   */
  async allow(context: RateLimitContext): Promise<boolean> {
    const key = this.buildKey(context);
    const now = Date.now();
    const windowStart = now - this.windowSeconds * 1000;

    const luaScript = `
      local key = KEYS[1]
      local now = tonumber(ARGV[1])
      local windowStart = tonumber(ARGV[2])
      local maxRequests = tonumber(ARGV[3])
      local windowSeconds = tonumber(ARGV[4])

      -- 移除窗口外的旧记录
      redis.call('zremrangebyscore', key, '-inf', windowStart)

      -- 统计当前窗口内请求数
      local current = redis.call('zcard', key)
      if current >= maxRequests then
        -- 刷新 TTL，避免 key 永久残留
        redis.call('expire', key, windowSeconds)
        return 0
      end

      -- 记录本次请求时间戳
      redis.call('zadd', key, now, now)
      redis.call('expire', key, windowSeconds)
      return 1
    `;

    const result = (await this.redis.eval(
      luaScript,
      1,
      key,
      now,
      windowStart,
      this.maxRequests,
      this.windowSeconds,
    )) as number;

    return result === 1;
  }

  /**
   * 清空所有限流记录（通过扫描前缀删除）
   */
  async clear(): Promise<void> {
    const pattern = `${this.prefix}:*`;
    let cursor = '0';

    do {
      const [nextCursor, keys] = await this.redis.scan(
        cursor,
        'MATCH',
        pattern,
        'COUNT',
        100,
      );
      if (keys.length > 0) {
        await this.redis.del(...keys);
      }
      cursor = nextCursor;
    } while (cursor !== '0');
  }

  /**
   * 构建限流 key
   * @param context - 限流上下文
   * @returns key 字符串
   */
  private buildKey(context: RateLimitContext): string {
    const parts = [this.prefix, context.action];
    if (context.userId) {
      parts.push(context.userId);
    }
    parts.push(context.ip);
    return parts.join(':');
  }
}
