import type { RateLimitContext, RateLimiter } from './rate-limit.interface';

/**
 * 内存滑动窗口限流器
 * 基于每个 key 的时间戳队列实现，自动清理过期记录
 */
export class MemoryRateLimiter implements RateLimiter {
  /** key -> 请求时间戳队列 */
  private readonly records = new Map<string, number[]>();

  /**
   * @param windowSeconds - 时间窗口大小（秒）
   * @param maxRequests - 窗口内最大请求次数
   */
  constructor(
    private readonly windowSeconds: number,
    private readonly maxRequests: number,
  ) {}

  /**
   * 检查当前请求是否允许通过
   * @param context - 限流上下文
   * @returns true 表示允许通过
   */
  // eslint-disable-next-line @typescript-eslint/require-await
  async allow(context: RateLimitContext): Promise<boolean> {
    const key = this.buildKey(context);
    const now = Date.now();
    const windowStart = now - this.windowSeconds * 1000;

    let timestamps = this.records.get(key) || [];
    // 过滤掉窗口外的旧记录
    timestamps = timestamps.filter((ts) => ts > windowStart);

    if (timestamps.length >= this.maxRequests) {
      this.records.set(key, timestamps);
      return false;
    }

    timestamps.push(now);
    this.records.set(key, timestamps);
    return true;
  }

  /**
   * 清空所有限流记录
   */
  // eslint-disable-next-line @typescript-eslint/require-await
  async clear(): Promise<void> {
    this.records.clear();
  }

  /**
   * 构建限流 key
   * @param context - 限流上下文
   * @returns key 字符串
   */
  private buildKey(context: RateLimitContext): string {
    const parts = [context.action];
    if (context.userId) {
      parts.push(context.userId);
    }
    parts.push(context.ip);
    return parts.join(':');
  }
}
