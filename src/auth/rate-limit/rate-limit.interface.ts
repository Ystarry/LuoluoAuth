/**
 * 限流检查上下文
 */
export interface RateLimitContext {
  /** 客户端 IP */
  ip: string;
  /** 用户 ID（可选） */
  userId?: string;
  /** 动作类型，如 login / refresh / password 等 */
  action: string;
}

/**
 * 限流器接口
 * 支持滑动窗口和令牌桶两种策略
 */
export interface RateLimiter {
  /**
   * 检查当前请求是否允许通过
   * @param context - 限流上下文
   * @returns true 表示允许通过，false 表示被限流
   */
  allow(context: RateLimitContext): Promise<boolean>;

  /**
   * 清空限流记录（主要用于测试）
   */
  clear?(): Promise<void>;
}

/**
 * 限流配置
 */
export interface RateLimitRule {
  /** 时间窗口大小（秒） */
  windowSeconds: number;
  /** 窗口内最大请求次数 */
  maxRequests: number;
}
