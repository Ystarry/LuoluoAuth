import { Inject, Injectable, OnModuleDestroy, Optional } from '@nestjs/common';
import type Redis from 'ioredis';

/**
 * Redis 连接生命周期管理
 * 在模块销毁时安全关闭由本模块创建的 Redis 连接
 */
@Injectable()
export class RedisLifecycleService implements OnModuleDestroy {
  constructor(
    @Inject('REDIS_CLIENT')
    @Optional()
    private readonly redis?: Redis,
  ) {}

  /**
   * 应用关闭时优雅关闭 Redis 连接
   */
  async onModuleDestroy(): Promise<void> {
    if (this.redis && typeof this.redis.quit === 'function') {
      await this.redis.quit();
    }
  }
}
