import { RedisLifecycleService } from './redis-lifecycle.service';

describe('RedisLifecycleService', () => {
  it('should call quit on module destroy when redis client exists', async () => {
    const quit = jest.fn().mockResolvedValue(undefined);
    const redis = { quit } as unknown as import('ioredis').default;

    const service = new RedisLifecycleService(redis);
    await service.onModuleDestroy();

    expect(quit).toHaveBeenCalled();
  });

  it('should do nothing when redis client is missing', async () => {
    const service = new RedisLifecycleService(undefined);
    await expect(service.onModuleDestroy()).resolves.toBeUndefined();
  });

  it('should do nothing when redis client does not have quit method', async () => {
    const service = new RedisLifecycleService({} as import('ioredis').default);
    await expect(service.onModuleDestroy()).resolves.toBeUndefined();
  });
});
