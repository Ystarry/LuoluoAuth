import { readFile, unlink } from 'fs/promises';
import { join } from 'path';
import { AuditService, AuditLog } from './audit.service';

describe('AuditService', () => {
  let consoleSpy: jest.SpyInstance;

  beforeEach(() => {
    consoleSpy = jest.spyOn(console, 'log').mockImplementation(() => undefined);
  });

  afterEach(() => {
    consoleSpy.mockRestore();
  });

  describe('disabled', () => {
    it('should not log when disabled', async () => {
      const service = new AuditService({ enabled: false }, undefined);
      await service.log({ userId: 'u1', action: 'login', timestamp: 1 });
      expect(consoleSpy).not.toHaveBeenCalled();
    });

    it('should return empty login history when disabled', async () => {
      const service = new AuditService({ enabled: false }, undefined);
      const history = await service.getLoginHistory('u1');
      expect(history).toEqual([]);
    });
  });

  describe('console storage', () => {
    it('should log to console', async () => {
      const service = new AuditService(
        { enabled: true, storage: 'console' },
        undefined,
      );
      const log: AuditLog = {
        userId: 'u1',
        action: 'login',
        timestamp: 1000,
        device: 'web',
      };

      await service.log(log);

      expect(consoleSpy).toHaveBeenCalledWith(`[AUDIT] ${JSON.stringify(log)}`);
    });

    it('should return empty login history for console storage', async () => {
      const service = new AuditService(
        { enabled: true, storage: 'console' },
        undefined,
      );
      await service.log({ userId: 'u1', action: 'login', timestamp: 1 });
      const history = await service.getLoginHistory('u1');
      expect(history).toEqual([]);
    });
  });

  describe('file storage', () => {
    let logFilePath: string;

    beforeEach(() => {
      logFilePath = join('/tmp', `audit-test-${Date.now()}.log`);
    });

    afterEach(async () => {
      try {
        await unlink(logFilePath);
      } catch {
        // ignore
      }
    });

    it('should write logs to file', async () => {
      const service = new AuditService(
        { enabled: true, storage: 'file', logFilePath },
        undefined,
      );
      const log: AuditLog = {
        userId: 'u1',
        action: 'login',
        timestamp: 1000,
      };

      await service.log(log);

      const content = await readFile(logFilePath, 'utf-8');
      expect(content.trim()).toBe(JSON.stringify(log));
    });

    it('should return login history from file sorted by time desc', async () => {
      const service = new AuditService(
        { enabled: true, storage: 'file', logFilePath },
        undefined,
      );

      await service.logBatch([
        { userId: 'u1', action: 'login', timestamp: 100 },
        { userId: 'u1', action: 'logout', timestamp: 200 },
        { userId: 'u1', action: 'login', timestamp: 300 },
        { userId: 'u2', action: 'login', timestamp: 400 },
      ] as AuditLog[]);

      const history = await service.getLoginHistory('u1', 10);

      expect(history).toHaveLength(2);
      expect(history[0].timestamp).toBe(300);
      expect(history[1].timestamp).toBe(100);
    });

    it('should respect limit when returning login history', async () => {
      const service = new AuditService(
        { enabled: true, storage: 'file', logFilePath },
        undefined,
      );

      await service.logBatch([
        { userId: 'u1', action: 'login', timestamp: 100 },
        { userId: 'u1', action: 'login', timestamp: 200 },
        { userId: 'u1', action: 'login', timestamp: 300 },
      ] as AuditLog[]);

      const history = await service.getLoginHistory('u1', 2);

      expect(history).toHaveLength(2);
      expect(history[0].timestamp).toBe(300);
      expect(history[1].timestamp).toBe(200);
    });

    it('should return empty history when file does not exist', async () => {
      const service = new AuditService(
        { enabled: true, storage: 'file', logFilePath },
        undefined,
      );

      const history = await service.getLoginHistory('u1');
      expect(history).toEqual([]);
    });
  });

  describe('redis storage', () => {
    const createMockRedis = () => ({
      lpush: jest.fn().mockResolvedValue(1),
      ltrim: jest.fn().mockResolvedValue('OK'),
      lrange: jest.fn().mockResolvedValue([]),
    });

    it('should write login log to redis list', async () => {
      const mockRedis = createMockRedis();
      const service = new AuditService(
        { enabled: true, storage: 'redis' },
        mockRedis as unknown as import('ioredis').default,
      );

      await service.log({ userId: 'u1', action: 'login', timestamp: 1000 });

      expect(mockRedis.lpush).toHaveBeenCalledWith(
        'auth:audit:u1',
        expect.any(String),
      );
      expect(mockRedis.ltrim).toHaveBeenCalledWith('auth:audit:u1', 0, 999);
    });

    it('should return login history from redis', async () => {
      const mockRedis = createMockRedis();
      mockRedis.lrange.mockResolvedValue([
        JSON.stringify({ userId: 'u1', action: 'login', timestamp: 200 }),
        JSON.stringify({ userId: 'u1', action: 'logout', timestamp: 150 }),
        JSON.stringify({ userId: 'u1', action: 'login', timestamp: 100 }),
      ]);

      const service = new AuditService(
        { enabled: true, storage: 'redis' },
        mockRedis as unknown as import('ioredis').default,
      );

      const history = await service.getLoginHistory('u1', 10);

      expect(history).toHaveLength(2);
      expect(history[0].timestamp).toBe(200);
      expect(history[1].timestamp).toBe(100);
      expect(mockRedis.lrange).toHaveBeenCalledWith('auth:audit:u1', 0, 9);
    });

    it('should return empty history when redis is unavailable', async () => {
      const service = new AuditService(
        { enabled: true, storage: 'redis' },
        undefined,
      );

      const history = await service.getLoginHistory('u1');
      expect(history).toEqual([]);
    });
  });
});
