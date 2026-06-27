import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { MemoryStore } from './stores/memory-store';
import { JwtStrategy } from './strategies/jwt.strategy';
import { AuthException } from './errors/auth.exception';
import { AuthErrorCode } from './errors/auth-error-code';
import { RandomTokenStrategy } from './strategies/random-token.strategy';
import { AuditLog } from './audit/audit.service';

describe('AuthService', () => {
  let service: AuthService;
  let store: MemoryStore;
  let tokenStrategy: JwtStrategy;

  beforeEach(async () => {
    store = new MemoryStore();
    tokenStrategy = new JwtStrategy({
      secret: 'test-secret',
      expiresIn: '1h',
    });

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        {
          provide: 'SESSION_STORE',
          useValue: store,
        },
        {
          provide: 'TOKEN_STRATEGY',
          useValue: tokenStrategy,
        },
        {
          provide: 'AUTH_CONFIG',
          useValue: {
            tokenTtl: 3600000,
            loginPolicy: 'multiple',
            safeAuthTtl: 1800000,
          },
        },
        {
          provide: 'REDIS_CLIENT',
          useValue: undefined,
        },
        {
          provide: 'AUDIT_CONFIG',
          useValue: { enabled: false },
        },
        AuthService,
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  afterEach(async () => {
    await store.clear();
  });

  describe('login', () => {
    it('should generate token and store session', async () => {
      const token = await service.login(
        'user-1',
        'device-1',
        ['user'],
        ['user:add'],
      );

      expect(typeof token).toBe('string');
      expect(token.length).toBeGreaterThan(0);

      const session = await service.validateToken(token);
      expect(session.userId).toBe('user-1');
      expect(session.device).toBe('device-1');
      expect(session.roles).toEqual(['user']);
      expect(session.permissions).toEqual(['user:add']);
    });

    it('should delete old sessions with single policy', async () => {
      const singleService = new AuthService(
        store,
        tokenStrategy,
        {
          tokenTtl: 3600000,
          loginPolicy: 'single',
        },
        undefined,
        undefined,
      );

      const token1 = await singleService.login('user-1');
      const token2 = await singleService.login('user-1');

      // token1 session should be deleted
      await expect(singleService.validateToken(token1)).rejects.toThrow(
        AuthException,
      );

      // token2 should still be valid
      const session = await singleService.validateToken(token2);
      expect(session.userId).toBe('user-1');
    });
  });

  describe('mutual-exclusion policy', () => {
    it('should keep only the newest session when maxSameDeviceSessions is 1', async () => {
      const exclusionService = new AuthService(
        store,
        tokenStrategy,
        {
          tokenTtl: 3600000,
          loginPolicy: 'mutual-exclusion',
        },
        undefined,
        undefined,
      );

      const token1 = await exclusionService.login('user-1', 'web');
      const token2 = await exclusionService.login('user-1', 'web');

      await expect(exclusionService.validateToken(token1)).rejects.toThrow(
        AuthException,
      );
      await expect(exclusionService.validateToken(token2)).resolves.toEqual(
        expect.objectContaining({ userId: 'user-1', device: 'web' }),
      );
    });

    it('should allow up to N sessions on the same device', async () => {
      const exclusionService = new AuthService(
        store,
        tokenStrategy,
        {
          tokenTtl: 3600000,
          loginPolicy: 'mutual-exclusion',
          maxSameDeviceSessions: 2,
        },
        undefined,
        undefined,
      );

      const token1 = await exclusionService.login('user-1', 'web');
      // ensure distinct createTime
      await new Promise((resolve) => setTimeout(resolve, 5));
      const token2 = await exclusionService.login('user-1', 'web');
      await new Promise((resolve) => setTimeout(resolve, 5));
      const token3 = await exclusionService.login('user-1', 'web');

      // oldest session should be evicted
      await expect(exclusionService.validateToken(token1)).rejects.toThrow(
        AuthException,
      );
      await expect(exclusionService.validateToken(token2)).resolves.toEqual(
        expect.objectContaining({ userId: 'user-1', device: 'web' }),
      );
      await expect(exclusionService.validateToken(token3)).resolves.toEqual(
        expect.objectContaining({ userId: 'user-1', device: 'web' }),
      );
    });

    it('should not affect sessions from other devices', async () => {
      const exclusionService = new AuthService(
        store,
        tokenStrategy,
        {
          tokenTtl: 3600000,
          loginPolicy: 'mutual-exclusion',
          maxSameDeviceSessions: 1,
        },
        undefined,
        undefined,
      );

      const webToken = await exclusionService.login('user-1', 'web');
      const mobileToken = await exclusionService.login('user-1', 'mobile');

      await expect(exclusionService.validateToken(webToken)).resolves.toEqual(
        expect.objectContaining({ userId: 'user-1', device: 'web' }),
      );
      await expect(
        exclusionService.validateToken(mobileToken),
      ).resolves.toEqual(
        expect.objectContaining({ userId: 'user-1', device: 'mobile' }),
      );
    });
  });

  describe('validateToken', () => {
    it('should return session for valid token', async () => {
      const token = await service.login('user-1');
      const session = await service.validateToken(token);

      expect(session.userId).toBe('user-1');
    });

    it('should throw for invalid token', async () => {
      await expect(service.validateToken('invalid-token')).rejects.toThrow();
    });
  });

  describe('logout', () => {
    it('should delete session on logout', async () => {
      const token = await service.login('user-1');
      await service.logout(token);

      await expect(service.validateToken(token)).rejects.toThrow(AuthException);
    });

    it('should not throw for invalid token', async () => {
      await expect(service.logout('invalid')).resolves.not.toThrow();
    });
  });

  describe('safeAuth', () => {
    it('should mark session as safe auth', async () => {
      const token = await service.login('user-1');
      const payload = tokenStrategy.verify(token);

      await service.openSafeAuth(payload.sessionId);

      const session = await service.validateToken(token);
      expect(service.isSafeAuth(session)).toBe(true);
      expect(session.safeAuth).toBe(true);
      expect(session.safeAuthTime).toBeDefined();
    });

    it('should expire safe auth after ttl', async () => {
      const shortService = new AuthService(
        store,
        tokenStrategy,
        {
          tokenTtl: 3600000,
          safeAuthTtl: 50,
        },
        undefined,
        undefined,
      );

      const token = await shortService.login('user-1');
      const payload = tokenStrategy.verify(token);

      await shortService.openSafeAuth(payload.sessionId);

      // Immediately after open
      const session = await shortService.validateToken(token);
      expect(shortService.isSafeAuth(session)).toBe(true);

      // Wait for TTL to expire
      await new Promise((resolve) => setTimeout(resolve, 100));
      expect(shortService.isSafeAuth(session)).toBe(false);
    });

    it('should remove safe auth on close', async () => {
      const token = await service.login('user-1');
      const payload = tokenStrategy.verify(token);

      await service.openSafeAuth(payload.sessionId);
      await service.closeSafeAuth(payload.sessionId);

      const session = await service.validateToken(token);
      expect(service.isSafeAuth(session)).toBe(false);
      expect(session.safeAuth).toBeUndefined();
    });
  });

  describe('switchIdentity', () => {
    it('should create token with original user info', async () => {
      const token = await service.switchIdentity('user-1', 'user-2');
      const session = await service.validateToken(token);

      expect(session.userId).toBe('user-2');
      expect(session.originalUserId).toBe('user-1');
      expect(session.switchTime).toBeDefined();
    });
  });

  describe('getConfig', () => {
    it('should return current config', () => {
      const config = service.getConfig();
      expect(config.tokenTtl).toBe(3600000);
      expect(config.loginPolicy).toBe('multiple');
    });
  });

  describe('session query', () => {
    it('should return all online sessions for a user', async () => {
      await service.login('user-1', 'web');
      await service.login('user-1', 'mobile');
      await service.login('user-2', 'web');

      const sessions = await service.getOnlineSessions('user-1');

      expect(sessions).toHaveLength(2);
      expect(sessions.map((s) => s.device).sort()).toEqual(['mobile', 'web']);
    });

    it('should return empty array when user has no online sessions', async () => {
      const sessions = await service.getOnlineSessions('unknown');
      expect(sessions).toEqual([]);
    });

    it('should return login history from audit service', async () => {
      const auditService = {
        log: jest.fn(),
        getLoginHistory: jest
          .fn()
          .mockResolvedValue([
            { userId: 'user-1', action: 'login', timestamp: 100 } as AuditLog,
          ]),
      };
      const queryService = new AuthService(
        store,
        tokenStrategy,
        { tokenTtl: 3600000, loginPolicy: 'multiple' },
        undefined,
        auditService as unknown as import('./audit/audit.service').AuditService,
      );

      const history = await queryService.getLoginHistory('user-1', 10);

      expect(history).toHaveLength(1);
      expect(auditService.getLoginHistory).toHaveBeenCalledWith('user-1', 10);
    });

    it('should return empty login history when audit service is absent', async () => {
      const history = await service.getLoginHistory('user-1');
      expect(history).toEqual([]);
    });
  });

  describe('blacklist', () => {
    it('should ban and check user via memory store', async () => {
      await service.banUser('user-1', 60);
      expect(await service.isBanned('user-1')).toBe(true);
      expect(await service.isBanned('user-2')).toBe(false);
    });

    it('should auto unban after duration expires', async () => {
      await service.banUser('user-1', 0);
      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(await service.isBanned('user-1')).toBe(false);
    });

    it('should unban user explicitly', async () => {
      await service.banUser('user-1', 60);
      expect(await service.isBanned('user-1')).toBe(true);

      await service.unbanUser('user-1');
      expect(await service.isBanned('user-1')).toBe(false);
    });

    it('should reject ban when store and redis both unavailable', async () => {
      const plainStore = {
        set: jest.fn(),
        get: jest.fn(),
        delete: jest.fn(),
        deleteByUserId: jest.fn(),
      };
      const noRedisService = new AuthService(
        plainStore,
        tokenStrategy,
        { tokenTtl: 3600000, loginPolicy: 'multiple' },
        undefined,
        undefined,
      );
      await expect(noRedisService.banUser('user-1', 60)).rejects.toThrow(
        'Either the session store must support blacklist operations',
      );
    });
  });

  describe('fingerprint', () => {
    it('should store ip and userAgent on login', async () => {
      const token = await service.login(
        'user-1',
        'device-1',
        undefined,
        undefined,
        '127.0.0.1',
        'test-ua',
      );
      const session = await service.validateToken(token);
      expect(session.ip).toBe('127.0.0.1');
      expect(session.userAgent).toBe('test-ua');
    });

    it('should pass validation when fingerprint matches', async () => {
      const token = await service.login(
        'user-1',
        undefined,
        undefined,
        undefined,
        '127.0.0.1',
        'test-ua',
      );
      const session = await service.validateToken(
        token,
        '127.0.0.1',
        'test-ua',
      );
      expect(session.userId).toBe('user-1');
    });

    it('should reject when fingerprint mismatches in strict mode', async () => {
      const strictService = new AuthService(
        store,
        tokenStrategy,
        {
          tokenTtl: 3600000,
          loginPolicy: 'multiple',
          fingerprint: { enabled: true, strict: true },
        },
        undefined,
        undefined,
      );
      const token = await strictService.login(
        'user-1',
        undefined,
        undefined,
        undefined,
        '127.0.0.1',
        'test-ua',
      );
      await expect(
        strictService.validateToken(token, '192.168.1.1', 'other-ua'),
      ).rejects.toThrow(AuthException);
    });

    it('should warn but allow when fingerprint mismatches in non-strict mode', async () => {
      const warnService = new AuthService(
        store,
        tokenStrategy,
        {
          tokenTtl: 3600000,
          loginPolicy: 'multiple',
          fingerprint: { enabled: true, strict: false },
        },
        undefined,
        undefined,
      );
      const token = await warnService.login(
        'user-1',
        undefined,
        undefined,
        undefined,
        '127.0.0.1',
        'test-ua',
      );
      const session = await warnService.validateToken(
        token,
        '192.168.1.1',
        'other-ua',
      );
      expect(session.userId).toBe('user-1');
    });

    it('should skip fingerprint check when disabled', async () => {
      const disabledService = new AuthService(
        store,
        tokenStrategy,
        {
          tokenTtl: 3600000,
          loginPolicy: 'multiple',
          fingerprint: { enabled: false },
        },
        undefined,
        undefined,
      );
      const token = await disabledService.login(
        'user-1',
        undefined,
        undefined,
        undefined,
        '127.0.0.1',
        'test-ua',
      );
      const session = await disabledService.validateToken(
        token,
        '192.168.1.1',
        'other-ua',
      );
      expect(session.userId).toBe('user-1');
    });

    it('should store fingerprint on switchIdentity', async () => {
      const token = await service.switchIdentity(
        'user-1',
        'user-2',
        'device-1',
        '127.0.0.1',
        'test-ua',
      );
      const session = await service.validateToken(token);
      expect(session.ip).toBe('127.0.0.1');
      expect(session.userAgent).toBe('test-ua');
      expect(session.originalUserId).toBe('user-1');
    });

    it('should reject Rpc token when fingerprint mismatches in strict mode', async () => {
      const strictService = new AuthService(
        store,
        tokenStrategy,
        {
          tokenTtl: 3600000,
          loginPolicy: 'multiple',
          fingerprint: { enabled: true, strict: true },
        },
        undefined,
        undefined,
      );
      const token = await strictService.login(
        'user-1',
        undefined,
        undefined,
        undefined,
        '127.0.0.1',
        'test-ua',
      );
      await expect(
        strictService.validateRpcToken(token, '192.168.1.1', 'other-ua'),
      ).rejects.toThrow(AuthException);
    });
  });

  describe('random token strategy', () => {
    it('should login and validate with random token', async () => {
      const randomStore = new MemoryStore();
      const randomStrategy = new RandomTokenStrategy(randomStore, {
        style: 'random-32',
      });
      const randomService = new AuthService(
        randomStore,
        randomStrategy,
        { tokenTtl: 3600000, loginPolicy: 'multiple' },
        undefined,
        undefined,
      );

      const token = await randomService.login('user-1', 'device-1');
      expect(token).toHaveLength(32);

      const session = await randomService.validateToken(token);
      expect(session.userId).toBe('user-1');
      expect(session.device).toBe('device-1');

      await randomService.logout(token);
      await expect(randomService.validateToken(token)).rejects.toThrow(
        AuthException,
      );
    });

    it('should generate prefixed random token', async () => {
      const randomStore = new MemoryStore();
      const randomStrategy = new RandomTokenStrategy(randomStore, {
        style: 'ulid',
        prefix: 'sa',
      });
      const randomService = new AuthService(
        randomStore,
        randomStrategy,
        { tokenTtl: 3600000, loginPolicy: 'multiple' },
        undefined,
        undefined,
      );

      const token = await randomService.login('user-1');
      expect(token.startsWith('sa:')).toBe(true);
      const session = await randomService.validateToken(token);
      expect(session.userId).toBe('user-1');
    });
  });

  describe('cookie mode', () => {
    const createMockResponse = () =>
      ({
        cookie: jest.fn(),
        clearCookie: jest.fn(),
      }) as unknown as import('express').Response;

    it('should write cookie on login when cookie mode enabled', async () => {
      const cookieService = {
        isEnabled: jest.fn().mockReturnValue(true),
        write: jest.fn(),
        read: jest.fn(),
        clear: jest.fn(),
      };
      const cookieAuthService = new AuthService(
        store,
        tokenStrategy,
        { tokenTtl: 3600000, loginPolicy: 'multiple' },
        undefined,
        undefined,
        undefined,
        cookieService as unknown as import('./cookie/cookie.service').CookieService,
      );

      const res = createMockResponse();
      const token = await cookieAuthService.login(
        'user-1',
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        res,
      );

      expect(cookieService.write).toHaveBeenCalledWith(res, token, 3600);
    });

    it('should not write cookie when cookie mode disabled', async () => {
      const cookieService = {
        isEnabled: jest.fn().mockReturnValue(false),
        write: jest.fn(),
        read: jest.fn(),
        clear: jest.fn(),
      };
      const cookieAuthService = new AuthService(
        store,
        tokenStrategy,
        { tokenTtl: 3600000, loginPolicy: 'multiple' },
        undefined,
        undefined,
        undefined,
        cookieService as unknown as import('./cookie/cookie.service').CookieService,
      );

      const res = createMockResponse();
      await cookieAuthService.login(
        'user-1',
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        res,
      );

      expect(cookieService.write).not.toHaveBeenCalled();
    });

    it('should clear cookie on logout when response is provided', async () => {
      const cookieService = {
        isEnabled: jest.fn().mockReturnValue(true),
        write: jest.fn(),
        read: jest.fn(),
        clear: jest.fn(),
      };
      const cookieAuthService = new AuthService(
        store,
        tokenStrategy,
        { tokenTtl: 3600000, loginPolicy: 'multiple' },
        undefined,
        undefined,
        undefined,
        cookieService as unknown as import('./cookie/cookie.service').CookieService,
      );

      const token = await cookieAuthService.login('user-1');
      const res = createMockResponse();
      await cookieAuthService.logout(token, res);

      expect(cookieService.clear).toHaveBeenCalledWith(res);
      await expect(cookieAuthService.validateToken(token)).rejects.toThrow(
        AuthException,
      );
    });

    it('should clear cookie even for invalid token', async () => {
      const cookieService = {
        isEnabled: jest.fn().mockReturnValue(true),
        write: jest.fn(),
        read: jest.fn(),
        clear: jest.fn(),
      };
      const cookieAuthService = new AuthService(
        store,
        tokenStrategy,
        { tokenTtl: 3600000, loginPolicy: 'multiple' },
        undefined,
        undefined,
        undefined,
        cookieService as unknown as import('./cookie/cookie.service').CookieService,
      );

      const res = createMockResponse();
      await expect(
        cookieAuthService.logout('invalid-token', res),
      ).resolves.not.toThrow();

      expect(cookieService.clear).toHaveBeenCalledWith(res);
    });
  });

  describe('remember me', () => {
    const createMockResponse = () =>
      ({
        cookie: jest.fn(),
        clearCookie: jest.fn(),
      }) as unknown as import('express').Response;

    it('should mark session as rememberMe and use long ttl', async () => {
      const rememberStore = new MemoryStore();
      const rememberService = new AuthService(
        rememberStore,
        tokenStrategy,
        {
          tokenTtl: 100,
          rememberMeTtl: 500,
          loginPolicy: 'multiple',
        },
        undefined,
        undefined,
      );

      const token = await rememberService.login(
        'user-1',
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        true,
      );
      const session = await rememberService.validateToken(token);
      expect(session.rememberMe).toBe(true);

      await new Promise((resolve) => setTimeout(resolve, 150));
      await expect(rememberService.validateToken(token)).resolves.toEqual(
        expect.objectContaining({ userId: 'user-1', rememberMe: true }),
      );
    });

    it('should use short ttl when rememberMe is false', async () => {
      const rememberStore = new MemoryStore();
      const rememberService = new AuthService(
        rememberStore,
        tokenStrategy,
        {
          tokenTtl: 100,
          rememberMeTtl: 500,
          loginPolicy: 'multiple',
        },
        undefined,
        undefined,
      );

      const token = await rememberService.login('user-1');
      await new Promise((resolve) => setTimeout(resolve, 150));
      await expect(rememberService.validateToken(token)).rejects.toThrow(
        AuthException,
      );
    });

    it('should write long-lived cookie when rememberMe is enabled', async () => {
      const cookieService = {
        isEnabled: jest.fn().mockReturnValue(true),
        write: jest.fn(),
        read: jest.fn(),
        clear: jest.fn(),
      };
      const cookieAuthService = new AuthService(
        store,
        tokenStrategy,
        {
          tokenTtl: 3600000,
          rememberMeTtl: 30 * 24 * 60 * 60 * 1000,
          loginPolicy: 'multiple',
        },
        undefined,
        undefined,
        undefined,
        cookieService as unknown as import('./cookie/cookie.service').CookieService,
      );

      const res = createMockResponse();
      const token = await cookieAuthService.login(
        'user-1',
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        res,
        true,
      );

      expect(cookieService.write).toHaveBeenCalledWith(
        res,
        token,
        30 * 24 * 60 * 60,
      );
    });
  });

  describe('distributed lock', () => {
    it('should release lock after login success', async () => {
      const release = jest.fn();
      const lockService = {
        acquire: jest
          .fn()
          .mockResolvedValue({ key: 'login:user-1:web', token: 'token-1' }),
        release,
      };
      const lockAuthService = new AuthService(
        store,
        tokenStrategy,
        { tokenTtl: 3600000, loginPolicy: 'multiple' },
        undefined,
        undefined,
        undefined,
        undefined,
        lockService,
      );

      const token = await lockAuthService.login('user-1', 'web');
      expect(token).toBeDefined();
      expect(lockService.acquire).toHaveBeenCalledWith(
        'login:user-1:web',
        5000,
      );
      expect(release).toHaveBeenCalled();
    });

    it('should throw LOGIN_CONCURRENT_LIMIT when lock acquisition fails', async () => {
      const lockService = {
        acquire: jest.fn().mockResolvedValue(undefined),
        release: jest.fn(),
      };
      const lockAuthService = new AuthService(
        store,
        tokenStrategy,
        { tokenTtl: 3600000, loginPolicy: 'multiple' },
        undefined,
        undefined,
        undefined,
        undefined,
        lockService,
      );

      try {
        await lockAuthService.login('user-1', 'web');
        fail('expected login to throw');
      } catch (err) {
        expect(err).toBeInstanceOf(AuthException);
        expect((err as AuthException).code).toBe(
          AuthErrorCode.LOGIN_CONCURRENT_LIMIT,
        );
      }
    });

    it('should skip lock when distributedLock.enabled is false', async () => {
      const lockService = {
        acquire: jest.fn().mockResolvedValue(undefined),
        release: jest.fn(),
      };
      const lockAuthService = new AuthService(
        store,
        tokenStrategy,
        {
          tokenTtl: 3600000,
          loginPolicy: 'multiple',
          distributedLock: { enabled: false },
        },
        undefined,
        undefined,
        undefined,
        undefined,
        lockService,
      );

      const token = await lockAuthService.login('user-1', 'web');
      expect(token).toBeDefined();
      expect(lockService.acquire).not.toHaveBeenCalled();
    });

    it('should retry lock acquisition and succeed', async () => {
      const release = jest.fn();
      const lockService = {
        acquire: jest
          .fn()
          .mockResolvedValueOnce(undefined)
          .mockResolvedValueOnce({ key: 'login:user-1:web', token: 'token-1' }),
        release,
      };
      const lockAuthService = new AuthService(
        store,
        tokenStrategy,
        {
          tokenTtl: 3600000,
          loginPolicy: 'multiple',
          distributedLock: { retries: 1, retryDelayMs: 10 },
        },
        undefined,
        undefined,
        undefined,
        undefined,
        lockService,
      );

      const token = await lockAuthService.login('user-1', 'web');
      expect(token).toBeDefined();
      expect(lockService.acquire).toHaveBeenCalledTimes(2);
      expect(release).toHaveBeenCalled();
    });

    it('should release lock even if login throws', async () => {
      const release = jest.fn();
      const brokenStore = {
        set: jest.fn().mockRejectedValue(new Error('store error')),
        get: jest.fn(),
        delete: jest.fn(),
        deleteByUserId: jest.fn(),
      };
      const lockService = {
        acquire: jest
          .fn()
          .mockResolvedValue({ key: 'login:user-1:web', token: 'token-1' }),
        release,
      };
      const lockAuthService = new AuthService(
        brokenStore,
        tokenStrategy,
        { tokenTtl: 3600000, loginPolicy: 'multiple' },
        undefined,
        undefined,
        undefined,
        undefined,
        lockService,
      );

      await expect(lockAuthService.login('user-1', 'web')).rejects.toThrow(
        'store error',
      );
      expect(release).toHaveBeenCalled();
    });
  });

  describe('multi account', () => {
    it('should allow multiple users on same device when enabled', async () => {
      const multiService = new AuthService(
        store,
        tokenStrategy,
        {
          tokenTtl: 3600000,
          loginPolicy: 'multiple',
          multiAccount: { enabled: true, maxAccounts: 2 },
        },
        undefined,
        undefined,
      );

      const token1 = await multiService.login('user-1', 'web');
      const token2 = await multiService.login('user-2', 'web');

      expect((await multiService.validateToken(token1)).userId).toBe('user-1');
      expect((await multiService.validateToken(token2)).userId).toBe('user-2');
    });

    it('should throw when exceeding maxAccounts', async () => {
      const multiService = new AuthService(
        store,
        tokenStrategy,
        {
          tokenTtl: 3600000,
          loginPolicy: 'multiple',
          multiAccount: { enabled: true, maxAccounts: 1 },
        },
        undefined,
        undefined,
      );

      await multiService.login('user-1', 'web');
      await expect(multiService.login('user-2', 'web')).rejects.toThrow(
        AuthException,
      );
    });

    it('should list accounts on a device', async () => {
      const multiService = new AuthService(
        store,
        tokenStrategy,
        {
          tokenTtl: 3600000,
          loginPolicy: 'multiple',
          multiAccount: { enabled: true, maxAccounts: 2 },
        },
        undefined,
        undefined,
      );

      await multiService.login('user-1', 'web');
      await multiService.login('user-2', 'web');

      const accounts = await multiService.listAccounts('web');
      expect(accounts.map((a) => a.userId).sort()).toEqual([
        'user-1',
        'user-2',
      ]);
    });

    it('should switch account and return target token', async () => {
      const multiService = new AuthService(
        store,
        tokenStrategy,
        {
          tokenTtl: 3600000,
          loginPolicy: 'multiple',
          multiAccount: { enabled: true, maxAccounts: 2 },
        },
        undefined,
        undefined,
      );

      const token1 = await multiService.login('user-1', 'web');
      await multiService.login('user-2', 'web');

      const targetToken = await multiService.switchAccount(token1, 'user-2');
      expect((await multiService.validateToken(targetToken)).userId).toBe(
        'user-2',
      );
    });

    it('should throw switchAccount when multi-account is disabled', async () => {
      const token = await service.login('user-1', 'web');
      await service.login('user-2', 'web');

      await expect(service.switchAccount(token, 'user-2')).rejects.toThrow(
        AuthException,
      );
    });

    it('should throw switchAccount when target account not found', async () => {
      const multiService = new AuthService(
        store,
        tokenStrategy,
        {
          tokenTtl: 3600000,
          loginPolicy: 'multiple',
          multiAccount: { enabled: true, maxAccounts: 2 },
        },
        undefined,
        undefined,
      );

      const token = await multiService.login('user-1', 'web');
      await expect(multiService.switchAccount(token, 'user-2')).rejects.toThrow(
        AuthException,
      );
    });
  });
});
