import { Test, TestingModule } from '@nestjs/testing';
import { AdminController } from './admin.controller';
import { AuthService } from '../../auth/auth.service';
import { AuthErrorCode } from '../../auth/errors/auth-error-code';
import { AuthException } from '../../auth/errors/auth.exception';
import { CookieService } from '../../auth/cookie/cookie.service';

describe('AdminController', () => {
  let controller: AdminController;

  const validAdminToken = 'valid-admin-token';
  const normalToken = 'normal-token';

  const mockAuthService = {
    validateToken: jest.fn().mockImplementation((token: string) => {
      if (token === validAdminToken) {
        return Promise.resolve({
          userId: 'admin-1',
          roles: ['admin'],
          permissions: ['admin:*'],
        });
      }
      if (token === normalToken) {
        return Promise.resolve({
          userId: 'user-1',
          roles: ['user'],
          permissions: ['user:read'],
        });
      }
      throw new AuthException(
        AuthErrorCode.TOKEN_INVALID,
        'Invalid token',
      );
    }),
    kickUser: jest.fn().mockResolvedValue(undefined),
    banUser: jest.fn().mockResolvedValue(undefined),
    unbanUser: jest.fn().mockResolvedValue(undefined),
    logout: jest.fn().mockResolvedValue(undefined),
  } as unknown as jest.Mocked<AuthService>;

  const mockSessionStore = {
    listByUserId: jest.fn().mockResolvedValue([
      { userId: 'user-1', device: 'web' },
    ]),
  };

  const mockClientStore = {
    registerClient: jest.fn().mockResolvedValue(undefined),
    getClient: jest.fn().mockImplementation((clientId: string) => {
      if (clientId === 'existing-client') {
        return Promise.resolve({
          clientId,
          clientSecret: 'secret',
          redirectUris: ['http://localhost/callback'],
          grants: ['authorization_code'],
        });
      }
      return Promise.resolve(undefined);
    }),
    removeToken: jest.fn().mockResolvedValue(undefined),
  };

  const mockAuthConfig = {
    randomToken: undefined,
    cookie: { enabled: false },
    fingerprint: { enabled: true },
    multiAccount: { enabled: false },
    loginPolicy: { policy: 'single' },
    rateLimit: { enabled: true },
  };

  const createRequest = (opts: {
    auth?: string;
    body?: Record<string, unknown>;
    query?: Record<string, string>;
    res?: unknown;
  }) => {
    return {
      headers: { authorization: opts.auth },
      ip: '127.0.0.1',
      body: opts.body || {},
      query: opts.query || {},
      res: opts.res,
    } as unknown as import('express').Request;
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AdminController],
      providers: [
        { provide: AuthService, useValue: mockAuthService },
        { provide: 'SESSION_STORE', useValue: mockSessionStore },
        { provide: 'OAUTH2_CLIENT_STORE', useValue: mockClientStore },
        { provide: 'AUTH_CONFIG', useValue: mockAuthConfig },
        { provide: CookieService, useValue: undefined },
      ],
    }).compile();

    controller = module.get<AdminController>(AdminController);
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('listSessions', () => {
    it('should return sessions for a user', async () => {
      const req = createRequest({ auth: `Bearer ${validAdminToken}` });
      const result = await controller.listSessions(req, 'user-1');
      expect(result).toEqual({
        userId: 'user-1',
        sessions: [{ userId: 'user-1', device: 'web' }],
        count: 1,
      });
    });

    it('should prompt for userId query when missing', async () => {
      const req = createRequest({ auth: `Bearer ${validAdminToken}` });
      const result = await controller.listSessions(req, undefined);
      expect(result).toEqual({
        message: 'userId query parameter required',
      });
    });
  });

  describe('kickUser', () => {
    it('should kick user', async () => {
      const req = createRequest({ auth: `Bearer ${validAdminToken}` });
      const result = await controller.kickUser(req, 'user-1');
      expect(result).toEqual({ success: true, userId: 'user-1' });
      expect(mockAuthService.kickUser).toHaveBeenCalledWith('user-1');
    });

    it('should require userId', async () => {
      const req = createRequest({ auth: `Bearer ${validAdminToken}` });
      await expect(controller.kickUser(req)).rejects.toThrow(
        'userId is required',
      );
    });
  });

  describe('banUser', () => {
    it('should ban user with default duration', async () => {
      const req = createRequest({
        auth: `Bearer ${validAdminToken}`,
        res: {},
      });
      const result = await controller.banUser(req, 'user-1', 'banned');
      expect(result).toEqual({
        success: true,
        userId: 'user-1',
        action: 'banned',
        duration: 3600,
      });
    });

    it('should unban user', async () => {
      const req = createRequest({ auth: `Bearer ${validAdminToken}` });
      const result = await controller.banUser(req, 'user-1', 'unban');
      expect(result).toEqual({
        success: true,
        userId: 'user-1',
        action: 'unbanned',
      });
      expect(mockAuthService.unbanUser).toHaveBeenCalledWith('user-1');
    });
  });

  describe('registerClient', () => {
    it('should register a new OAuth2 client', async () => {
      const req = createRequest({
        auth: `Bearer ${validAdminToken}`,
        body: {
          clientId: 'new-client',
          clientSecret: 'secret',
          redirectUris: ['http://localhost/callback'],
          grants: ['authorization_code'],
        },
      });

      const result = await controller.registerClient(req);
      expect(result.success).toBe(true);
      expect(mockClientStore.registerClient).toHaveBeenCalled();
    });

    it('should require clientId/secret/redirectUris', async () => {
      const req = createRequest({
        auth: `Bearer ${validAdminToken}`,
        body: { clientId: 'only-id' },
      });

      await expect(controller.registerClient(req)).rejects.toThrow(
        'clientId, clientSecret, and redirectUris are required',
      );
    });
  });

  describe('deleteClient', () => {
    it('should delete existing client', async () => {
      const req = createRequest({
        auth: `Bearer ${validAdminToken}`,
        query: { clientId: 'existing-client' },
      });

      const result = await controller.deleteClient(req, 'existing-client');
      expect(result).toEqual({ success: true, clientId: 'existing-client' });
    });

    it('should throw if client not found', async () => {
      const req = createRequest({
        auth: `Bearer ${validAdminToken}`,
        query: { clientId: 'missing-client' },
      });

      await expect(
        controller.deleteClient(req, 'missing-client'),
      ).rejects.toThrow('Client not found');
    });
  });

  describe('revokeToken', () => {
    it('should revoke a token', async () => {
      const req = createRequest({
        auth: `Bearer ${validAdminToken}`,
        query: { token: 'target-token' },
      });

      const result = await controller.revokeToken(req, 'target-token');
      expect(result).toEqual({ success: true });
    });

    it('should require token', async () => {
      const req = createRequest({ auth: `Bearer ${validAdminToken}` });
      await expect(controller.revokeToken(req)).rejects.toThrow(
        'token is required',
      );
    });
  });

  describe('getConfig', () => {
    it('should return auth config snapshot', async () => {
      const req = createRequest({ auth: `Bearer ${validAdminToken}` });
      const result = await controller.getConfig(req);
      expect(result).toEqual({
        tokenStrategy: 'jwt',
        cookieMode: false,
        fingerprintEnabled: true,
        multiAccountEnabled: false,
        loginPolicy: 'single',
        rateLimitEnabled: true,
      });
    });
  });

  describe('admin permission checks', () => {
    it('should reject requests without authorization', async () => {
      const req = createRequest({});
      await expect(controller.getConfig(req)).rejects.toThrow(
        'Admin token required',
      );
    });

    it('should reject non-admin users', async () => {
      const req = createRequest({ auth: `Bearer ${normalToken}` });
      await expect(controller.getConfig(req)).rejects.toThrow(
        'Admin privileges required',
      );
    });

    it('should reject invalid tokens', async () => {
      const req = createRequest({ auth: 'Bearer invalid-token' });
      await expect(controller.getConfig(req)).rejects.toThrow(
        'Invalid admin token',
      );
    });
  });

  describe('missing dependencies', () => {
    it('should reject session query when store not configured', async () => {
      const module: TestingModule = await Test.createTestingModule({
        controllers: [AdminController],
        providers: [
          { provide: AuthService, useValue: mockAuthService },
          { provide: 'AUTH_CONFIG', useValue: mockAuthConfig },
          { provide: CookieService, useValue: undefined },
        ],
      }).compile();

      const ctrl = module.get<AdminController>(AdminController);
      const req = createRequest({ auth: `Bearer ${validAdminToken}` });

      await expect(ctrl.listSessions(req, 'user-1')).rejects.toThrow(
        'Session store not configured',
      );
    });

    it('should reject client registration when OAuth2 store not configured', async () => {
      const module: TestingModule = await Test.createTestingModule({
        controllers: [AdminController],
        providers: [
          { provide: AuthService, useValue: mockAuthService },
          { provide: 'AUTH_CONFIG', useValue: mockAuthConfig },
          { provide: CookieService, useValue: undefined },
        ],
      }).compile();

      const ctrl = module.get<AdminController>(AdminController);
      const req = createRequest({ auth: `Bearer ${validAdminToken}` });

      await expect(ctrl.listClients(req)).rejects.toThrow(
        'OAuth2 client store not configured',
      );
    });
  });
});
