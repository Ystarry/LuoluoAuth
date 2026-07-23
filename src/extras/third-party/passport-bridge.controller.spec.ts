import { BadRequestException } from '@nestjs/common';
import type { Request, Response, NextFunction } from 'express';
import { AuthService } from '../../auth/auth.service';
import { PassportBridgeController } from './passport-bridge.controller';
import type {
  PassportInstance,
  PassportStrategyLike,
  ThirdPartyLoginHandler,
} from './interfaces';

describe('PassportBridgeController', () => {
  let controller: PassportBridgeController;
  let authService: AuthService;
  let passport: PassportInstance;
  let strategies: Record<string, PassportStrategyLike>;
  let loginHandler: ThirdPartyLoginHandler;

  const mockStrategy: PassportStrategyLike = { name: 'github' };

  const createMockRes = (): Response => {
    const res = {} as Response;
    res.status = jest.fn().mockReturnValue(res);
    res.json = jest.fn().mockReturnValue(res);
    return res;
  };

  const createMockReq = (overrides: Partial<Request> = {}): Request => {
    return {
      ip: '127.0.0.1',
      headers: { 'user-agent': 'test' },
      ...overrides,
    } as unknown as Request;
  };

  beforeEach(() => {
    authService = {
      login: jest.fn().mockResolvedValue('login-token'),
    } as unknown as AuthService;

    passport = {
      use: jest.fn(),
      authenticate: jest.fn(),
    } as unknown as PassportInstance;

    strategies = { github: mockStrategy };

    loginHandler = jest.fn().mockResolvedValue({
      userId: 'user-001',
      roles: ['user'],
      permissions: ['user:read'],
    });

    controller = new PassportBridgeController(
      authService,
      passport,
      strategies,
      loginHandler,
    );
  });

  describe('login', () => {
    it('should call passport.authenticate for known strategy', () => {
      const authenticateMiddleware = jest.fn();
      (passport.authenticate as jest.Mock).mockReturnValue(authenticateMiddleware);

      const req = createMockReq();
      const res = createMockRes();
      const next = jest.fn() as NextFunction;

      controller.login('github', req, res, next);

      expect(passport.authenticate).toHaveBeenCalledWith('github');
      expect(authenticateMiddleware).toHaveBeenCalledWith(req, res, next);
    });

    it('should throw BadRequestException for unknown strategy', () => {
      const req = createMockReq();
      const res = createMockRes();
      const next = jest.fn() as NextFunction;

      expect(() => controller.login('google', req, res, next)).toThrow(
        BadRequestException,
      );
    });
  });

  describe('callback', () => {
    const invokeCallback = (
      err: Error | null,
      profile?: Record<string, unknown>,
    ): PassportInstance['authenticate'] => {
      return jest.fn().mockImplementation((_name, _options, callback) => {
        return (_req: unknown, _res: unknown, _next: unknown) => {
          callback!(err, profile);
        };
      }) as unknown as PassportInstance['authenticate'];
    };

    it('should authenticate and login on success', async () => {
      const req = createMockReq();
      const res = createMockRes();
      const next = jest.fn() as NextFunction;

      controller = new PassportBridgeController(
        authService,
        { use: jest.fn(), authenticate: invokeCallback(null, {
          id: 'github-123',
          displayName: 'GitHub User',
          emails: [{ value: 'github@example.com' }],
          photos: [{ value: 'https://avatar.png' }],
        }) } as unknown as PassportInstance,
        strategies,
        loginHandler,
      );

      await controller.callback('github', req, res, next);
      // callback 内部包含 await，等待微任务完成
      await new Promise((resolve) => setImmediate(resolve));

      expect(loginHandler).toHaveBeenCalledWith(
        expect.objectContaining({
          provider: 'github',
          providerUserId: 'github-123',
          email: 'github@example.com',
          username: 'GitHub User',
          avatar: 'https://avatar.png',
        }),
        req,
        res,
      );
      expect(authService.login).toHaveBeenCalledWith(
        'user-001',
        'github',
        ['user'],
        ['user:read'],
        '127.0.0.1',
        'test',
        res,
      );
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ token: 'login-token' }),
      );
    });

    it('should handle authentication error', async () => {
      const req = createMockReq();
      const res = createMockRes();
      const next = jest.fn() as NextFunction;

      controller = new PassportBridgeController(
        authService,
        { use: jest.fn(), authenticate: invokeCallback(new Error('OAuth denied')) } as unknown as PassportInstance,
        strategies,
        loginHandler,
      );

      await controller.callback('github', req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ error: 'OAuth denied' }),
      );
    });

    it('should handle missing profile', async () => {
      const req = createMockReq();
      const res = createMockRes();
      const next = jest.fn() as NextFunction;

      controller = new PassportBridgeController(
        authService,
        { use: jest.fn(), authenticate: invokeCallback(null) } as unknown as PassportInstance,
        strategies,
        loginHandler,
      );

      await controller.callback('github', req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ error: 'Passport authentication failed' }),
      );
    });

    it('should handle login handler error', async () => {
      const req = createMockReq();
      const res = createMockRes();
      const next = jest.fn() as NextFunction;

      (loginHandler as jest.Mock).mockRejectedValue(new Error('handler failed'));

      controller = new PassportBridgeController(
        authService,
        { use: jest.fn(), authenticate: invokeCallback(null, { id: 'github-123', displayName: 'User' }) } as unknown as PassportInstance,
        strategies,
        loginHandler,
      );

      await controller.callback('github', req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ error: 'handler failed' }),
      );
    });

    it('should normalize profile with various fields', async () => {
      const req = createMockReq();
      const res = createMockRes();
      const next = jest.fn() as NextFunction;

      controller = new PassportBridgeController(
        authService,
        { use: jest.fn(), authenticate: invokeCallback(null, {
          sub: 'sub-123',
          email: 'direct@example.com',
          username: 'direct-user',
          picture: 'https://direct.png',
        }) } as unknown as PassportInstance,
        strategies,
        loginHandler,
      );

      await controller.callback('github', req, res, next);

      expect(loginHandler).toHaveBeenCalledWith(
        expect.objectContaining({
          providerUserId: 'sub-123',
          email: 'direct@example.com',
          username: 'direct-user',
          avatar: 'https://direct.png',
        }),
        req,
        res,
      );
    });
  });
});
