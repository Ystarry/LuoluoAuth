import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { AuthGuard } from './auth.guard';
import { AuthService } from './auth.service';
import { CookieService } from './cookie/cookie.service';
import { PermissionEngine } from './permission/permission.engine';
import { AUTH_METADATA_KEY } from './auth.decorator';

describe('AuthGuard Cookie mode', () => {
  let guard: AuthGuard;
  let authService: AuthService;
  let cookieService: CookieService;
  let reflector: Reflector;

  const createToken = (payload: Record<string, unknown>): string => {
    return jwt.sign(payload, 'test-secret', { expiresIn: '1h' });
  };

  const createContext = (
    req: Partial<Request>,
    res: Partial<Response>,
  ): ExecutionContext => {
    return {
      switchToHttp: () => ({
        getRequest: () => req as Request,
        getResponse: () => res as Response,
      }),
      getHandler: () => jest.fn(),
      getClass: () => ({}),
    } as unknown as ExecutionContext;
  };

  beforeEach(() => {
    authService = {
      validateToken: jest.fn(),
      isBanned: jest.fn().mockResolvedValue(false),
      getConfig: jest.fn().mockReturnValue({ autoRenew: false }),
      renewSession: jest.fn(),
      rotateToken: jest.fn().mockResolvedValue(undefined),
    } as unknown as AuthService;

    cookieService = {
      isEnabled: jest.fn().mockReturnValue(true),
      read: jest.fn(),
      write: jest.fn(),
      clear: jest.fn(),
    } as unknown as CookieService;

    reflector = {
      getAllAndOverride: jest.fn((key: string) => {
        return key === AUTH_METADATA_KEY ? true : undefined;
      }),
    } as unknown as Reflector;

    guard = new AuthGuard(
      authService,
      reflector,
      new PermissionEngine(),
      cookieService,
    );
  });

  it('should authenticate via cookie token and renew cookie', async () => {
    const token = createToken({ sessionId: 's1', userId: 'u1' });
    const req = {
      headers: {},
      cookies: { 'auth-token': token },
      ip: '127.0.0.1',
    } as unknown as Request;
    const res = { cookie: jest.fn() } as unknown as Response;

    (cookieService.read as jest.Mock).mockReturnValue(token);
    (authService.validateToken as jest.Mock).mockResolvedValue({
      userId: 'u1',
      createTime: Date.now(),
    });

    const result = await guard.canActivate(createContext(req, res));

    expect(result).toBe(true);
    expect(cookieService.read).toHaveBeenCalledWith(req);
    expect(authService.validateToken).toHaveBeenCalledWith(
      token,
      '127.0.0.1',
      undefined,
    );
    expect(cookieService.write).toHaveBeenCalledWith(res, token);
  });

  it('should rotate cookie token when strategy supports rotation', async () => {
    const oldToken = createToken({ sessionId: 's1', userId: 'u1' });
    const newToken = createToken({ sessionId: 's2', userId: 'u1' });
    const req = {
      headers: {},
      cookies: { 'auth-token': oldToken },
      ip: '127.0.0.1',
    } as unknown as Request;
    const res = { cookie: jest.fn() } as unknown as Response;

    (cookieService.read as jest.Mock).mockReturnValue(oldToken);
    (authService.validateToken as jest.Mock).mockResolvedValue({
      userId: 'u1',
      createTime: Date.now(),
    });
    (authService.rotateToken as jest.Mock).mockResolvedValue(newToken);

    const result = await guard.canActivate(createContext(req, res));

    expect(result).toBe(true);
    expect(authService.rotateToken).toHaveBeenCalledWith(oldToken);
    expect(cookieService.write).toHaveBeenCalledWith(res, newToken);
  });

  it('should prefer header token over cookie token', async () => {
    const headerToken = createToken({ sessionId: 's1', userId: 'u1' });
    const cookieToken = createToken({ sessionId: 's2', userId: 'u2' });
    const req = {
      headers: { authorization: `Bearer ${headerToken}` },
      cookies: { 'auth-token': cookieToken },
      ip: '127.0.0.1',
    } as unknown as Request;
    const res = { cookie: jest.fn() } as unknown as Response;

    (authService.validateToken as jest.Mock).mockResolvedValue({
      userId: 'u1',
      createTime: Date.now(),
    });

    await guard.canActivate(createContext(req, res));

    expect(authService.validateToken).toHaveBeenCalledWith(
      headerToken,
      '127.0.0.1',
      undefined,
    );
    expect(cookieService.read).not.toHaveBeenCalled();
    expect(cookieService.write).not.toHaveBeenCalled();
  });

  it('should throw UnauthorizedException when token is missing', async () => {
    const req = {
      headers: {},
      cookies: {},
      ip: '127.0.0.1',
    } as unknown as Request;
    const res = { cookie: jest.fn() } as unknown as Response;

    (cookieService.read as jest.Mock).mockReturnValue(undefined);

    await expect(guard.canActivate(createContext(req, res))).rejects.toThrow(
      UnauthorizedException,
    );
  });

  it('should throw UnauthorizedException for invalid cookie token', async () => {
    const req = {
      headers: {},
      cookies: { 'auth-token': 'bad-token' },
      ip: '127.0.0.1',
    } as unknown as Request;
    const res = { cookie: jest.fn() } as unknown as Response;

    (cookieService.read as jest.Mock).mockReturnValue('bad-token');
    (authService.validateToken as jest.Mock).mockRejectedValue(
      new Error('invalid'),
    );

    await expect(guard.canActivate(createContext(req, res))).rejects.toThrow(
      UnauthorizedException,
    );
  });

  it('should skip cookie handling when cookie mode is disabled', async () => {
    (cookieService.isEnabled as jest.Mock).mockReturnValue(false);

    const req = {
      headers: {},
      cookies: { 'auth-token': createToken({ sessionId: 's1', userId: 'u1' }) },
      ip: '127.0.0.1',
    } as unknown as Request;
    const res = { cookie: jest.fn() } as unknown as Response;

    await expect(guard.canActivate(createContext(req, res))).rejects.toThrow(
      UnauthorizedException,
    );

    expect(cookieService.read).not.toHaveBeenCalled();
  });
});
