import { ExecutionContext, ForbiddenException, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { RpcException } from '@nestjs/microservices';
import { AuthGuard } from './auth.guard';
import { AuthService } from './auth.service';
import { PermissionEngine } from './permission/permission.engine';
import { CookieService } from './cookie/cookie.service';
import {
  AUTH_METADATA_KEY,
  ROLES_METADATA_KEY,
  PERMISSIONS_METADATA_KEY,
  SAFE_AUTH_METADATA_KEY,
} from './auth.decorator';

describe('AuthGuard.forMicroservice', () => {
  let guard: ReturnType<typeof AuthGuard.forMicroservice>;
  let authService: AuthService;
  let cookieService: CookieService;
  let reflector: Reflector;

  const createRpcContext = (
    metadata: Record<string, unknown> = {},
  ): ExecutionContext => {
    return {
      getType: () => 'rpc',
      switchToRpc: () => ({
        getContext: () => ({
          getMap: () => metadata,
        }),
      }),
      getHandler: () => jest.fn(),
      getClass: () => ({}),
    } as unknown as ExecutionContext;
  };

  const createHttpContext = (req: Record<string, unknown> = {}): ExecutionContext => {
    return {
      getType: () => 'http',
      switchToHttp: () => ({
        getRequest: () => req,
        getResponse: () => ({}),
      }),
      getHandler: () => jest.fn(),
      getClass: () => ({}),
    } as unknown as ExecutionContext;
  };

  const setupReflector = (overrides: Record<string, unknown> = {}) => {
    const map: Record<string, unknown> = {
      [AUTH_METADATA_KEY]: true,
      ...overrides,
    };
    (reflector.getAllAndOverride as jest.Mock).mockImplementation((key: string) => {
      return map[key] ?? undefined;
    });
  };

  beforeEach(() => {
    authService = {
      validateRpcToken: jest.fn(),
      validateToken: jest.fn(),
      isBanned: jest.fn().mockResolvedValue(false),
      getConfig: jest.fn().mockReturnValue({ autoRenew: false }),
      isSafeAuth: jest.fn().mockReturnValue(false),
    } as unknown as AuthService;

    cookieService = {
      isEnabled: jest.fn().mockReturnValue(false),
    } as unknown as CookieService;

    reflector = {
      getAllAndOverride: jest.fn(),
    } as unknown as Reflector;

    guard = new (AuthGuard.forMicroservice())(
      authService,
      reflector,
      new PermissionEngine(),
      cookieService,
    );
  });

  it('should allow valid rpc token', async () => {
    setupReflector();
    (authService.validateRpcToken as jest.Mock).mockResolvedValue({
      userId: 'u1',
      roles: ['user'],
      permissions: ['user:read'],
    });

    const result = await guard.canActivate(
      createRpcContext({ authorization: 'Bearer valid-token' }) as ExecutionContext,
    );

    expect(result).toBe(true);
    expect(authService.validateRpcToken).toHaveBeenCalledWith('valid-token', undefined);
  });

  it('should extract token from plain rpc context', async () => {
    setupReflector();
    const rpcContext = {
      getMap: () => ({ authorization: 'Bearer plain-token' }),
      ip: '10.0.0.1',
    };
    (authService.validateRpcToken as jest.Mock).mockResolvedValue({
      userId: 'u1',
      roles: ['user'],
      permissions: ['user:read'],
    });

    const context = {
      getType: () => 'rpc',
      switchToRpc: () => ({ getContext: () => rpcContext }),
      getHandler: () => jest.fn(),
      getClass: () => ({}),
    } as unknown as ExecutionContext;

    await guard.canActivate(context);

    expect(authService.validateRpcToken).toHaveBeenCalledWith('plain-token', '10.0.0.1');
  });

  it('should throw RpcException when token is missing', async () => {
    setupReflector();
    await expect(guard.canActivate(createRpcContext() as ExecutionContext)).rejects.toThrow(
      RpcException,
    );
  });

  it('should throw RpcException when token is invalid', async () => {
    setupReflector();
    const rpcContext = { getMap: () => ({ authorization: 'Bearer invalid-token' }) };
    (authService.validateRpcToken as jest.Mock).mockRejectedValue(new Error('invalid'));

    const context = {
      getType: () => 'rpc',
      switchToRpc: () => ({ getContext: () => rpcContext }),
      getHandler: () => jest.fn(),
      getClass: () => ({}),
    } as unknown as ExecutionContext;

    await expect(guard.canActivate(context)).rejects.toThrow(RpcException);
  });

  it('should throw RpcException when user is banned', async () => {
    setupReflector();
    const rpcContext = { getMap: () => ({ authorization: 'Bearer token' }) };
    (authService.validateRpcToken as jest.Mock).mockResolvedValue({ userId: 'u1' });
    (authService.isBanned as jest.Mock).mockResolvedValue(true);

    const context = {
      getType: () => 'rpc',
      switchToRpc: () => ({ getContext: () => rpcContext }),
      getHandler: () => jest.fn(),
      getClass: () => ({}),
    } as unknown as ExecutionContext;

    await expect(guard.canActivate(context)).rejects.toThrow(RpcException);
  });

  it('should reject when role is missing', async () => {
    setupReflector({ [ROLES_METADATA_KEY]: ['admin'] });
    const rpcContext = { getMap: () => ({ authorization: 'Bearer token' }) };
    (authService.validateRpcToken as jest.Mock).mockResolvedValue({
      userId: 'u1',
      roles: ['user'],
    });

    const context = {
      getType: () => 'rpc',
      switchToRpc: () => ({ getContext: () => rpcContext }),
      getHandler: () => jest.fn(),
      getClass: () => ({}),
    } as unknown as ExecutionContext;

    await expect(guard.canActivate(context)).rejects.toThrow(RpcException);
  });

  it('should reject when permission is missing', async () => {
    setupReflector({ [PERMISSIONS_METADATA_KEY]: ['admin:write'] });
    const rpcContext = { getMap: () => ({ authorization: 'Bearer token' }) };
    (authService.validateRpcToken as jest.Mock).mockResolvedValue({
      userId: 'u1',
      permissions: ['user:read'],
    });

    const context = {
      getType: () => 'rpc',
      switchToRpc: () => ({ getContext: () => rpcContext }),
      getHandler: () => jest.fn(),
      getClass: () => ({}),
    } as unknown as ExecutionContext;

    await expect(guard.canActivate(context)).rejects.toThrow(RpcException);
  });

  it('should reject when safe auth is required but not active', async () => {
    setupReflector({ [SAFE_AUTH_METADATA_KEY]: true });
    const rpcContext = { getMap: () => ({ authorization: 'Bearer token' }) };
    (authService.validateRpcToken as jest.Mock).mockResolvedValue({ userId: 'u1' });

    const context = {
      getType: () => 'rpc',
      switchToRpc: () => ({ getContext: () => rpcContext }),
      getHandler: () => jest.fn(),
      getClass: () => ({}),
    } as unknown as ExecutionContext;

    await expect(guard.canActivate(context)).rejects.toThrow(RpcException);
  });

  it('should allow when safe auth is active', async () => {
    setupReflector({ [SAFE_AUTH_METADATA_KEY]: true });
    const rpcContext = { getMap: () => ({ authorization: 'Bearer token' }) };
    (authService.validateRpcToken as jest.Mock).mockResolvedValue({ userId: 'u1' });
    (authService.isSafeAuth as jest.Mock).mockReturnValue(true);

    const context = {
      getType: () => 'rpc',
      switchToRpc: () => ({ getContext: () => rpcContext }),
      getHandler: () => jest.fn(),
      getClass: () => ({}),
    } as unknown as ExecutionContext;

    const result = await guard.canActivate(context);
    expect(result).toBe(true);
  });

  it('should fallback to http guard logic for http context', async () => {
    setupReflector();
    const token = 'http-token';
    const req = {
      headers: { authorization: `Bearer ${token}` },
      ip: '127.0.0.1',
    };
    (authService.validateToken as jest.Mock).mockResolvedValue({
      userId: 'u1',
      roles: ['user'],
      permissions: ['user:read'],
    });

    const result = await guard.canActivate(createHttpContext(req) as ExecutionContext);

    expect(result).toBe(true);
    expect(authService.validateToken).toHaveBeenCalledWith(
      token,
      '127.0.0.1',
      undefined,
    );
  });
});
