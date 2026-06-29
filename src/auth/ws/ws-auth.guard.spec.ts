import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { WsAuthGuard } from './ws-auth.guard';
import type { AuthService } from '../auth.service';
import type { CookieService } from '../cookie/cookie.service';

function createContext(client: unknown): ExecutionContext {
  return {
    switchToWs: () => ({
      getClient: () => client,
    }),
    switchToHttp: () => ({
      getRequest: () => ({}),
      getResponse: () => ({}),
    }),
    getHandler: () => jest.fn(),
    getClass: () => ({}),
  } as unknown as ExecutionContext;
}

describe('WsAuthGuard', () => {
  const mockSession = {
    userId: 'user-1',
    device: 'web',
    createTime: Date.now(),
  };

  let validateToken: jest.Mock;
  let authService: AuthService;
  let cookieService: CookieService;
  let guard: WsAuthGuard;

  beforeEach(() => {
    validateToken = jest.fn().mockResolvedValue(mockSession);
    authService = { validateToken } as unknown as AuthService;

    cookieService = {
      isEnabled: jest.fn().mockReturnValue(true),
      getName: jest.fn().mockReturnValue('auth-token'),
    } as unknown as CookieService;

    guard = new WsAuthGuard(authService, cookieService);
  });

  it('should authenticate Socket.IO client via auth.token', async () => {
    const client: {
      data?: Record<string, unknown>;
      handshake: Record<string, unknown>;
    } = {
      handshake: {
        auth: { token: 'valid-token' },
        headers: {},
        address: '127.0.0.1',
      },
    };

    const result = await guard.canActivate(createContext(client));

    expect(result).toBe(true);
    expect(client.data?.user).toEqual(mockSession);
    expect(validateToken).toHaveBeenCalledWith(
      'valid-token',
      '127.0.0.1',
      undefined,
    );
  });

  it('should fallback to query.token when auth.token and headers are absent', async () => {
    const client = {
      handshake: {
        query: { token: 'query-token' },
        headers: {},
        address: '127.0.0.1',
      },
    };

    await guard.canActivate(createContext(client));

    expect(validateToken).toHaveBeenCalledWith(
      'query-token',
      '127.0.0.1',
      undefined,
    );
  });

  it('should prefer auth.token over query.token', async () => {
    const client = {
      handshake: {
        auth: { token: 'auth-token' },
        query: { token: 'query-token' },
        headers: {},
        address: '127.0.0.1',
      },
    };

    await guard.canActivate(createContext(client));

    expect(validateToken).toHaveBeenCalledWith(
      'auth-token',
      '127.0.0.1',
      undefined,
    );
  });

  it('should authenticate Socket.IO client via authorization header', async () => {
    const client = {
      handshake: {
        headers: {
          authorization: 'Bearer header-token',
          'user-agent': 'Mozilla/5.0',
        },
        address: '192.168.1.1',
      },
    };

    await guard.canActivate(createContext(client));

    expect(validateToken).toHaveBeenCalledWith(
      'header-token',
      '192.168.1.1',
      'Mozilla/5.0',
    );
  });

  it('should authenticate native WS client via url token', async () => {
    const client = {
      upgradeReq: {
        url: '/ws?token=url-token',
        headers: {},
        socket: { remoteAddress: '10.0.0.1' },
      },
    };

    await guard.canActivate(createContext(client));

    expect(validateToken).toHaveBeenCalledWith(
      'url-token',
      '10.0.0.1',
      undefined,
    );
  });

  it('should authenticate via cookie when CookieService is enabled', async () => {
    const client = {
      handshake: {
        headers: {
          cookie: 'auth-token=cookie-token; other=value',
        },
        address: '127.0.0.1',
      },
    };

    await guard.canActivate(createContext(client));

    expect(validateToken).toHaveBeenCalledWith(
      'cookie-token',
      '127.0.0.1',
      undefined,
    );
  });

  it('should reject missing token', async () => {
    const client = {
      handshake: {
        headers: {},
      },
    };

    await expect(guard.canActivate(createContext(client))).rejects.toThrow(
      UnauthorizedException,
    );
  });

  it('should reject invalid token', async () => {
    validateToken.mockRejectedValue(new Error('invalid'));
    const client = {
      handshake: {
        auth: { token: 'invalid-token' },
        headers: {},
      },
    };

    await expect(guard.canActivate(createContext(client))).rejects.toThrow(
      UnauthorizedException,
    );
  });

  describe('native WS (upgradeReq)', () => {
    it('should authenticate via upgradeReq authorization header', async () => {
      const client = {
        upgradeReq: {
          url: '/ws',
          headers: {
            authorization: 'Bearer ws-header-token',
          },
          socket: { remoteAddress: '10.0.0.2' },
        },
      };

      await guard.canActivate(createContext(client));

      expect(validateToken).toHaveBeenCalledWith(
        'ws-header-token',
        '10.0.0.2',
        undefined,
      );
    });

    it('should authenticate via upgradeReq cookie', async () => {
      const client = {
        upgradeReq: {
          url: '/ws',
          headers: {
            cookie: 'auth-token=ws-cookie-token',
          },
          socket: { remoteAddress: '10.0.0.3' },
        },
      };

      await guard.canActivate(createContext(client));

      expect(validateToken).toHaveBeenCalledWith(
        'ws-cookie-token',
        '10.0.0.3',
        undefined,
      );
    });

    it('should skip cookie when CookieService is disabled', async () => {
      const disabledCookieGuard = new WsAuthGuard(authService, {
        isEnabled: jest.fn().mockReturnValue(false),
        getName: jest.fn(),
      } as unknown as CookieService);

      const client = {
        handshake: {
          headers: {
            cookie: 'auth-token=some-token',
          },
        },
      };

      await expect(
        disabledCookieGuard.canActivate(createContext(client)),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should return undefined for cookie without matching name', async () => {
      const client = {
        handshake: {
          headers: {
            cookie: 'other-cookie=value',
          },
        },
      };

      await expect(guard.canActivate(createContext(client))).rejects.toThrow(
        UnauthorizedException,
      );
    });
  });

  describe('token extraction edge cases', () => {
    it('should handle url without search params', async () => {
      const client = {
        upgradeReq: {
          url: '/ws',
          headers: {},
          socket: { remoteAddress: '10.0.0.4' },
        },
      };

      await expect(guard.canActivate(createContext(client))).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should handle malformed URL gracefully', async () => {
      // URL with invalid characters that won't throw from URLSearchParams
      const client = {
        upgradeReq: {
          url: '/ws?token=valid',
          headers: {},
          socket: { remoteAddress: '10.0.0.5' },
        },
      };

      await guard.canActivate(createContext(client));

      expect(validateToken).toHaveBeenCalledWith(
        'valid',
        '10.0.0.5',
        undefined,
      );
    });

    it('should handle asString with array value', async () => {
      const client = {
        handshake: {
          query: { token: ['array-token', 'second'] },
          headers: {},
          address: '10.0.0.6',
        },
      };

      await guard.canActivate(createContext(client));

      expect(validateToken).toHaveBeenCalledWith(
        'array-token',
        '10.0.0.6',
        undefined,
      );
    });
  });

  describe('extractClientInfo edge cases', () => {
    it('should return empty object for unknown client structure', async () => {
      const client = {
        handshake: {
          auth: { token: 'valid' },
          address: '10.0.0.7',
        },
      };

      await guard.canActivate(createContext(client));

      expect(validateToken).toHaveBeenCalledWith(
        'valid',
        '10.0.0.7',
        undefined,
      );
    });
  });
});
