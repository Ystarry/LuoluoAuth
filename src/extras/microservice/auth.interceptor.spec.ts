import { Test, TestingModule } from '@nestjs/testing';
import { ExecutionContext, CallHandler } from '@nestjs/common';
import { of } from 'rxjs';
import { Metadata } from '@grpc/grpc-js';
import { Request } from 'express';
import {
  MicroserviceAuthInterceptor,
  RpcTokenResolver,
} from './auth.interceptor';
import { AuthService } from '../../auth/auth.service';

describe('MicroserviceAuthInterceptor', () => {
  let interceptor: MicroserviceAuthInterceptor;
  const mockAuthService = {
    validateToken: jest.fn().mockResolvedValue({
      userId: 'user-1',
      roles: ['user'],
      permissions: ['read'],
    }),
  } as unknown as AuthService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        {
          provide: AuthService,
          useValue: mockAuthService,
        },
        MicroserviceAuthInterceptor,
      ],
    }).compile();

    interceptor = module.get<MicroserviceAuthInterceptor>(
      MicroserviceAuthInterceptor,
    );
    jest.clearAllMocks();
  });

  it('should attach token from HTTP request header to internal cache', (done) => {
    const request = {
      headers: { authorization: 'Bearer http-token' },
    } as unknown as Request;

    const context = {
      getType: () => 'http' as const,
      switchToHttp: () => ({ getRequest: () => request }),
    } as unknown as ExecutionContext;

    const next: CallHandler = {
      handle: () => of(undefined),
    };

    interceptor.intercept(context, next).subscribe(() => {
      expect(request['__rpc_auth_token']).toBe('http-token');
      done();
    });
  });

  it('should attach token from AsyncLocalStorage in RPC context', (done) => {
    const metadata = new Metadata();
    const context = {
      getType: () => 'rpc' as const,
      switchToRpc: () => ({ getContext: () => metadata }),
    } as unknown as ExecutionContext;

    const next: CallHandler = {
      handle: () => of(undefined),
    };

    // eslint-disable-next-line @typescript-eslint/no-floating-promises
    MicroserviceAuthInterceptor.runWithToken('als-token', async () => {
      await Promise.resolve();
      interceptor.intercept(context, next).subscribe(() => {
        const map = metadata.getMap();
        expect(map['authorization']).toBe('Bearer als-token');
        done();
      });
    });
  });

  it('should attach token from custom resolver in RPC context', async () => {
    const resolver: RpcTokenResolver = () => 'custom-token';

    const moduleWithResolver: TestingModule = await Test.createTestingModule({
      providers: [
        {
          provide: AuthService,
          useValue: mockAuthService,
        },
        {
          provide: 'RPC_TOKEN_RESOLVER',
          useValue: resolver,
        },
        MicroserviceAuthInterceptor,
      ],
    }).compile();

    const interceptorWithResolver = moduleWithResolver.get(
      MicroserviceAuthInterceptor,
    );

    const metadata = new Metadata();
    const context = {
      getType: () => 'rpc' as const,
      switchToRpc: () => ({ getContext: () => metadata }),
    } as unknown as ExecutionContext;

    const next: CallHandler = {
      handle: () => of(undefined),
    };

    await new Promise<void>((resolve) => {
      interceptorWithResolver.intercept(context, next).subscribe(() => {
        const map = metadata.getMap();
        expect(map['authorization']).toBe('Bearer custom-token');
        resolve();
      });
    });
  });

  it('should attach token to plain object RPC context', (done) => {
    const rpcContext: Record<string, string> = {};
    const context = {
      getType: () => 'rpc' as const,
      switchToRpc: () => ({ getContext: () => rpcContext }),
    } as unknown as ExecutionContext;

    const next: CallHandler = {
      handle: () => of(undefined),
    };

    // eslint-disable-next-line @typescript-eslint/no-floating-promises
    MicroserviceAuthInterceptor.runWithToken('tcp-token', async () => {
      await Promise.resolve();
      interceptor.intercept(context, next).subscribe(() => {
        expect(rpcContext['authorization']).toBe('Bearer tcp-token');
        done();
      });
    });
  });

  it('should attach token to object with add method (non-Metadata)', async () => {
    const rpcContext: Record<string, unknown> = {
      add: jest.fn(),
    };

    const context = {
      getType: () => 'rpc' as const,
      switchToRpc: () => ({ getContext: () => rpcContext }),
    } as unknown as ExecutionContext;

    const next: CallHandler = {
      handle: () => of(undefined),
    };

    await new Promise<void>((resolve) => {
      // eslint-disable-next-line @typescript-eslint/no-floating-promises
      MicroserviceAuthInterceptor.runWithToken('add-method-token', async () => {
        await Promise.resolve();
        interceptor.intercept(context, next).subscribe(() => {
          expect(rpcContext.add).toHaveBeenCalledWith(
            'authorization',
            'Bearer add-method-token',
          );
          resolve();
        });
      });
    });
  });

  it('should not modify RPC context when no token is available', (done) => {
    const rpcContext: Record<string, string> = {};
    const context = {
      getType: () => 'rpc' as const,
      switchToRpc: () => ({ getContext: () => rpcContext }),
    } as unknown as ExecutionContext;

    const next: CallHandler = {
      handle: () => of(undefined),
    };

    interceptor.intercept(context, next).subscribe(() => {
      expect(Object.keys(rpcContext)).toHaveLength(0);
      done();
    });
  });

  it('should handle RPC error when attachTokenToRpc fails', (done) => {
    // Mock a failing attachTokenToRpc by providing a broken setup
    const context = {
      getType: () => 'rpc' as const,
      switchToRpc: () => {
        throw new Error('RPC context error');
      },
    } as unknown as ExecutionContext;

    const next: CallHandler = {
      handle: () => of(undefined),
    };

    interceptor.intercept(context, next).subscribe({
      error: (err: Error) => {
        expect(err.message).toBe('RPC context error');
        done();
      },
    });
  });

  it('should validate token before attaching when validateToken is enabled', async () => {
    const moduleWithValidation: TestingModule = await Test.createTestingModule({
      providers: [
        {
          provide: AuthService,
          useValue: mockAuthService,
        },
        {
          provide: 'RPC_AUTH_INTERCEPTOR_CONFIG',
          useValue: { validateToken: true },
        },
        MicroserviceAuthInterceptor,
      ],
    }).compile();

    const interceptorWithValidation = moduleWithValidation.get(
      MicroserviceAuthInterceptor,
    );

    const rpcContext: Record<string, string> = {};
    const context = {
      getType: () => 'rpc' as const,
      switchToRpc: () => ({ getContext: () => rpcContext }),
    } as unknown as ExecutionContext;

    const next: CallHandler = {
      handle: () => of(undefined),
    };

    await new Promise<void>((resolve) => {
      // eslint-disable-next-line @typescript-eslint/no-floating-promises
      MicroserviceAuthInterceptor.runWithToken('valid-token', async () => {
        await Promise.resolve();
        interceptorWithValidation.intercept(context, next).subscribe(() => {
          expect(mockAuthService.validateToken).toHaveBeenCalledWith(
            'valid-token',
          );
          expect(rpcContext['authorization']).toBe('Bearer valid-token');
          resolve();
        });
      });
    });
  });

  it('should skip invalid token when validateToken is enabled', async () => {
    const invalidMockAuthService = {
      validateToken: jest.fn().mockRejectedValue(new Error('Invalid token')),
    } as unknown as AuthService;

    const moduleWithValidation: TestingModule = await Test.createTestingModule({
      providers: [
        {
          provide: AuthService,
          useValue: invalidMockAuthService,
        },
        {
          provide: 'RPC_AUTH_INTERCEPTOR_CONFIG',
          useValue: { validateToken: true },
        },
        MicroserviceAuthInterceptor,
      ],
    }).compile();

    const interceptorWithValidation = moduleWithValidation.get(
      MicroserviceAuthInterceptor,
    );

    const rpcContext: Record<string, string> = {};
    const context = {
      getType: () => 'rpc' as const,
      switchToRpc: () => ({ getContext: () => rpcContext }),
    } as unknown as ExecutionContext;

    const next: CallHandler = {
      handle: () => of(undefined),
    };

    await new Promise<void>((resolve) => {
      // eslint-disable-next-line @typescript-eslint/no-floating-promises
      MicroserviceAuthInterceptor.runWithToken('invalid-token', async () => {
        await Promise.resolve();
        interceptorWithValidation.intercept(context, next).subscribe(() => {
          expect(invalidMockAuthService.validateToken).toHaveBeenCalledWith(
            'invalid-token',
          );
          expect(Object.keys(rpcContext)).toHaveLength(0);
          resolve();
        });
      });
    });
  });

  describe('runWithToken', () => {
    it('should execute task within AsyncLocalStorage context', async () => {
      let capturedToken: string | undefined;

      const result = await MicroserviceAuthInterceptor.runWithToken(
        'run-with-token',
        () => {
          capturedToken = MicroserviceAuthInterceptor.tokenStore.getStore();
          return Promise.resolve('task-result');
        },
      );

      expect(result).toBe('task-result');
      expect(capturedToken).toBe('run-with-token');
    });

    it('should isolate token contexts between concurrent calls', async () => {
      const results = await Promise.all([
        MicroserviceAuthInterceptor.runWithToken('token-a', () => {
          return Promise.resolve(
            MicroserviceAuthInterceptor.tokenStore.getStore(),
          );
        }),
        MicroserviceAuthInterceptor.runWithToken('token-b', () => {
          return Promise.resolve(
            MicroserviceAuthInterceptor.tokenStore.getStore(),
          );
        }),
      ]);

      expect(results).toEqual(['token-a', 'token-b']);
    });
  });

  describe('non-rpc type', () => {
    it('should pass through for unknown context type', (done) => {
      const context = {
        getType: () => 'graphql' as const,
      } as unknown as ExecutionContext;

      const next: CallHandler = {
        handle: () => of('result'),
      };

      interceptor.intercept(context, next).subscribe((result) => {
        expect(result).toBe('result');
        done();
      });
    });
  });
});
