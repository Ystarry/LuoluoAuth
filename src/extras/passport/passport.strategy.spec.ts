import { Test, TestingModule } from '@nestjs/testing';
import { PassportAuthStrategy } from './passport.strategy';
import type { PassportRequest } from './passport.strategy';
import { AuthService } from '../../auth/auth.service';

describe('PassportAuthStrategy', () => {
  let strategy: PassportAuthStrategy;
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
        PassportAuthStrategy,
      ],
    }).compile();

    strategy = module.get<PassportAuthStrategy>(PassportAuthStrategy);
    jest.clearAllMocks();
  });

  it('should validate token from Authorization header', async () => {
    const request: PassportRequest = {
      headers: { authorization: 'Bearer test-token' },
      ip: '127.0.0.1',
    };

    const result = await strategy.validate(request);
    expect(result).toEqual({
      userId: 'user-1',
      roles: ['user'],
      permissions: ['read'],
      token: 'test-token',
    });
  });

  it('should validate token from Cookie', async () => {
    const request: PassportRequest = {
      cookies: { token: 'cookie-token' },
      ip: '127.0.0.1',
    };

    const result = await strategy.validate(request);
    expect(result?.token).toBe('cookie-token');
  });

  it('should return null when no token is found', async () => {
    const request: PassportRequest = {};

    const result = await strategy.validate(request);
    expect(result).toBeNull();
  });

  it('should return null when token validation fails', async () => {
    const failingAuthService = {
      validateToken: jest.fn().mockRejectedValue(new Error('Invalid')),
    } as unknown as AuthService;

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        { provide: AuthService, useValue: failingAuthService },
        PassportAuthStrategy,
      ],
    }).compile();

    const failingStrategy =
      module.get<PassportAuthStrategy>(PassportAuthStrategy);

    const request: PassportRequest = {
      headers: { authorization: 'Bearer bad-token' },
    };

    const result = await failingStrategy.validate(request);
    expect(result).toBeNull();
  });

  it('should use custom cookie name from config', async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        { provide: AuthService, useValue: mockAuthService },
        {
          provide: 'PASSPORT_AUTH_CONFIG',
          useValue: { cookieName: 'my-auth' },
        },
        PassportAuthStrategy,
      ],
    }).compile();

    const configuredStrategy =
      module.get<PassportAuthStrategy>(PassportAuthStrategy);

    const request: PassportRequest = {
      cookies: { 'my-auth': 'custom-cookie-token' },
    };

    const result = await configuredStrategy.validate(request);
    expect(result?.token).toBe('custom-cookie-token');
  });

  it('should use custom token extractor', async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        { provide: AuthService, useValue: mockAuthService },
        {
          provide: 'PASSPORT_AUTH_CONFIG',
          useValue: {
            tokenExtractor: (req: PassportRequest) =>
              req.queryParams?.token as string,
          },
        },
        PassportAuthStrategy,
      ],
    }).compile();

    const configuredStrategy =
      module.get<PassportAuthStrategy>(PassportAuthStrategy);

    const request: PassportRequest = {
      queryParams: { token: 'query-token' },
    };

    const result = await configuredStrategy.validate(request);
    expect(result?.token).toBe('query-token');
  });

  it('should use custom IP extractor', async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        { provide: AuthService, useValue: mockAuthService },
        {
          provide: 'PASSPORT_AUTH_CONFIG',
          useValue: {
            extractIp: (req: PassportRequest) => req.xForwardedFor as string,
          },
        },
        PassportAuthStrategy,
      ],
    }).compile();

    const configuredStrategy =
      module.get<PassportAuthStrategy>(PassportAuthStrategy);

    const request: PassportRequest = {
      headers: { authorization: 'Bearer ip-token' },
      xForwardedFor: '10.0.0.1',
    };

    await configuredStrategy.validate(request);
    expect(mockAuthService.validateToken).toHaveBeenCalledWith(
      'ip-token',
      '10.0.0.1',
      undefined,
    );
  });

  it('should handle Authorization header with different casing', async () => {
    const request: PassportRequest = {
      headers: { Authorization: 'Bearer case-token' },
    };

    const result = await strategy.validate(request);
    expect(result?.token).toBe('case-token');
  });
});
