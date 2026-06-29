import { Test, TestingModule } from '@nestjs/testing';
import { SsoService } from './sso.service';
import { AuthService } from '../../auth/auth.service';

describe('SsoService', () => {
  let service: SsoService;

  const mockAuthService = {
    validateToken: jest.fn().mockResolvedValue({
      userId: 'user-1',
      roles: ['user'],
      permissions: ['read'],
    }),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        {
          provide: AuthService,
          useValue: mockAuthService,
        },
        {
          provide: 'SSO_CONFIG',
          useValue: {
            loginUrl: 'http://sso.example.com/login',
            tokenParamName: 'token',
          },
        },
        SsoService,
      ],
    }).compile();

    service = module.get<SsoService>(SsoService);
    jest.clearAllMocks();
  });

  describe('buildRedirectFormData', () => {
    it('should build SSO redirect form data without exposing token in URL', () => {
      const result = service.buildRedirectFormData(
        'http://client.example.com/callback',
        'access-token',
      );

      expect(result.url).toBe('http://sso.example.com/login');
      expect(result.fields.redirect_uri).toBe(
        'http://client.example.com/callback',
      );
      expect(result.fields.token).toBe('access-token');
    });
  });

  describe('buildRedirectUrl', () => {
    it('should build SSO redirect URL with token (deprecated)', () => {
      const url = service.buildRedirectUrl(
        'http://client.example.com/callback',
        'access-token',
      );

      expect(url).toContain('http://sso.example.com/login');
      expect(url).toContain(
        'redirect_uri=' +
          encodeURIComponent('http://client.example.com/callback'),
      );
      expect(url).toContain('token=access-token');
    });
  });

  describe('handleCallback', () => {
    it('should return user info from local token when no handler is configured', async () => {
      const info = await service.handleCallback({ code: 'valid-token' });

      expect(info.userId).toBe('user-1');
      expect(info.username).toBe('user-1');
      expect(info.roles).toEqual(['user']);
      expect(info.permissions).toEqual(['read']);
      expect(mockAuthService.validateToken).toHaveBeenCalledWith('valid-token');
    });

    it('should use codeExchangeHandler when configured', async () => {
      const moduleWithHandler: TestingModule = await Test.createTestingModule({
        providers: [
          {
            provide: AuthService,
            useValue: mockAuthService,
          },
          {
            provide: 'SSO_CONFIG',
            useValue: {
              codeExchangeHandler: jest.fn().mockResolvedValue({
                userId: 'external-user',
                username: 'External User',
                roles: ['admin'],
                permissions: ['write'],
              }),
            },
          },
          SsoService,
        ],
      }).compile();

      const serviceWithHandler = moduleWithHandler.get<SsoService>(SsoService);
      const info = await serviceWithHandler.handleCallback({
        code: 'auth-code',
        state: 'state-1',
      });

      expect(info.userId).toBe('external-user');
      expect(info.username).toBe('External User');
      expect(info.roles).toEqual(['admin']);
      expect(info.permissions).toEqual(['write']);
      expect(mockAuthService.validateToken).not.toHaveBeenCalled();
    });

    it('should throw error for SSO authorization error', async () => {
      await expect(
        service.handleCallback({
          error: 'access_denied',
          error_description: 'User denied access',
        }),
      ).rejects.toThrow('access_denied');
    });

    it('should throw error when code is missing', async () => {
      await expect(service.handleCallback({})).rejects.toThrow(
        'Missing authorization code',
      );
    });

    it('should throw error when handler returns invalid userId', async () => {
      const moduleWithHandler: TestingModule = await Test.createTestingModule({
        providers: [
          {
            provide: AuthService,
            useValue: mockAuthService,
          },
          {
            provide: 'SSO_CONFIG',
            useValue: {
              codeExchangeHandler: jest.fn().mockResolvedValue({
                userId: '',
              }),
            },
          },
          SsoService,
        ],
      }).compile();

      const serviceWithHandler = moduleWithHandler.get<SsoService>(SsoService);
      await expect(
        serviceWithHandler.handleCallback({ code: 'auth-code' }),
      ).rejects.toThrow('did not return a valid userId');
    });
  });

  describe('extractTokenFromRequest', () => {
    it('should extract token from header', () => {
      const req = {
        headers: { authorization: 'Bearer header-token' },
        cookies: {},
        query: {},
      } as unknown as Request;

      expect(service.extractTokenFromRequest(req)).toBe('header-token');
    });

    it('should extract token from query', () => {
      const req = {
        headers: {},
        cookies: {},
        query: { token: 'query-token' },
      } as unknown as Request;

      expect(service.extractTokenFromRequest(req)).toBe('query-token');
    });

    it('should extract token from cookie', () => {
      const req = {
        headers: {},
        cookies: { token: 'cookie-token' },
        query: {},
      } as unknown as Request;

      expect(service.extractTokenFromRequest(req)).toBe('cookie-token');
    });
  });
});
