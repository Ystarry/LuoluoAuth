import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException } from '@nestjs/common';
import { ThirdPartyAuthController } from './third-party-auth.controller';
import { OAuth2ClientService } from './oauth2-client.service';
import { AuthService } from '../../auth/auth.service';
import type { ThirdPartyLoginHandler, ThirdPartyUserInfo } from './interfaces';

describe('ThirdPartyAuthController', () => {
  let controller: ThirdPartyAuthController;
  let oauth2Client: jest.Mocked<OAuth2ClientService>;
  let authService: jest.Mocked<AuthService>;
  let loginHandler: jest.Mocked<ThirdPartyLoginHandler>;

  const mockUserInfo: ThirdPartyUserInfo = {
    provider: 'apple',
    providerUserId: 'apple-123',
    email: 'user@example.com',
    username: 'John Doe',
  };

  const mockRes = () => {
    const res: Record<string, unknown> = {};
    res.json = jest.fn().mockReturnValue(res);
    res.redirect = jest.fn().mockReturnValue(res);
    return res;
  };

  const mockReq = () =>
    ({
      ip: '127.0.0.1',
      headers: { 'user-agent': 'test-agent' },
    }) as unknown as import('express').Request;

  beforeEach(async () => {
    oauth2Client = {
      buildAuthorizationUrl: jest.fn(),
      handleCallback: jest.fn().mockResolvedValue(mockUserInfo),
    } as unknown as jest.Mocked<OAuth2ClientService>;

    authService = {
      login: jest.fn().mockResolvedValue('local-token'),
    } as unknown as jest.Mocked<AuthService>;

    loginHandler = jest.fn().mockResolvedValue({
      userId: 'local-123',
      roles: ['user'],
    });

    const module: TestingModule = await Test.createTestingModule({
      controllers: [ThirdPartyAuthController],
      providers: [
        { provide: OAuth2ClientService, useValue: oauth2Client },
        { provide: AuthService, useValue: authService },
        { provide: 'THIRD_PARTY_LOGIN_HANDLER', useValue: loginHandler },
      ],
    }).compile();

    controller = module.get<ThirdPartyAuthController>(ThirdPartyAuthController);
  });

  describe('login', () => {
    it('should redirect to authorization url', () => {
      oauth2Client.buildAuthorizationUrl.mockReturnValue(
        'https://appleid.apple.com/auth/authorize?client_id=foo',
      );
      const res = mockRes();

      controller.login('apple', res as unknown as import('express').Response);

      expect(oauth2Client.buildAuthorizationUrl).toHaveBeenCalledWith('apple');
      expect(res.redirect).toHaveBeenCalledWith(
        'https://appleid.apple.com/auth/authorize?client_id=foo',
      );
    });
  });

  describe('callbackGet', () => {
    it('should handle query callback', async () => {
      const req = mockReq();
      const res = mockRes();

      await controller.callbackGet(
        'apple',
        'code-123',
        'state-123',
        undefined,
        undefined,
        req,
        res as unknown as import('express').Response,
      );

      expect(oauth2Client.handleCallback).toHaveBeenCalledWith(
        'apple',
        'code-123',
        'state-123',
        undefined,
      );
      expect(loginHandler).toHaveBeenCalledWith(mockUserInfo, req, res);
      expect(authService.login).toHaveBeenCalledWith(
        'local-123',
        'apple',
        ['user'],
        undefined,
        '127.0.0.1',
        'test-agent',
        res,
      );
      expect(res.json).toHaveBeenCalledWith({
        token: 'local-token',
        provider: 'apple',
        userInfo: mockUserInfo,
      });
    });

    it('should throw BadRequestException when provider returns error', async () => {
      await expect(
        controller.callbackGet(
          'apple',
          'code-123',
          'state-123',
          'access_denied',
          'user denied',
          mockReq(),
          mockRes() as unknown as import('express').Response,
        ),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('callbackPost', () => {
    it('should handle form_post callback and merge body', async () => {
      const req = mockReq();
      const res = mockRes();
      const callbackBody = {
        user: JSON.stringify({ name: { firstName: 'John', lastName: 'Doe' } }),
      };

      await controller.callbackPost(
        'apple',
        'code-123',
        'state-123',
        undefined,
        undefined,
        callbackBody,
        req,
        res as unknown as import('express').Response,
      );

      expect(oauth2Client.handleCallback).toHaveBeenCalledWith(
        'apple',
        'code-123',
        'state-123',
        callbackBody,
      );
      expect(res.json).toHaveBeenCalledWith({
        token: 'local-token',
        provider: 'apple',
        userInfo: mockUserInfo,
      });
    });
  });
});
