import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException, UnauthorizedException } from '@nestjs/common';
import type { Request, Response } from 'express';
import { OAuth2Controller, OAUTH2_CLIENT_STORE } from './oauth2.controller';
import { InMemoryOAuth2ClientStore } from './client-store';
import { AuthService } from '../../auth/auth.service';
import { generateCodeChallenge, generateCodeVerifier } from './pkce.util';
import { OidcService } from './oidc.service';
import { OidcController } from './oidc.controller';

describe('OAuth2Controller', () => {
  let controller: OAuth2Controller;
  let store: InMemoryOAuth2ClientStore;
  let rateLimiter: { allow: jest.Mock; clear: jest.Mock };
  let oidcService: OidcService;

  const mockAuthService = {
    login: jest.fn().mockResolvedValue('access-token-jwt'),
    validateToken: jest.fn().mockResolvedValue({
      userId: 'user-1',
      roles: ['user'],
      permissions: ['read'],
    }),
  };

  const mockUserValidator = jest.fn().mockResolvedValue({ userId: 'user-1' });

  beforeEach(async () => {
    store = new InMemoryOAuth2ClientStore();
    store.registerClient({
      clientId: 'client-1',
      clientSecret: 'secret-1',
      redirectUris: ['http://localhost/callback'],
      grants: [
        'authorization_code',
        'password',
        'client_credentials',
        'refresh_token',
      ],
    });
    store.registerClient({
      clientId: 'public-client',
      clientSecret: '',
      redirectUris: ['http://localhost/callback'],
      grants: ['authorization_code', 'refresh_token'],
      isPublic: true,
    });

    rateLimiter = {
      allow: jest.fn().mockResolvedValue(true),
      clear: jest.fn().mockResolvedValue(undefined),
    };

    oidcService = new OidcService({
      issuer: 'http://localhost:3000',
      secret: 'oidc-secret-change-me',
      idTokenExpiresIn: 3600,
    });

    const module: TestingModule = await Test.createTestingModule({
      controllers: [OAuth2Controller],
      providers: [
        {
          provide: AuthService,
          useValue: mockAuthService,
        },
        {
          provide: OAUTH2_CLIENT_STORE,
          useValue: store,
        },
        {
          provide: 'OAUTH2_USER_VALIDATOR',
          useValue: mockUserValidator,
        },
        {
          provide: 'RATE_LIMITER',
          useValue: rateLimiter,
        },
        {
          provide: OidcService,
          useValue: oidcService,
        },
        {
          provide: 'OAUTH2_AUTHORIZE_CONFIG',
          useValue: { authCheckMode: 'header' },
        },
      ],
    }).compile();

    controller = module.get<OAuth2Controller>(OAuth2Controller);

    jest.clearAllMocks();
  });

  describe('token', () => {
    it('should issue token for password grant', async () => {
      const req = {
        ip: '127.0.0.1',
        headers: { 'user-agent': 'test-ua' },
        body: {
          grant_type: 'password',
          client_id: 'client-1',
          client_secret: 'secret-1',
          username: 'user',
          password: 'pass',
        },
      } as unknown as Request;

      const token = await controller.token(req);

      expect(token.accessToken).toBe('access-token-jwt');
      expect(token.tokenType).toBe('Bearer');
      expect(rateLimiter.allow).toHaveBeenCalledWith({
        ip: '127.0.0.1',
        action: 'oauth2:password',
      });
    });

    it('should throw 429 for password grant when rate limit exceeded', async () => {
      rateLimiter.allow.mockResolvedValueOnce(false);

      const req = {
        ip: '127.0.0.1',
        headers: { 'user-agent': 'test-ua' },
        body: {
          grant_type: 'password',
          client_id: 'client-1',
          client_secret: 'secret-1',
          username: 'user',
          password: 'pass',
        },
      } as unknown as Request;

      await expect(controller.token(req)).rejects.toMatchObject({
        status: 429,
      });
    });

    it('should issue token for refresh_token grant', async () => {
      store.saveToken(
        {
          accessToken: 'old-access',
          refreshToken: 'old-refresh',
          tokenType: 'Bearer',
          expiresIn: 3600,
          userId: 'user-1',
        },
        'family-1',
      );

      const req = {
        ip: '127.0.0.1',
        headers: { 'user-agent': 'test-ua' },
        body: {
          grant_type: 'refresh_token',
          client_id: 'client-1',
          client_secret: 'secret-1',
          refresh_token: 'old-refresh',
        },
      } as unknown as Request;

      const token = await controller.token(req);

      expect(token.accessToken).toBe('access-token-jwt');
      expect(rateLimiter.allow).toHaveBeenCalledWith({
        ip: '127.0.0.1',
        action: 'oauth2:refresh',
      });
    });

    it('should throw 429 for refresh_token grant when rate limit exceeded', async () => {
      rateLimiter.allow.mockResolvedValueOnce(false);

      const req = {
        ip: '127.0.0.1',
        headers: { 'user-agent': 'test-ua' },
        body: {
          grant_type: 'refresh_token',
          client_id: 'client-1',
          client_secret: 'secret-1',
          refresh_token: 'old-refresh',
        },
      } as unknown as Request;

      await expect(controller.token(req)).rejects.toMatchObject({
        status: 429,
      });
    });

    it('should reject invalid client_id', async () => {
      const req = {
        ip: '127.0.0.1',
        headers: {},
        body: {
          grant_type: 'password',
          client_id: 'unknown',
          client_secret: 'secret-1',
        },
      } as unknown as Request;

      await expect(controller.token(req)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should reject unsupported grant_type', async () => {
      const req = {
        ip: '127.0.0.1',
        headers: {},
        body: {
          grant_type: 'unknown',
          client_id: 'client-1',
          client_secret: 'secret-1',
        },
      } as unknown as Request;

      await expect(controller.token(req)).rejects.toThrow(BadRequestException);
    });
  });

  describe('authorize', () => {
    it('should redirect with authorization code when authenticated', async () => {
      const res = {
        redirect: jest.fn(),
      } as unknown as Response;

      await controller.authorize(
        {
          response_type: 'code',
          client_id: 'client-1',
          redirect_uri: 'http://localhost/callback',
          state: 'state-1',
        },
        {
          headers: { authorization: 'Bearer valid-token' },
          ip: '127.0.0.1',
          originalUrl: '/oauth/authorize?response_type=code',
          protocol: 'http',
        } as unknown as Request,
        res,
      );

      const redirectMock = res.redirect as jest.Mock;
      expect(redirectMock).toHaveBeenCalled();
      const callArgs = redirectMock.mock.calls[0] as string[];
      const redirectUrl = new URL(callArgs[0]);
      expect(redirectUrl.searchParams.get('code')).toBeTruthy();
      expect(redirectUrl.searchParams.get('state')).toBe('state-1');
      expect(mockAuthService.validateToken).toHaveBeenCalledWith(
        'valid-token',
        '127.0.0.1',
        undefined,
      );
    });

    it('should redirect to login when user is not authenticated in redirect mode', async () => {
      const res = {
        redirect: jest.fn(),
      } as unknown as Response;

      const moduleWithRedirect = await Test.createTestingModule({
        controllers: [OAuth2Controller],
        providers: [
          {
            provide: AuthService,
            useValue: mockAuthService,
          },
          {
            provide: OAUTH2_CLIENT_STORE,
            useValue: store,
          },
          {
            provide: 'OAUTH2_USER_VALIDATOR',
            useValue: mockUserValidator,
          },
          {
            provide: 'RATE_LIMITER',
            useValue: rateLimiter,
          },
          {
            provide: OidcService,
            useValue: oidcService,
          },
          {
            provide: 'OAUTH2_AUTHORIZE_CONFIG',
            useValue: { authCheckMode: 'redirect', loginUrl: '/custom/login' },
          },
        ],
      }).compile();

      const redirectController =
        moduleWithRedirect.get<OAuth2Controller>(OAuth2Controller);

      await redirectController.authorize(
        {
          response_type: 'code',
          client_id: 'client-1',
          redirect_uri: 'http://localhost/callback',
          state: 'state-1',
        },
        {
          headers: {},
          ip: '127.0.0.1',
          originalUrl: '/oauth/authorize?response_type=code',
          protocol: 'http',
        } as unknown as Request,
        res,
      );

      const redirectMock = res.redirect as jest.Mock;
      expect(redirectMock).toHaveBeenCalled();
      const callArgs = redirectMock.mock.calls[0] as string[];
      const redirectUrl = new URL(callArgs[0], 'http://localhost');
      expect(redirectUrl.pathname).toBe('/custom/login');
      expect(redirectUrl.searchParams.get('redirect_uri')).toContain(
        '/oauth/authorize',
      );
      expect(redirectUrl.searchParams.get('oauth_state')).toBe('state-1');
    });

    it('should reject unauthenticated user in header mode', async () => {
      const res = {
        redirect: jest.fn(),
      } as unknown as Response;

      await expect(
        controller.authorize(
          {
            response_type: 'code',
            client_id: 'client-1',
            redirect_uri: 'http://localhost/callback',
            state: 'state-1',
          },
          {
            headers: {},
            ip: '127.0.0.1',
            originalUrl: '/oauth/authorize?response_type=code',
            protocol: 'http',
          } as unknown as Request,
          res,
        ),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('PKCE flow', () => {
    it('should require code_challenge for public clients on authorize', async () => {
      const res = {
        redirect: jest.fn(),
      } as unknown as Response;

      await expect(
        controller.authorize(
          {
            response_type: 'code',
            client_id: 'public-client',
            redirect_uri: 'http://localhost/callback',
          },
          {
            headers: { authorization: 'Bearer valid-token' },
            ip: '127.0.0.1',
            originalUrl: '/oauth/authorize?response_type=code',
            protocol: 'http',
          } as unknown as Request,
          res,
        ),
      ).rejects.toThrow(BadRequestException);
    });

    it('should issue token for public client with valid PKCE verifier', async () => {
      const verifier = generateCodeVerifier(43);
      const challenge = generateCodeChallenge(verifier, 'S256');

      const res = {
        redirect: jest.fn(),
      } as unknown as Response;

      await controller.authorize(
        {
          response_type: 'code',
          client_id: 'public-client',
          redirect_uri: 'http://localhost/callback',
          code_challenge: challenge,
        },
        {
          headers: { authorization: 'Bearer valid-token' },
          ip: '127.0.0.1',
          originalUrl: '/oauth/authorize?response_type=code',
          protocol: 'http',
        } as unknown as Request,
        res,
      );

      const redirectMock = res.redirect as jest.Mock;
      const redirectUrl = new URL((redirectMock.mock.calls[0] as string[])[0]);
      const code = redirectUrl.searchParams.get('code')!;

      const req = {
        ip: '127.0.0.1',
        headers: { 'user-agent': 'test-ua' },
        body: {
          grant_type: 'authorization_code',
          client_id: 'public-client',
          code,
          redirect_uri: 'http://localhost/callback',
          code_verifier: verifier,
        },
      } as unknown as Request;

      const token = await controller.token(req);

      expect(token.accessToken).toBe('access-token-jwt');
      expect(token.tokenType).toBe('Bearer');
    });

    it('should reject public client token request without PKCE', async () => {
      const res = {
        redirect: jest.fn(),
      } as unknown as Response;

      await controller.authorize(
        {
          response_type: 'code',
          client_id: 'public-client',
          redirect_uri: 'http://localhost/callback',
          code_challenge: generateCodeChallenge(generateCodeVerifier(43)),
        },
        {
          headers: { authorization: 'Bearer valid-token' },
          ip: '127.0.0.1',
          originalUrl: '/oauth/authorize?response_type=code',
          protocol: 'http',
        } as unknown as Request,
        res,
      );

      const redirectMock = res.redirect as jest.Mock;
      const redirectUrl = new URL((redirectMock.mock.calls[0] as string[])[0]);
      const code = redirectUrl.searchParams.get('code')!;

      const req = {
        ip: '127.0.0.1',
        headers: {},
        body: {
          grant_type: 'authorization_code',
          client_id: 'public-client',
          code,
          redirect_uri: 'http://localhost/callback',
        },
      } as unknown as Request;

      await expect(controller.token(req)).rejects.toThrow(BadRequestException);
    });

    it('should reject invalid PKCE verifier', async () => {
      const challenge = generateCodeChallenge(generateCodeVerifier(43));

      const res = {
        redirect: jest.fn(),
      } as unknown as Response;

      await controller.authorize(
        {
          response_type: 'code',
          client_id: 'public-client',
          redirect_uri: 'http://localhost/callback',
          code_challenge: challenge,
        },
        {
          headers: { authorization: 'Bearer valid-token' },
          ip: '127.0.0.1',
          originalUrl: '/oauth/authorize?response_type=code',
          protocol: 'http',
        } as unknown as Request,
        res,
      );

      const redirectMock = res.redirect as jest.Mock;
      const redirectUrl = new URL((redirectMock.mock.calls[0] as string[])[0]);
      const code = redirectUrl.searchParams.get('code')!;

      const req = {
        ip: '127.0.0.1',
        headers: {},
        body: {
          grant_type: 'authorization_code',
          client_id: 'public-client',
          code,
          redirect_uri: 'http://localhost/callback',
          code_verifier: 'wrong-verifier',
        },
      } as unknown as Request;

      await expect(controller.token(req)).rejects.toThrow(BadRequestException);
    });

    it('should allow confidential client without PKCE', async () => {
      const res = {
        redirect: jest.fn(),
      } as unknown as Response;

      await controller.authorize(
        {
          response_type: 'code',
          client_id: 'client-1',
          redirect_uri: 'http://localhost/callback',
        },
        {
          headers: { authorization: 'Bearer valid-token' },
          ip: '127.0.0.1',
          originalUrl: '/oauth/authorize?response_type=code',
          protocol: 'http',
        } as unknown as Request,
        res,
      );

      const redirectMock = res.redirect as jest.Mock;
      const redirectUrl = new URL((redirectMock.mock.calls[0] as string[])[0]);
      const code = redirectUrl.searchParams.get('code')!;

      const req = {
        ip: '127.0.0.1',
        headers: {},
        body: {
          grant_type: 'authorization_code',
          client_id: 'client-1',
          client_secret: 'secret-1',
          code,
          redirect_uri: 'http://localhost/callback',
        },
      } as unknown as Request;

      const token = await controller.token(req);

      expect(token.accessToken).toBe('access-token-jwt');
    });
  });

  describe('userinfo', () => {
    it('should return user info for valid token', async () => {
      store.saveToken({
        accessToken: 'access-token-jwt',
        refreshToken: 'refresh',
        tokenType: 'Bearer',
        expiresIn: 3600,
        userId: 'user-1',
      });

      const req = {
        headers: {
          authorization: 'Bearer access-token-jwt',
        },
      } as unknown as Request;

      const info = await controller.userinfo(req);
      expect(info.sub).toBe('user-1');
    });

    it('should reject missing authorization header', async () => {
      const req = { headers: {} } as unknown as Request;
      await expect(controller.userinfo(req)).rejects.toThrow(
        UnauthorizedException,
      );
    });
  });

  describe('OIDC', () => {
    it('should issue id_token for authorization_code with openid scope', async () => {
      const res = {
        redirect: jest.fn(),
      } as unknown as Response;

      await controller.authorize(
        {
          response_type: 'code',
          client_id: 'client-1',
          redirect_uri: 'http://localhost/callback',
          scope: 'openid profile',
          nonce: 'nonce-123',
        },
        {
          headers: { authorization: 'Bearer valid-token' },
          ip: '127.0.0.1',
          originalUrl: '/oauth/authorize?response_type=code',
          protocol: 'http',
        } as unknown as Request,
        res,
      );

      const redirectMock = res.redirect as jest.Mock;
      const redirectUrl = new URL((redirectMock.mock.calls[0] as string[])[0]);
      const code = redirectUrl.searchParams.get('code')!;

      const req = {
        ip: '127.0.0.1',
        headers: {},
        body: {
          grant_type: 'authorization_code',
          client_id: 'client-1',
          client_secret: 'secret-1',
          code,
          redirect_uri: 'http://localhost/callback',
        },
      } as unknown as Request;

      const token = await controller.token(req);

      expect(token.idToken).toBeDefined();
      const payload = oidcService.verifyIdToken(token.idToken!);
      expect(payload.sub).toBe('user-1');
      expect(payload.aud).toBe('client-1');
      expect(payload.nonce).toBe('nonce-123');
      expect(payload.iss).toBe('http://localhost:3000');
    });

    it('should issue id_token for password grant with openid scope', async () => {
      const req = {
        ip: '127.0.0.1',
        headers: { 'user-agent': 'test-ua' },
        body: {
          grant_type: 'password',
          client_id: 'client-1',
          client_secret: 'secret-1',
          username: 'user',
          password: 'pass',
          scope: 'openid',
        },
      } as unknown as Request;

      const token = await controller.token(req);

      expect(token.idToken).toBeDefined();
      const payload = oidcService.verifyIdToken(token.idToken!);
      expect(payload.sub).toBe('user-1');
      expect(payload.aud).toBe('client-1');
    });

    it('should not issue id_token for client_credentials grant', async () => {
      const req = {
        ip: '127.0.0.1',
        headers: {},
        body: {
          grant_type: 'client_credentials',
          client_id: 'client-1',
          client_secret: 'secret-1',
          scope: 'openid',
        },
      } as unknown as Request;

      const token = await controller.token(req);

      expect(token.idToken).toBeUndefined();
    });

    it('should not issue id_token without openid scope', async () => {
      const req = {
        ip: '127.0.0.1',
        headers: { 'user-agent': 'test-ua' },
        body: {
          grant_type: 'password',
          client_id: 'client-1',
          client_secret: 'secret-1',
          username: 'user',
          password: 'pass',
          scope: 'profile',
        },
      } as unknown as Request;

      const token = await controller.token(req);

      expect(token.idToken).toBeUndefined();
    });
  });

  describe('authorize - error paths', () => {
    it('should reject unsupported response_type', async () => {
      const res = { redirect: jest.fn() } as unknown as Response;

      await expect(
        controller.authorize(
          {
            response_type: 'token',
            client_id: 'client-1',
            redirect_uri: 'http://localhost/callback',
          },
          { headers: {}, ip: '127.0.0.1' } as unknown as Request,
          res,
        ),
      ).rejects.toThrow(BadRequestException);
    });

    it('should reject invalid client_id', async () => {
      const res = { redirect: jest.fn() } as unknown as Response;

      await expect(
        controller.authorize(
          {
            response_type: 'code',
            client_id: 'unknown-client',
            redirect_uri: 'http://localhost/callback',
          },
          { headers: {}, ip: '127.0.0.1' } as unknown as Request,
          res,
        ),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should reject invalid redirect_uri', async () => {
      const res = { redirect: jest.fn() } as unknown as Response;

      await expect(
        controller.authorize(
          {
            response_type: 'code',
            client_id: 'client-1',
            redirect_uri: 'http://evil.com/callback',
          },
          { headers: {}, ip: '127.0.0.1' } as unknown as Request,
          res,
        ),
      ).rejects.toThrow(BadRequestException);
    });

    it('should reject unsupported grant type for client', async () => {
      store.registerClient({
        clientId: 'no-auth-code-client',
        clientSecret: 'secret',
        redirectUris: ['http://localhost/callback'],
        grants: ['password'],
      });

      const res = { redirect: jest.fn() } as unknown as Response;

      await expect(
        controller.authorize(
          {
            response_type: 'code',
            client_id: 'no-auth-code-client',
            redirect_uri: 'http://localhost/callback',
          },
          { headers: {}, ip: '127.0.0.1' } as unknown as Request,
          res,
        ),
      ).rejects.toThrow(BadRequestException);
    });

    it('should reject unsupported code_challenge_method', async () => {
      const res = { redirect: jest.fn() } as unknown as Response;

      await expect(
        controller.authorize(
          {
            response_type: 'code',
            client_id: 'client-1',
            redirect_uri: 'http://localhost/callback',
            code_challenge: 'some-challenge',
            code_challenge_method: 'SHA512',
          },
          {
            headers: { authorization: 'Bearer valid-token' },
            ip: '127.0.0.1',
            originalUrl: '/oauth/authorize',
            protocol: 'http',
          } as unknown as Request,
          res,
        ),
      ).rejects.toThrow(BadRequestException);
    });

    it('should extract token from cookie when mode is cookie', async () => {
      const moduleWithCookie = await Test.createTestingModule({
        controllers: [OAuth2Controller],
        providers: [
          { provide: AuthService, useValue: mockAuthService },
          { provide: OAUTH2_CLIENT_STORE, useValue: store },
          { provide: 'OAUTH2_USER_VALIDATOR', useValue: mockUserValidator },
          { provide: 'RATE_LIMITER', useValue: rateLimiter },
          { provide: OidcService, useValue: oidcService },
          {
            provide: 'OAUTH2_AUTHORIZE_CONFIG',
            useValue: {
              authCheckMode: 'cookie',
              cookieName: 'my-token',
            },
          },
        ],
      }).compile();

      const cookieController =
        moduleWithCookie.get<OAuth2Controller>(OAuth2Controller);

      const res = { redirect: jest.fn() } as unknown as Response;

      await cookieController.authorize(
        {
          response_type: 'code',
          client_id: 'client-1',
          redirect_uri: 'http://localhost/callback',
        },
        {
          headers: {},
          cookies: { 'my-token': 'cookie-token-value' },
          ip: '127.0.0.1',
          originalUrl: '/oauth/authorize',
          protocol: 'http',
        } as unknown as Request,
        res,
      );

      expect(mockAuthService.validateToken).toHaveBeenCalledWith(
        'cookie-token-value',
        '127.0.0.1',
        undefined,
      );
    });
  });

  describe('token - error paths', () => {
    it('should reject invalid client_secret', async () => {
      const req = {
        ip: '127.0.0.1',
        headers: {},
        body: {
          grant_type: 'password',
          client_id: 'client-1',
          client_secret: 'wrong-secret',
          username: 'user',
          password: 'pass',
        },
      } as unknown as Request;

      await expect(controller.token(req)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should reject authorization_code without code parameter', async () => {
      const req = {
        ip: '127.0.0.1',
        headers: {},
        body: {
          grant_type: 'authorization_code',
          client_id: 'client-1',
          client_secret: 'secret-1',
          redirect_uri: 'http://localhost/callback',
        },
      } as unknown as Request;

      await expect(controller.token(req)).rejects.toThrow(BadRequestException);
    });

    it('should reject invalid or expired authorization code', async () => {
      const req = {
        ip: '127.0.0.1',
        headers: {},
        body: {
          grant_type: 'authorization_code',
          client_id: 'client-1',
          client_secret: 'secret-1',
          code: 'non-existent-code',
          redirect_uri: 'http://localhost/callback',
        },
      } as unknown as Request;

      await expect(controller.token(req)).rejects.toThrow(BadRequestException);
    });

    it('should reject client ID mismatch in authorization_code', async () => {
      const res = {
        redirect: jest.fn(),
      } as unknown as Response;

      await controller.authorize(
        {
          response_type: 'code',
          client_id: 'client-1',
          redirect_uri: 'http://localhost/callback',
        },
        {
          headers: { authorization: 'Bearer valid-token' },
          ip: '127.0.0.1',
          originalUrl: '/oauth/authorize',
          protocol: 'http',
        } as unknown as Request,
        res,
      );

      const redirectMock = res.redirect as jest.Mock;
      const redirectUrl = new URL((redirectMock.mock.calls[0] as string[])[0]);
      const code = redirectUrl.searchParams.get('code')!;

      const req = {
        ip: '127.0.0.1',
        headers: {},
        body: {
          grant_type: 'authorization_code',
          client_id: 'public-client',
          code,
          redirect_uri: 'http://localhost/callback',
        },
      } as unknown as Request;

      await expect(controller.token(req)).rejects.toThrow(BadRequestException);
    });

    it('should reject redirect URI mismatch in authorization_code', async () => {
      const res = {
        redirect: jest.fn(),
      } as unknown as Response;

      await controller.authorize(
        {
          response_type: 'code',
          client_id: 'client-1',
          redirect_uri: 'http://localhost/callback',
        },
        {
          headers: { authorization: 'Bearer valid-token' },
          ip: '127.0.0.1',
          originalUrl: '/oauth/authorize',
          protocol: 'http',
        } as unknown as Request,
        res,
      );

      const redirectMock = res.redirect as jest.Mock;
      const redirectUrl = new URL((redirectMock.mock.calls[0] as string[])[0]);
      const code = redirectUrl.searchParams.get('code')!;

      const req = {
        ip: '127.0.0.1',
        headers: {},
        body: {
          grant_type: 'authorization_code',
          client_id: 'client-1',
          client_secret: 'secret-1',
          code,
          redirect_uri: 'http://evil.com/callback',
        },
      } as unknown as Request;

      await expect(controller.token(req)).rejects.toThrow(BadRequestException);
    });

    it('should reject password grant without userValidator', async () => {
      const moduleWithoutValidator = await Test.createTestingModule({
        controllers: [OAuth2Controller],
        providers: [
          { provide: AuthService, useValue: mockAuthService },
          { provide: OAUTH2_CLIENT_STORE, useValue: store },
          { provide: 'RATE_LIMITER', useValue: rateLimiter },
          { provide: OidcService, useValue: oidcService },
          {
            provide: 'OAUTH2_AUTHORIZE_CONFIG',
            useValue: { authCheckMode: 'header' },
          },
        ],
      }).compile();

      const noValidatorController =
        moduleWithoutValidator.get<OAuth2Controller>(OAuth2Controller);

      const req = {
        ip: '127.0.0.1',
        headers: {},
        body: {
          grant_type: 'password',
          client_id: 'client-1',
          client_secret: 'secret-1',
          username: 'user',
          password: 'pass',
        },
      } as unknown as Request;

      await expect(noValidatorController.token(req)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should reject password grant with missing username', async () => {
      const req = {
        ip: '127.0.0.1',
        headers: {},
        body: {
          grant_type: 'password',
          client_id: 'client-1',
          client_secret: 'secret-1',
          username: '',
          password: 'pass',
        },
      } as unknown as Request;

      await expect(controller.token(req)).rejects.toThrow(BadRequestException);
    });

    it('should reject password grant with invalid credentials', async () => {
      mockUserValidator.mockResolvedValueOnce(null);

      const req = {
        ip: '127.0.0.1',
        headers: {},
        body: {
          grant_type: 'password',
          client_id: 'client-1',
          client_secret: 'secret-1',
          username: 'bad',
          password: 'wrong',
        },
      } as unknown as Request;

      await expect(controller.token(req)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should reject refresh_token without refresh_token parameter', async () => {
      const req = {
        ip: '127.0.0.1',
        headers: {},
        body: {
          grant_type: 'refresh_token',
          client_id: 'client-1',
          client_secret: 'secret-1',
        },
      } as unknown as Request;

      await expect(controller.token(req)).rejects.toThrow(BadRequestException);
    });

    it('should reject invalid or expired refresh token', async () => {
      const req = {
        ip: '127.0.0.1',
        headers: {},
        body: {
          grant_type: 'refresh_token',
          client_id: 'client-1',
          client_secret: 'secret-1',
          refresh_token: 'non-existent-refresh',
        },
      } as unknown as Request;

      await expect(controller.token(req)).rejects.toThrow(BadRequestException);
    });

    it('should reject refresh token reuse', async () => {
      store.saveToken(
        {
          accessToken: 'old-access',
          refreshToken: 'used-refresh',
          tokenType: 'Bearer',
          expiresIn: 3600,
          userId: 'user-1',
        },
        'family-1',
      );

      // Consume the refresh token first
      store.consumeRefreshToken('used-refresh');

      const req = {
        ip: '127.0.0.1',
        headers: {},
        body: {
          grant_type: 'refresh_token',
          client_id: 'client-1',
          client_secret: 'secret-1',
          refresh_token: 'used-refresh',
        },
      } as unknown as Request;

      await expect(controller.token(req)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should issue token for client_credentials grant', async () => {
      const req = {
        ip: '127.0.0.1',
        headers: {},
        body: {
          grant_type: 'client_credentials',
          client_id: 'client-1',
          client_secret: 'secret-1',
        },
      } as unknown as Request;

      const token = await controller.token(req);
      expect(token.tokenType).toBe('Bearer');
      expect(token.expiresIn).toBe(3600);
    });
  });

  describe('userinfo - error paths', () => {
    it('should reject invalid authorization header format', async () => {
      const req = {
        headers: {
          authorization: 'InvalidFormat',
        },
      } as unknown as Request;

      await expect(controller.userinfo(req)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should reject invalid access token', async () => {
      const req = {
        headers: {
          authorization: 'Bearer non-existent-token',
        },
      } as unknown as Request;

      await expect(controller.userinfo(req)).rejects.toThrow(
        UnauthorizedException,
      );
    });
  });

  describe('OidcController', () => {
    it('should return discovery metadata', () => {
      const oidcController = new OidcController(oidcService);
      const metadata = oidcController.discovery();

      expect(metadata.issuer).toBe('http://localhost:3000');
      expect(metadata.authorization_endpoint).toBe(
        'http://localhost:3000/oauth/authorize',
      );
      expect(metadata.token_endpoint).toBe('http://localhost:3000/oauth/token');
      expect(metadata.userinfo_endpoint).toBe(
        'http://localhost:3000/oauth/userinfo',
      );
      expect(metadata.id_token_signing_alg_values_supported).toContain('HS256');
    });
  });
});
