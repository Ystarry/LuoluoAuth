import type { Request, Response } from 'express';
import { CookieService } from './cookie.service';

/* eslint-disable @typescript-eslint/unbound-method */

describe('CookieService', () => {
  const createMockResponse = (): Response => {
    return {
      cookie: jest.fn(),
      clearCookie: jest.fn(),
    } as unknown as Response;
  };

  describe('default behavior', () => {
    it('should be disabled by default', () => {
      const service = new CookieService();
      expect(service.isEnabled()).toBe(false);
    });

    it('should read token from request cookies', () => {
      const service = new CookieService({ enabled: true, name: 'auth-token' });
      const req = {
        cookies: { 'auth-token': 'token-123' },
      } as unknown as Request;

      expect(service.read(req)).toBe('token-123');
    });

    it('should return undefined when cookie is missing', () => {
      const service = new CookieService({ enabled: true, name: 'auth-token' });
      const req = { cookies: {} } as unknown as Request;

      expect(service.read(req)).toBeUndefined();
    });

    it('should return undefined when cookies object is missing', () => {
      const service = new CookieService({ enabled: true, name: 'auth-token' });
      const req = {} as unknown as Request;

      expect(service.read(req)).toBeUndefined();
    });
  });

  describe('write', () => {
    it('should write token with default options', () => {
      const service = new CookieService({ enabled: true });
      const res = createMockResponse();

      service.write(res, 'token-123');

      expect(res.cookie).toHaveBeenCalledWith(
        'auth-token',
        'token-123',
        expect.objectContaining({
          path: '/',
          httpOnly: true,
          secure: false,
          sameSite: 'lax',
          maxAge: 7 * 24 * 60 * 60 * 1000,
        }),
      );
    });

    it('should use custom maxAge in seconds', () => {
      const service = new CookieService({ enabled: true, maxAge: 3600 });
      const res = createMockResponse();

      service.write(res, 'token-123');

      expect(res.cookie).toHaveBeenCalledWith(
        'auth-token',
        'token-123',
        expect.objectContaining({ maxAge: 3600 * 1000 }),
      );
    });

    it('should override maxAge when provided', () => {
      const service = new CookieService({ enabled: true, maxAge: 3600 });
      const res = createMockResponse();

      service.write(res, 'token-123', 60);

      expect(res.cookie).toHaveBeenCalledWith(
        'auth-token',
        'token-123',
        expect.objectContaining({ maxAge: 60 * 1000 }),
      );
    });

    it('should include domain when configured', () => {
      const service = new CookieService({
        enabled: true,
        domain: '.example.com',
      });
      const res = createMockResponse();

      service.write(res, 'token-123');

      expect(res.cookie).toHaveBeenCalledWith(
        'auth-token',
        'token-123',
        expect.objectContaining({ domain: '.example.com' }),
      );
    });
  });

  describe('clear', () => {
    it('should clear cookie with configured options', () => {
      const service = new CookieService({
        enabled: true,
        name: 'auth-token',
        domain: '.example.com',
        path: '/api',
      });
      const res = createMockResponse();

      service.clear(res);

      expect(res.clearCookie).toHaveBeenCalledWith('auth-token', {
        domain: '.example.com',
        path: '/api',
      });
    });
  });
});
