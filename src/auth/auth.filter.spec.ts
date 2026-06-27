import {
  ArgumentsHost,
  BadRequestException,
  UnauthorizedException,
} from '@nestjs/common';
import type { Response, Request } from 'express';
import { AuthExceptionFilter } from './auth.filter';
import { AuthException } from './errors/auth.exception';
import { AuthErrorCode } from './errors/auth-error-code';

/* eslint-disable @typescript-eslint/unbound-method */

describe('AuthExceptionFilter', () => {
  let filter: AuthExceptionFilter;

  const createMockHost = (
    headers: Record<string, string> = {},
  ): ArgumentsHost => {
    const json = jest.fn();
    const status = jest.fn().mockReturnValue({ json });
    const response = { status } as unknown as Response;
    const request = {
      url: '/test',
      headers,
    } as unknown as Request;

    return {
      switchToHttp: () => ({
        getResponse: () => response,
        getRequest: () => request,
      }),
    } as unknown as ArgumentsHost;
  };

  const getResponseBody = (host: ArgumentsHost): Record<string, unknown> => {
    const response = host.switchToHttp().getResponse<Response>();
    const statusMock = response.status as jest.Mock;
    const jsonValue = statusMock.mock.results[0].value as { json: jest.Mock };
    const callArgs = jsonValue.json.mock.calls[0] as Record<string, unknown>[];
    return callArgs[0];
  };

  beforeEach(() => {
    filter = new AuthExceptionFilter();
  });

  it('should handle AuthException with business code and Chinese message', () => {
    const host = createMockHost();
    const exception = new AuthException(
      AuthErrorCode.TOKEN_EXPIRED,
      401,
      'Token expired',
    );

    filter.catch(exception, host);

    const response = host.switchToHttp().getResponse<Response>();
    expect(response.status).toHaveBeenCalledWith(401);
    const body = getResponseBody(host);
    expect(body.code).toBe(AuthErrorCode.TOKEN_EXPIRED);
    expect(body.message).toBe('令牌已过期');
    expect(body.path).toBe('/test');
    expect(body.timestamp).toBeDefined();
  });

  it('should use English message when Accept-Language starts with en', () => {
    const host = createMockHost({ 'accept-language': 'en-US,en;q=0.9' });
    const exception = new AuthException(AuthErrorCode.FORBIDDEN, 403);

    filter.catch(exception, host);

    const body = getResponseBody(host);
    expect(body.message).toBe('Forbidden, insufficient permissions');
  });

  it('should map UnauthorizedException to UNAUTHORIZED code', () => {
    const host = createMockHost();
    const exception = new UnauthorizedException('Missing token');

    filter.catch(exception, host);

    const response = host.switchToHttp().getResponse<Response>();
    expect(response.status).toHaveBeenCalledWith(401);
    const body = getResponseBody(host);
    expect(body.code).toBe(AuthErrorCode.UNAUTHORIZED);
    expect(body.message).toBe('Missing token');
  });

  it('should map BadRequestException to BAD_REQUEST code', () => {
    const host = createMockHost();
    const exception = new BadRequestException('Invalid params');

    filter.catch(exception, host);

    const response = host.switchToHttp().getResponse<Response>();
    expect(response.status).toHaveBeenCalledWith(400);
    const body = getResponseBody(host);
    expect(body.code).toBe(AuthErrorCode.BAD_REQUEST);
  });
});
