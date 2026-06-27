import { ExecutionContext, ForbiddenException } from '@nestjs/common';
import type { Request, Response } from 'express';
import { SignatureGuard } from './signature.guard';
import { generateSignature } from './signature.util';
import { MemoryNonceStore } from './nonce-store';

describe('SignatureGuard', () => {
  const secret = 'test-secret';

  const createRequest = (
    headers: Record<string, string>,
    body?: unknown,
  ): Request => {
    return {
      method: 'POST',
      originalUrl: '/api/test',
      url: '/api/test',
      headers,
      body,
    } as unknown as Request;
  };

  const createContext = (request: Request): ExecutionContext => {
    return {
      switchToHttp: () => ({
        getRequest: () => request,
        getResponse: () => ({}) as Response,
      }),
    } as unknown as ExecutionContext;
  };

  const buildHeaders = (
    nonce: string,
    timestamp = Date.now(),
    body?: unknown,
  ): Record<string, string> => {
    const payload = {
      method: 'POST',
      path: '/api/test',
      timestamp,
      nonce,
      body: body ? JSON.stringify(body) : undefined,
    };
    return {
      'x-signature': generateSignature(payload, secret),
      'x-timestamp': String(timestamp),
      'x-nonce': nonce,
    };
  };

  it('should allow valid request with memory nonce store', async () => {
    const nonceStore = new MemoryNonceStore();
    const guard = new SignatureGuard(
      { secret, timestampTolerance: 60000 },
      nonceStore,
    );
    const request = createRequest(buildHeaders('nonce-1'));

    await expect(guard.canActivate(createContext(request))).resolves.toBe(true);
    expect(await nonceStore.has('nonce-1')).toBe(true);
  });

  it('should reject duplicate nonce', async () => {
    const nonceStore = new MemoryNonceStore();
    const guard = new SignatureGuard(
      { secret, timestampTolerance: 60000 },
      nonceStore,
    );
    const request = createRequest(buildHeaders('nonce-1'));

    await guard.canActivate(createContext(request));
    await expect(
      guard.canActivate(createContext(request)),
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('should reject missing signature headers', async () => {
    const guard = new SignatureGuard(
      { secret, timestampTolerance: 60000 },
      new MemoryNonceStore(),
    );
    const request = createRequest({});

    await expect(guard.canActivate(createContext(request))).rejects.toThrow(
      ForbiddenException,
    );
  });

  it('should reject expired timestamp', async () => {
    const guard = new SignatureGuard(
      { secret, timestampTolerance: 1000 },
      new MemoryNonceStore(),
    );
    const request = createRequest(buildHeaders('nonce-1', Date.now() - 2000));

    await expect(guard.canActivate(createContext(request))).rejects.toThrow(
      ForbiddenException,
    );
  });

  it('should reject invalid signature', async () => {
    const guard = new SignatureGuard(
      { secret, timestampTolerance: 60000 },
      new MemoryNonceStore(),
    );
    const request = createRequest({
      'x-signature': 'invalid',
      'x-timestamp': String(Date.now()),
      'x-nonce': 'nonce-1',
    });

    await expect(guard.canActivate(createContext(request))).rejects.toThrow(
      ForbiddenException,
    );
  });

  it('should allow request when nonce store is undefined', async () => {
    const guard = new SignatureGuard(
      { secret, timestampTolerance: 60000 },
      undefined,
    );
    const request = createRequest(buildHeaders('nonce-1'));

    await expect(guard.canActivate(createContext(request))).resolves.toBe(true);
  });
});
