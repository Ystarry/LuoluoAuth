import { extractBearerToken, extractTokenFromRpcContext } from './token.util';

describe('token.util', () => {
  describe('extractBearerToken', () => {
    it('should return token from Bearer header', () => {
      expect(extractBearerToken('Bearer abc123')).toBe('abc123');
    });

    it('should return undefined for non-Bearer header', () => {
      expect(extractBearerToken('Basic abc123')).toBeUndefined();
    });

    it('should return undefined for empty header', () => {
      expect(extractBearerToken(undefined)).toBeUndefined();
      expect(extractBearerToken('')).toBeUndefined();
    });
  });

  describe('extractTokenFromRpcContext', () => {
    it('should return undefined for falsy context', () => {
      expect(extractTokenFromRpcContext(null)).toBeUndefined();
      expect(extractTokenFromRpcContext(undefined)).toBeUndefined();
    });

    it('should extract token from gRPC metadata', () => {
      const metadata = {
        getMap: () => ({ authorization: 'Bearer grpc-token' }),
      };
      expect(extractTokenFromRpcContext(metadata)).toBe('grpc-token');
    });

    it('should extract raw authorization from gRPC metadata when not Bearer', () => {
      const metadata = {
        getMap: () => ({ authorization: 'raw-token' }),
      };
      expect(extractTokenFromRpcContext(metadata)).toBe('raw-token');
    });

    it('should extract token from plain object context', () => {
      expect(
        extractTokenFromRpcContext({ authorization: 'Bearer obj-token' }),
      ).toBe('obj-token');
    });

    it('should return undefined when no authorization present', () => {
      expect(extractTokenFromRpcContext({ other: 'value' })).toBeUndefined();
    });
  });
});
