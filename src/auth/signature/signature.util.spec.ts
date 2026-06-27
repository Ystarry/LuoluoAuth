import {
  generateSignature,
  verifySignature,
  isTimestampValid,
} from './signature.util';

describe('signature.util', () => {
  const secret = 'test-secret';

  describe('generateSignature', () => {
    it('should generate consistent signature for same payload', () => {
      const payload = {
        method: 'POST',
        path: '/api/users',
        timestamp: 1700000000000,
        nonce: 'abc123',
        body: '{"name":"test"}',
      };

      const sig1 = generateSignature(payload, secret);
      const sig2 = generateSignature(payload, secret);

      expect(sig1).toBe(sig2);
      expect(typeof sig1).toBe('string');
      expect(sig1.length).toBeGreaterThan(0);
    });

    it('should generate different signatures for different payloads', () => {
      const payload1 = {
        method: 'POST',
        path: '/api/users',
        timestamp: 1700000000000,
        nonce: 'abc123',
      };
      const payload2 = {
        method: 'GET',
        path: '/api/users',
        timestamp: 1700000000000,
        nonce: 'abc123',
      };

      const sig1 = generateSignature(payload1, secret);
      const sig2 = generateSignature(payload2, secret);

      expect(sig1).not.toBe(sig2);
    });
  });

  describe('verifySignature', () => {
    it('should return true for valid signature', () => {
      const payload = {
        method: 'POST',
        path: '/api/users',
        timestamp: 1700000000000,
        nonce: 'abc123',
      };

      const signature = generateSignature(payload, secret);
      expect(verifySignature(payload, signature, secret)).toBe(true);
    });

    it('should return false for invalid signature', () => {
      const payload = {
        method: 'POST',
        path: '/api/users',
        timestamp: 1700000000000,
        nonce: 'abc123',
      };

      expect(verifySignature(payload, 'invalid-sig', secret)).toBe(false);
    });

    it('should return false for wrong secret', () => {
      const payload = {
        method: 'POST',
        path: '/api/users',
        timestamp: 1700000000000,
        nonce: 'abc123',
      };

      const signature = generateSignature(payload, secret);
      expect(verifySignature(payload, signature, 'wrong-secret')).toBe(false);
    });
  });

  describe('isTimestampValid', () => {
    it('should return true for current timestamp', () => {
      expect(isTimestampValid(Date.now())).toBe(true);
    });

    it('should return false for expired timestamp', () => {
      const oldTimestamp = Date.now() - 10 * 60 * 1000; // 10 minutes ago
      expect(isTimestampValid(oldTimestamp, 5 * 60 * 1000)).toBe(false);
    });

    it('should return true for timestamp within tolerance', () => {
      const recentTimestamp = Date.now() - 2 * 60 * 1000; // 2 minutes ago
      expect(isTimestampValid(recentTimestamp, 5 * 60 * 1000)).toBe(true);
    });
  });
});
