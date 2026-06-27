import {
  generateCodeChallenge,
  generateCodeVerifier,
  verifyCodeVerifier,
} from './pkce.util';

describe('PKCE utils', () => {
  it('should generate a code verifier of specified length', () => {
    const verifier = generateCodeVerifier(43);
    expect(verifier.length).toBe(43);
    expect(/^[A-Za-z0-9\-_]+$/.test(verifier)).toBe(true);
  });

  it('should generate S256 challenge correctly', () => {
    const verifier = 'test-verifier';
    const challenge = generateCodeChallenge(verifier, 'S256');
    // expected base64url(sha256('test-verifier'))
    expect(challenge).toBe('JBbiqONGWPaAmwXk_8bT6UnlPfrn65D32eZlJS-zGG0');
  });

  it('plain challenge should equal verifier', () => {
    const verifier = 'plain-verifier';
    expect(generateCodeChallenge(verifier, 'plain')).toBe(verifier);
  });

  it('should verify S256 challenge', () => {
    const verifier = generateCodeVerifier(43);
    const challenge = generateCodeChallenge(verifier, 'S256');
    expect(verifyCodeVerifier(verifier, challenge, 'S256')).toBe(true);
  });

  it('should reject invalid verifier', () => {
    const verifier = generateCodeVerifier(43);
    const challenge = generateCodeChallenge(verifier, 'S256');
    expect(verifyCodeVerifier('wrong-verifier', challenge, 'S256')).toBe(false);
  });

  it('should verify plain challenge', () => {
    const verifier = 'plain-verifier';
    expect(verifyCodeVerifier(verifier, verifier, 'plain')).toBe(true);
  });
});
