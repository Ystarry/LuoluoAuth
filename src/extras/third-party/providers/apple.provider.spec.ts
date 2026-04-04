import { createAppleProvider } from './apple.provider';
import { verify } from 'jsonwebtoken';

const applePrivateKey = `-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIBXDRNGLLGkDi2WfKhfsAJ3FSKgb0/BI1Q9LM8rxN9ohoAcGBSuBBAAK
oUQDQgAEX5nA4q7PF1VV2AaDE3i9d2Kbb1W0rQYh6KX3gRQ8tlAqW3f9y2RqNF1+
X0qjA2XGotXt9Sf3n3K0pT9xXm0FkQ==
-----END EC PRIVATE KEY-----`;

describe('createAppleProvider', () => {
  it('should create Apple provider config with form_post response mode', () => {
    const provider = createAppleProvider({
      clientId: 'com.example.app',
      teamId: 'TEAM123',
      keyId: 'KEY456',
      privateKey: applePrivateKey,
      redirectUri: 'https://app.example.com/auth/third-party/apple/callback',
    });

    expect(provider.id).toBe('apple');
    expect(provider.responseMode).toBe('form_post');
    expect(provider.scopes).toEqual(['name', 'email']);
    expect(provider.authorizationEndpoint).toBe(
      'https://appleid.apple.com/auth/authorize',
    );
    expect(provider.tokenEndpoint).toBe(
      'https://appleid.apple.com/auth/token',
    );
  });

  it('should generate a valid client_secret JWT', async () => {
    const provider = createAppleProvider({
      clientId: 'com.example.app',
      teamId: 'TEAM123',
      keyId: 'KEY456',
      privateKey: applePrivateKey,
      redirectUri: 'https://app.example.com/auth/third-party/apple/callback',
    });

    const clientSecret = await provider.clientSecretGenerator!();
    const decoded = verify(clientSecret, applePrivateKey, {
      algorithms: ['ES256'],
    }) as Record<string, unknown>;

    expect(decoded.iss).toBe('TEAM123');
    expect(decoded.aud).toBe('https://appleid.apple.com');
    expect(decoded.sub).toBe('com.example.app');
    expect(decoded.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  it('should extract username from callback body on first login', () => {
    const provider = createAppleProvider({
      clientId: 'com.example.app',
      teamId: 'TEAM123',
      keyId: 'KEY456',
      privateKey: applePrivateKey,
      redirectUri: 'https://app.example.com/auth/third-party/apple/callback',
    });

    const extra = provider.callbackBodyExtractor!({
      user: JSON.stringify({
        name: { firstName: 'John', lastName: 'Doe' },
        email: 'john@example.com',
      }),
    });

    expect(extra.username).toBe('John Doe');
  });

  it('should handle callback body without user info', () => {
    const provider = createAppleProvider({
      clientId: 'com.example.app',
      teamId: 'TEAM123',
      keyId: 'KEY456',
      privateKey: applePrivateKey,
      redirectUri: 'https://app.example.com/auth/third-party/apple/callback',
    });

    const extra = provider.callbackBodyExtractor!({});
    expect(extra.username).toBeUndefined();
  });
});
