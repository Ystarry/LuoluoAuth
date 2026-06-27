import { plainToInstance } from 'class-transformer';
import { validateSync } from 'class-validator';
import { AuthFrameworkConfig, defaultConfig } from './auth.config';

describe('AuthFrameworkConfig validation', () => {
  it('should validate default config without errors', () => {
    const config = plainToInstance(AuthFrameworkConfig, defaultConfig);
    const errors = validateSync(config);
    expect(errors).toHaveLength(0);
  });

  it('should accept valid custom config', () => {
    const config = plainToInstance(AuthFrameworkConfig, {
      token: {
        secret: 'my-secret',
        expiresIn: '1h',
      },
      storage: {
        useRedis: true,
        maxSize: 1000,
      },
      rateLimit: {
        enabled: true,
        strategy: 'sliding-window',
        keyType: 'ip-user',
        windowSeconds: 60,
        maxRequests: 10,
      },
    });
    const errors = validateSync(config);
    expect(errors).toHaveLength(0);
  });

  it('should reject invalid login policy', () => {
    const config = plainToInstance(AuthFrameworkConfig, {
      loginPolicy: {
        policy: 'invalid-policy',
      },
    });
    const errors = validateSync(config);
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0].property).toBe('loginPolicy');
    const nested = errors[0].children?.[0];
    expect(nested?.property).toBe('policy');
  });

  it('should reject negative windowSeconds', () => {
    const config = plainToInstance(AuthFrameworkConfig, {
      rateLimit: {
        enabled: true,
        windowSeconds: -1,
        maxRequests: 10,
      },
    });
    const errors = validateSync(config);
    expect(errors.length).toBeGreaterThan(0);
    const nested = errors[0].children?.[0];
    expect(nested?.property).toBe('windowSeconds');
  });

  it('should reject invalid tokenStrategy item', () => {
    const config = plainToInstance(AuthFrameworkConfig, {
      sso: {
        enabled: true,
        tokenStrategy: ['header', 'body'],
      },
    });
    const errors = validateSync(config);
    expect(errors.length).toBeGreaterThan(0);
    const nested = errors[0].children?.[0];
    expect(nested?.property).toBe('tokenStrategy');
  });

  it('should reject string value for boolean field', () => {
    const config = plainToInstance(AuthFrameworkConfig, {
      permission: {
        enabled: 'yes',
      },
    });
    const errors = validateSync(config);
    expect(errors.length).toBeGreaterThan(0);
    const nested = errors[0].children?.[0];
    expect(nested?.property).toBe('enabled');
  });

  it('should reject invalid storage maxSize', () => {
    const config = plainToInstance(AuthFrameworkConfig, {
      storage: {
        maxSize: -10,
      },
    });
    const errors = validateSync(config);
    expect(errors.length).toBeGreaterThan(0);
    const nested = errors[0].children?.[0];
    expect(nested?.property).toBe('maxSize');
  });

  it('should reject invalid maxSameDeviceSessions', () => {
    const config = plainToInstance(AuthFrameworkConfig, {
      loginPolicy: {
        maxSameDeviceSessions: 0,
      },
    });
    const errors = validateSync(config);
    expect(errors.length).toBeGreaterThan(0);
    const nested = errors[0].children?.[0];
    expect(nested?.property).toBe('maxSameDeviceSessions');
  });

  it('should accept valid multiAccount config', () => {
    const config = plainToInstance(AuthFrameworkConfig, {
      multiAccount: {
        enabled: true,
        maxAccounts: 3,
      },
    });
    const errors = validateSync(config);
    expect(errors).toHaveLength(0);
  });

  it('should reject invalid multiAccount maxAccounts', () => {
    const config = plainToInstance(AuthFrameworkConfig, {
      multiAccount: {
        enabled: true,
        maxAccounts: 0,
      },
    });
    const errors = validateSync(config);
    expect(errors.length).toBeGreaterThan(0);
    const nested = errors[0].children?.[0];
    expect(nested?.property).toBe('maxAccounts');
  });
});
