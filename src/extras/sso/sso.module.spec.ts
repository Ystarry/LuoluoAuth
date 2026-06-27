import { SsoModule } from './sso.module';
import { SsoService } from './sso.service';

describe('SsoModule', () => {
  describe('register', () => {
    it('should create a dynamic module with default config', () => {
      const module = SsoModule.register();

      expect(module.module).toBe(SsoModule);
      expect(module.imports).toBeDefined();
      expect(module.exports).toEqual([SsoService]);

      const configProvider = module.providers?.find(
        (p) =>
          typeof p === 'object' &&
          'provide' in p &&
          (p as Record<string, unknown>).provide === 'SSO_CONFIG',
      );
      expect(configProvider).toBeDefined();
      expect((configProvider as Record<string, unknown>).useValue).toEqual({});
    });

    it('should create a dynamic module with custom config', () => {
      const config = {
        ssoServer: 'http://sso.example.com',
        appId: 'my-app',
        appSecret: 'my-secret',
      };
      const module = SsoModule.register(config);

      const configProvider = module.providers?.find(
        (p) =>
          typeof p === 'object' &&
          'provide' in p &&
          (p as Record<string, unknown>).provide === 'SSO_CONFIG',
      );
      expect(configProvider).toBeDefined();
      expect((configProvider as Record<string, unknown>).useValue).toBe(config);
    });

    it('should include SsoService in providers', () => {
      const module = SsoModule.register();

      const ssoProvider = module.providers?.find((p) => p === SsoService);
      expect(ssoProvider).toBe(SsoService);
    });
  });
});
