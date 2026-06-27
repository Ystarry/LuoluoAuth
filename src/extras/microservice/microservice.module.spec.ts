import { MicroserviceModule } from './microservice.module';
import { MicroserviceAuthInterceptor } from './auth.interceptor';

describe('MicroserviceModule', () => {
  describe('register', () => {
    it('should create a dynamic module with default options', () => {
      const module = MicroserviceModule.register();

      expect(module.module).toBe(MicroserviceModule);
      expect(module.imports).toBeDefined();
      expect(module.providers).toBeDefined();
      expect(module.exports).toEqual([MicroserviceAuthInterceptor]);

      const interceptorProvider = module.providers?.find(
        (p) => p === MicroserviceAuthInterceptor,
      );
      expect(interceptorProvider).toBe(MicroserviceAuthInterceptor);
    });

    it('should create a dynamic module with custom token resolver', () => {
      const resolver = jest.fn();
      const module = MicroserviceModule.register({ tokenResolver: resolver });

      const resolverProvider = module.providers?.find(
        (p) =>
          typeof p === 'object' &&
          'provide' in p &&
          (p as Record<string, unknown>).provide === 'RPC_TOKEN_RESOLVER',
      );
      expect(resolverProvider).toBeDefined();
      expect((resolverProvider as Record<string, unknown>).useValue).toBe(
        resolver,
      );
    });

    it('should create a dynamic module with interceptor config', () => {
      const config = { validateToken: true };
      const module = MicroserviceModule.register({ interceptorConfig: config });

      const configProvider = module.providers?.find(
        (p) =>
          typeof p === 'object' &&
          'provide' in p &&
          (p as Record<string, unknown>).provide ===
            'RPC_AUTH_INTERCEPTOR_CONFIG',
      );
      expect(configProvider).toBeDefined();
      expect((configProvider as Record<string, unknown>).useValue).toBe(config);
    });

    it('should create a dynamic module with both options', () => {
      const resolver = jest.fn();
      const config = { validateToken: false };
      const module = MicroserviceModule.register({
        tokenResolver: resolver,
        interceptorConfig: config,
      });

      expect(module.providers).toHaveLength(3);
      expect(module.exports).toEqual([MicroserviceAuthInterceptor]);
    });
  });
});
