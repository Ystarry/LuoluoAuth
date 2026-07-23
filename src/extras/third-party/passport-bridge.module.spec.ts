import { PassportBridgeModule } from './passport-bridge.module';
import { PassportBridgeController } from './passport-bridge.controller';
import type { PassportInstance, PassportStrategyLike } from './interfaces';

describe('PassportBridgeModule', () => {
  it('should register strategies on passport instance', () => {
    const passport = {
      use: jest.fn(),
      authenticate: jest.fn(),
    } as unknown as PassportInstance;

    const strategies: Record<string, PassportStrategyLike> = {
      github: { name: 'github' },
      google: { name: 'google' },
    };

    const dynamicModule = PassportBridgeModule.register({
      passport,
      strategies,
      loginHandler: jest.fn(),
    });

    expect(dynamicModule.module).toBe(PassportBridgeModule);
    expect(dynamicModule.controllers).toContain(PassportBridgeController);
    expect(passport.use).toHaveBeenCalledWith('github', strategies.github);
    expect(passport.use).toHaveBeenCalledWith('google', strategies.google);
    expect(dynamicModule.providers).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          provide: 'PASSPORT_INSTANCE',
          useValue: passport,
        }),
        expect.objectContaining({
          provide: 'PASSPORT_STRATEGIES',
          useValue: strategies,
        }),
        expect.objectContaining({
          provide: 'PASSPORT_LOGIN_HANDLER',
          useValue: expect.any(Function) as unknown,
        }),
      ]),
    );
  });
});
