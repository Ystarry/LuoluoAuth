import { Test, TestingModule } from '@nestjs/testing';
import { SamlAuthModule } from './saml.module';
import { SamlService } from './saml.service';
import { SamlController } from './saml.controller';
import { AuthModule } from '../../../auth/auth.module';

describe('SamlAuthModule', () => {
  it('should register with IdP config and expose service/controller', async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [
        AuthModule.register({
          jwt: { secret: 'saml-test-secret', expiresIn: '1h' },
        }),
        SamlAuthModule.register({
          serviceProvider: {
            entityId: 'https://app.example.com/sp',
            assertEndpoint: 'https://app.example.com/auth/saml/okta/acs',
          },
          identityProviders: [
            {
              id: 'okta',
              name: 'Okta',
              ssoLoginUrl: 'https://okta.example.com/app/saml/sso',
            },
          ],
          loginHandler: (userInfo) =>
            Promise.resolve({
              userId: `saml_${userInfo.providerUserId}`,
              roles: ['user'],
            }),
        }),
      ],
    }).compile();

    expect(module.get(SamlService)).toBeDefined();
    expect(module.get(SamlController)).toBeDefined();
  });
});
