import { Test, TestingModule } from '@nestjs/testing';
import { ThirdPartyAuthModule } from './third-party-auth.module';
import { OAuth2ClientService } from './oauth2-client.service';
import { ThirdPartyAuthController } from './third-party-auth.controller';
import { AuthModule } from '../../auth/auth.module';
import { createGoogleProvider } from './providers';

describe('ThirdPartyAuthModule', () => {
  it('should register with providers and expose service/controller', async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [
        AuthModule.register({
          jwt: { secret: 'third-party-test-secret', expiresIn: '1h' },
        }),
        ThirdPartyAuthModule.register({
          stateSecret: 'state-secret',
          providers: [
            createGoogleProvider({
              clientId: 'google-client-id',
              clientSecret: 'google-client-secret',
              redirectUri: 'https://app.example.com/auth/google/callback',
            }),
          ],
          loginHandler: (userInfo) =>
            Promise.resolve({
              userId: `google_${userInfo.providerUserId}`,
              roles: ['user'],
            }),
        }),
      ],
    }).compile();

    expect(module.get(OAuth2ClientService)).toBeDefined();
    expect(module.get(ThirdPartyAuthController)).toBeDefined();
  });
});
