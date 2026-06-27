import { Module } from '@nestjs/common';
import { AuthModule, OAuth2Module } from 'luoluo-auth';
import { UserModule } from './user/user.module';

@Module({
  imports: [
    AuthModule.register({
      jwt: {
        secret: 'sample-app-secret-must-be-at-least-32-characters-long',
        expiresIn: '1h',
      },
      auth: {
        tokenTtl: 3600000,
        loginPolicy: 'multiple',
        autoRenew: true,
        maxSameDeviceSessions: 3,
        rememberMeTtl: 30 * 24 * 60 * 60 * 1000,
        fingerprint: {
          enabled: false,
          strict: false,
        },
        distributedLock: {
          enabled: true,
          ttlMs: 5000,
          retries: 3,
          retryDelayMs: 50,
        },
        multiAccount: {
          enabled: true,
          maxAccounts: 3,
        },
      },
      rateLimit: {
        enabled: false,
        windowSeconds: 60,
        maxRequests: 100,
      },
      cookie: {
        enabled: true,
        name: 'sample-auth-token',
        path: '/',
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        maxAge: 3600,
      },
      audit: {
        enabled: true,
        storage: 'console',
      },
    }),
    OAuth2Module.register({
      clients: [
        {
          clientId: 'sample-public-client',
          clientSecret: '',
          redirectUris: ['http://localhost:3100/oauth/callback'],
          grants: ['authorization_code', 'refresh_token'],
          scopes: ['profile', 'openid'],
          isPublic: true,
        },
        {
          clientId: 'sample-confidential-client',
          clientSecret: 'sample-confidential-secret',
          redirectUris: ['http://localhost:3100/oauth/callback'],
          grants: [
            'authorization_code',
            'password',
            'client_credentials',
            'refresh_token',
          ],
          scopes: ['profile', 'openid', 'email'],
        },
      ],
      // eslint-disable-next-line @typescript-eslint/require-await
      userValidator: async (username, password) => {
        if (username === 'alice' && password === 'secret') {
          return {
            userId: 'user-alice',
            roles: ['user'],
            permissions: ['profile:read', 'profile:write'],
          };
        }
        if (username === 'admin' && password === 'admin') {
          return {
            userId: 'user-admin',
            roles: ['admin'],
            permissions: ['*'],
          };
        }
        return null;
      },
      oidc: {
        issuer: 'http://localhost:3100',
        secret: 'sample-oidc-secret-must-be-at-least-32-characters-long',
      },
    }),
    UserModule,
  ],
})
export class AppModule {}
