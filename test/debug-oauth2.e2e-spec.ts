import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import type { Server } from 'http';
import { AuthModule } from '../src/auth/auth.module';
import { OAuth2Module } from '../src/extras/oauth2/oauth2.module';
import {
  generateCodeVerifier,
  generateCodeChallenge,
} from '../src/extras/oauth2/pkce.util';

function httpRequest(app: INestApplication) {
  return request(app.getHttpServer() as Server);
}

// eslint-disable-next-line @typescript-eslint/require-await
const userValidator = async () => ({
  userId: 'demo-user',
  roles: ['user'],
  permissions: ['profile:read'],
});

describe('Debug OAuth2 (e2e)', () => {
  let app: INestApplication;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [
        AuthModule.register({
          jwt: {
            secret: 'e2e-oauth2-secret-with-enough-length',
            expiresIn: '1h',
          },
          auth: { tokenTtl: 3600000, loginPolicy: 'multiple' },
        }),
        OAuth2Module.register({
          clients: [
            {
              clientId: 'public-spa',
              redirectUris: ['http://localhost:3000/callback'],
              grants: ['authorization_code', 'refresh_token'],
              scopes: ['profile', 'openid'],
              isPublic: true,
            },
          ],
          userValidator,
          oidc: {
            issuer: 'http://localhost:3000',
            secret: 'e2e-oidc-secret-with-enough-length',
          },
        }),
      ],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  afterEach(async () => {
    await app.close();
  });

  it('prints authorize redirect location', async () => {
    const verifier = generateCodeVerifier();
    const challenge = generateCodeChallenge(verifier, 'S256');

    const authorizeRes = await httpRequest(app)
      .get('/oauth/authorize')
      .query({
        client_id: 'public-spa',
        redirect_uri: 'http://localhost:3000/callback',
        response_type: 'code',
        scope: 'profile openid',
        code_challenge: challenge,
        code_challenge_method: 'S256',
        nonce: 'test-nonce',
      })
      .expect(302);

    console.log('LOCATION:', authorizeRes.headers.location);
  });
});
