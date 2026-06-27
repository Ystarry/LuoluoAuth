import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import type { Server } from 'http';
import { AuthModule } from '../src/auth/auth.module';
import { AuthService } from '../src/auth/auth.service';
import { OAuth2Module } from '../src/extras/oauth2/oauth2.module';
import {
  generateCodeVerifier,
  generateCodeChallenge,
} from '../src/extras/oauth2/pkce.util';
import type { UserValidator } from '../src/extras/oauth2/client-store';

function httpRequest(app: INestApplication) {
  return request(app.getHttpServer() as Server);
}

interface TokenResponse {
  accessToken: string;
  refreshToken: string;
  idToken?: string;
  tokenType: string;
}

interface DiscoveryResponse {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
}

interface UserInfoResponse {
  sub: string;
}

// eslint-disable-next-line @typescript-eslint/require-await
const userValidator: UserValidator = async (username, password) => {
  if (username === 'alice' && password === 'secret') {
    return {
      userId: 'user-alice',
      roles: ['user'],
      permissions: ['profile:read'],
    };
  }
  return null;
};

describe('OAuth2Module (e2e)', () => {
  let app: INestApplication;
  let authService: AuthService;

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
            {
              clientId: 'confidential-app',
              clientSecret: 'app-secret',
              redirectUris: ['http://localhost:3000/callback'],
              grants: ['authorization_code'],
              scopes: ['profile'],
            },
          ],
          userValidator,
          oidc: {
            issuer: 'http://localhost:3000',
            secret: 'e2e-oidc-secret-with-enough-length',
          },
          authorize: {
            authCheckMode: 'header',
          },
        }),
      ],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();

    authService = moduleFixture.get<AuthService>(AuthService);
  });

  afterEach(async () => {
    await app.close();
  });

  it('/oauth/authorize (GET) - public client requires code_challenge', async () => {
    return httpRequest(app)
      .get('/oauth/authorize')
      .query({
        client_id: 'public-spa',
        redirect_uri: 'http://localhost:3000/callback',
        response_type: 'code',
        scope: 'profile',
      })
      .expect(400);
  });

  it('/oauth/authorize + /oauth/token - public client with PKCE and openid scope', async () => {
    const loginToken = await authService.login(
      'demo-user',
      'test-device',
      ['user'],
      ['profile:read'],
    );

    const verifier = generateCodeVerifier();
    const challenge = generateCodeChallenge(verifier, 'S256');

    const authorizeRes = await httpRequest(app)
      .get('/oauth/authorize')
      .set('Authorization', `Bearer ${loginToken}`)
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

    const location = authorizeRes.headers.location;
    const code = new URLSearchParams(location.split('?')[1]).get('code');
    expect(code).toBeTruthy();

    const tokenRes = await httpRequest(app)
      .post('/oauth/token')
      .send({
        grant_type: 'authorization_code',
        client_id: 'public-spa',
        code,
        redirect_uri: 'http://localhost:3000/callback',
        code_verifier: verifier,
      })
      .expect(201);

    const tokenBody = tokenRes.body as TokenResponse;
    expect(tokenBody.accessToken).toBeTruthy();
    expect(tokenBody.refreshToken).toBeTruthy();
    expect(tokenBody.idToken).toBeTruthy();
    expect(tokenBody.tokenType).toBe('Bearer');

    const userinfoRes = await httpRequest(app)
      .get('/oauth/userinfo')
      .set('Authorization', `Bearer ${tokenBody.accessToken}`)
      .expect(200);

    expect((userinfoRes.body as UserInfoResponse).sub).toBe('demo-user');
  });

  it('/oauth/token (password) - confidential client authenticates and refreshes', async () => {
    const tokenRes = await httpRequest(app)
      .post('/oauth/token')
      .send({
        grant_type: 'password',
        client_id: 'confidential-app',
        client_secret: 'app-secret',
        username: 'alice',
        password: 'secret',
        scope: 'profile',
      })
      .expect(201);

    const tokenBody = tokenRes.body as TokenResponse;
    expect(tokenBody.accessToken).toBeTruthy();
    expect(tokenBody.refreshToken).toBeTruthy();

    const refreshRes = await httpRequest(app)
      .post('/oauth/token')
      .send({
        grant_type: 'refresh_token',
        client_id: 'confidential-app',
        client_secret: 'app-secret',
        refresh_token: tokenBody.refreshToken,
      })
      .expect(201);

    const refreshBody = refreshRes.body as TokenResponse;
    expect(refreshBody.accessToken).toBeTruthy();
    expect(refreshBody.refreshToken).toBeTruthy();
  });

  it('/oauth/token (password) - rejects invalid credentials', async () => {
    return httpRequest(app)
      .post('/oauth/token')
      .send({
        grant_type: 'password',
        client_id: 'confidential-app',
        client_secret: 'app-secret',
        username: 'alice',
        password: 'wrong',
      })
      .expect(401);
  });

  it('/.well-known/openid-configuration - returns discovery metadata', async () => {
    const res = await httpRequest(app)
      .get('/.well-known/openid-configuration')
      .expect(200);
    const body = res.body as DiscoveryResponse;
    expect(body.issuer).toBe('http://localhost:3000');
    expect(body.authorization_endpoint).toContain('/oauth/authorize');
    expect(body.token_endpoint).toContain('/oauth/token');
  });
});
