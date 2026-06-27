import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import type { Server } from 'http';
import { Controller, Get, Post, Req, Res } from '@nestjs/common';
import type { Request, Response } from 'express';
import { AuthModule } from '../src/auth/auth.module';
import { AuthService } from '../src/auth/auth.service';
import { AuthGuard } from '../src/auth/auth.guard';
import {
  RequireLogin,
  RequireRoles,
  RequirePermissions,
  RequireSafeAuth,
} from '../src/auth/auth.decorator';

@Controller('test')
class TestController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  async login() {
    const token = await this.authService.login(
      'user-1',
      'web',
      ['user'],
      ['user:add'],
    );
    return { token };
  }

  @Get('public')
  publicRoute() {
    return { message: 'public' };
  }

  @Get('protected')
  @RequireLogin()
  protectedRoute() {
    return { message: 'protected' };
  }

  @Get('admin')
  @RequireRoles('admin')
  adminRoute() {
    return { message: 'admin' };
  }

  @Get('user-add')
  @RequirePermissions('user:add')
  userAddRoute() {
    return { message: 'user-add' };
  }

  @Get('safe')
  @RequireSafeAuth()
  safeRoute() {
    return { message: 'safe' };
  }

  @Post('logout')
  @RequireLogin()
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const authHeader = req.headers.authorization;
    const token = authHeader?.replace('Bearer ', '') ?? '';
    await this.authService.logout(token, res);
    return { message: 'logged out' };
  }
}

function httpRequest(app: INestApplication) {
  return request(app.getHttpServer() as Server);
}

describe('AuthModule (e2e)', () => {
  let app: INestApplication;
  let authService: AuthService;
  let token: string;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [
        AuthModule.register({
          jwt: {
            secret: 'e2e-test-secret-with-enough-length',
            expiresIn: '1h',
          },
          auth: { tokenTtl: 3600000, loginPolicy: 'multiple' },
        }),
      ],
      controllers: [TestController],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalGuards(app.get(AuthGuard));
    await app.init();

    authService = moduleFixture.get<AuthService>(AuthService);

    // Login to get token
    const loginRes = await httpRequest(app).post('/test/login').expect(201);
    token = (loginRes.body as { token: string }).token;
  });

  afterEach(async () => {
    await app.close();
  });

  it('/test/public (GET) - should be accessible without token', () => {
    return httpRequest(app)
      .get('/test/public')
      .expect(200)
      .expect({ message: 'public' });
  });

  it('/test/protected (GET) - should reject without token', () => {
    return httpRequest(app).get('/test/protected').expect(401);
  });

  it('/test/protected (GET) - should allow with valid token', () => {
    return httpRequest(app)
      .get('/test/protected')
      .set('Authorization', `Bearer ${token}`)
      .expect(200)
      .expect({ message: 'protected' });
  });

  it('/test/admin (GET) - should reject without admin role', () => {
    return httpRequest(app)
      .get('/test/admin')
      .set('Authorization', `Bearer ${token}`)
      .expect(403);
  });

  it('/test/user-add (GET) - should allow with matching permission', () => {
    return httpRequest(app)
      .get('/test/user-add')
      .set('Authorization', `Bearer ${token}`)
      .expect(200)
      .expect({ message: 'user-add' });
  });

  it('/test/safe (GET) - should reject without safe auth', () => {
    return httpRequest(app)
      .get('/test/safe')
      .set('Authorization', `Bearer ${token}`)
      .expect(403);
  });

  it('/test/safe (GET) - should allow after opening safe auth', async () => {
    // Open safe auth
    const payload = await authService['tokenStrategy'].verify(token);
    await authService.openSafeAuth(payload.sessionId);

    return httpRequest(app)
      .get('/test/safe')
      .set('Authorization', `Bearer ${token}`)
      .expect(200)
      .expect({ message: 'safe' });
  });

  it('/test/logout (POST) - should invalidate token after logout', async () => {
    await httpRequest(app)
      .post('/test/logout')
      .set('Authorization', `Bearer ${token}`)
      .expect(201)
      .expect({ message: 'logged out' });

    return httpRequest(app)
      .get('/test/protected')
      .set('Authorization', `Bearer ${token}`)
      .expect(401);
  });
});
