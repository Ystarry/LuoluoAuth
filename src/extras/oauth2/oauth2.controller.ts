import {
  BadRequestException,
  Controller,
  Get,
  Inject,
  Optional,
  Post,
  Query,
  Req,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { randomUUID } from 'crypto';
import { verifyCodeVerifier } from './pkce.util';
import { AuthService } from '../../auth/auth.service';
import { extractBearerToken } from '../../auth/utils/token.util';
import type { RateLimiter } from '../../auth/rate-limit/rate-limit.interface';
import { AuthErrorCode } from '../../auth/errors/auth-error-code';
import { AuthException } from '../../auth/errors/auth.exception';
import {
  AuthorizationCode,
  DeviceCode,
  InMemoryOAuth2ClientStore,
  OAuth2Token,
} from './client-store';
import type {
  OAuth2Client,
  OAuth2ClientStore,
  UserValidator,
} from './client-store';
import { OidcService } from './oidc.service';

/**
 * OAuth2 授权检查模式
 * - cookie: 从当前请求 Cookie 中读取并校验 Token
 * - header: 从当前请求 Authorization 头中读取并校验 Token
 * - redirect: 未登录时重定向到登录页（默认行为）
 */
export type OAuth2AuthCheckMode = 'cookie' | 'header' | 'redirect';

/**
 * OAuth2 模块扩展配置
 * 用于控制 authorize 端点的登录态检查行为
 */
export interface OAuth2AuthorizeConfig {
  /** 登录态检查模式（默认 redirect） */
  authCheckMode?: OAuth2AuthCheckMode;
  /** Cookie Token 名称（authCheckMode 为 cookie 时使用） */
  cookieName?: string;
  /** 未登录时的重定向地址（authCheckMode 为 redirect 时使用） */
  loginUrl?: string;
  /** 请求原始授权参数存储键名 */
  stateKey?: string;
}

/**
 * OAuth2 ClientStore 注入令牌
 * 默认使用 InMemoryOAuth2ClientStore，可替换为 RedisOAuth2ClientStore
 */
export const OAUTH2_CLIENT_STORE = 'OAUTH2_CLIENT_STORE';

/**
 * OAuth2 授权请求查询参数
 */
interface AuthorizeQuery {
  /** 客户端 ID */
  client_id: string;
  /** 回调地址 */
  redirect_uri: string;
  /** 响应类型 */
  response_type: string;
  /** 状态值 */
  state?: string;
  /** 请求的 scope */
  scope?: string;
  /** PKCE code_challenge */
  code_challenge?: string;
  /** PKCE code_challenge_method，默认 S256 */
  code_challenge_method?: string;
  /** OIDC nonce */
  nonce?: string;
}

/**
 * 从 authorize 请求中读取用户 Token
 * 支持 Cookie 或 Authorization 请求头
 */
function extractTokenFromRequest(
  req: Request,
  mode: OAuth2AuthCheckMode,
  cookieName = 'token',
): string | undefined {
  if (mode === 'cookie') {
    const cookies = req.cookies as Record<string, string> | undefined;
    const value = cookies?.[cookieName];
    return typeof value === 'string' ? value : undefined;
  }
  if (mode === 'header') {
    return extractBearerToken(req.headers.authorization);
  }
  return undefined;
}

/**
 * OAuth2 Token 请求体
 */
interface TokenRequest {
  /** 授权类型 */
  grant_type: string;
  /** 客户端 ID */
  client_id: string;
  /** 客户端密钥 */
  client_secret: string;
  /** 授权码（authorization_code 模式） */
  code?: string;
  /** 回调地址 */
  redirect_uri?: string;
  /** 用户名（password 模式） */
  username?: string;
  /** 密码（password 模式） */
  password?: string;
  /** 刷新令牌（refresh_token 模式） */
  refresh_token?: string;
  /** 请求的 scope */
  scope?: string;
  /** PKCE code_verifier（authorization_code 模式） */
  code_verifier?: string;
}

/**
 * OAuth2 控制器
 * 实现标准 OAuth2 端点：authorize、token、userinfo
 */
@Controller('oauth')
export class OAuth2Controller {
  /**
   * @param authService - 认证服务实例
   * @param clientStore - 客户端存储实例
   * @param userValidator - 用户名密码校验器（password 模式必需）
   * @param authorizeConfig - authorize 端点登录态检查配置
   */
  constructor(
    @Inject(AuthService)
    private readonly authService: AuthService,
    @Optional()
    @Inject(OAUTH2_CLIENT_STORE)
    clientStore?: OAuth2ClientStore,
    @Optional()
    @Inject('OAUTH2_USER_VALIDATOR')
    private readonly userValidator?: UserValidator,
    @Optional()
    @Inject('RATE_LIMITER')
    private readonly rateLimiter?: RateLimiter,
    @Optional()
    @Inject(OidcService)
    private readonly oidcService?: OidcService,
    @Optional()
    @Inject('OAUTH2_AUTHORIZE_CONFIG')
    private readonly authorizeConfig?: OAuth2AuthorizeConfig,
  ) {
    this.clientStore = clientStore ?? new InMemoryOAuth2ClientStore();
  }

  private readonly clientStore: OAuth2ClientStore;
  /** Device Code 内存存储（device_code 授权流程专用） */
  private readonly deviceCodes = new Map<string, DeviceCode>();

  /**
   * OAuth2 授权端点
   * GET /oauth/authorize
   * 检查用户登录态后重定向到登录页或返回授权码
   * @param query - 授权请求参数
   * @param req - HTTP 请求对象
   * @param res - HTTP 响应对象
   */
  @Get('authorize')
  async authorize(
    @Query() query: AuthorizeQuery,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    // 验证 response_type
    if (query.response_type !== 'code') {
      throw new BadRequestException('Unsupported response_type');
    }

    // 验证客户端
    const client = await this.clientStore.getClient(query.client_id);
    if (!client) {
      throw new UnauthorizedException('Invalid client_id');
    }

    // 验证回调地址
    if (
      !(await this.clientStore.verifyRedirectUri(
        query.client_id,
        query.redirect_uri,
      ))
    ) {
      throw new BadRequestException('Invalid redirect_uri');
    }

    // 验证授权类型
    if (
      !(await this.clientStore.supportsGrant(
        query.client_id,
        'authorization_code',
      ))
    ) {
      throw new BadRequestException('Unsupported grant type for this client');
    }

    // 公共客户端必须使用 PKCE
    if (client.isPublic && !query.code_challenge) {
      throw new BadRequestException(
        'code_challenge is required for public clients',
      );
    }

    // 校验并归一化 PKCE code_challenge_method
    const codeChallengeMethod = this.normalizeCodeChallengeMethod(
      query.code_challenge_method,
    );
    if (
      query.code_challenge &&
      codeChallengeMethod !== 'S256' &&
      codeChallengeMethod !== 'plain'
    ) {
      throw new BadRequestException(
        'Unsupported code_challenge_method. Use S256 or plain',
      );
    }

    const mode = this.authorizeConfig?.authCheckMode || 'redirect';

    // 尝试获取当前登录用户的 Token
    const token = extractTokenFromRequest(
      req,
      mode,
      this.authorizeConfig?.cookieName,
    );

    let userId: string;
    if (token) {
      try {
        const session = await this.authService.validateToken(
          token,
          req.ip,
          req.headers['user-agent'],
        );
        userId = session.userId;
      } catch {
        // Token 校验失败时按未登录处理，继续执行重定向或拒绝逻辑
      }
    }

    if (!userId!) {
      if (mode === 'redirect') {
        const loginUrl = this.authorizeConfig?.loginUrl || '/auth/login';
        const stateKey = this.authorizeConfig?.stateKey || 'oauth_state';
        const returnUrl = new URL(
          req.originalUrl || req.url,
          `${req.protocol}://${req.headers.host || 'localhost'}`,
        ).toString();

        const redirectUrl = new URL(loginUrl, 'http://localhost');
        redirectUrl.searchParams.set('redirect_uri', returnUrl);
        redirectUrl.searchParams.set(stateKey, query.state || '');
        res.redirect(redirectUrl.toString());
        return;
      }

      throw new UnauthorizedException('User not authenticated');
    }

    // 生成授权码并返回
    const code = randomUUID();
    const authCode: AuthorizationCode = {
      code,
      clientId: query.client_id,
      userId,
      redirectUri: query.redirect_uri,
      expiresAt: Date.now() + 10 * 60 * 1000, // 授权码 10 分钟有效
      state: query.state,
      scope: query.scope,
      nonce: query.nonce,
      codeChallenge: query.code_challenge,
      codeChallengeMethod,
    };

    await this.clientStore.saveAuthorizationCode(authCode);

    // 构建回调 URL，携带授权码
    const redirectUrl = new URL(query.redirect_uri);
    redirectUrl.searchParams.set('code', code);
    if (query.state) {
      redirectUrl.searchParams.set('state', query.state);
    }

    res.redirect(redirectUrl.toString());
  }

  /**
   * OAuth2 Token 端点
   * POST /oauth/token
   * 支持 authorization_code、password、client_credentials、refresh_token 四种模式
   * @param req - HTTP 请求对象
   * @returns Token 响应
   */
  @Post('token')
  async token(@Req() req: Request): Promise<OAuth2Token> {
    const body = req.body as TokenRequest;
    const ip = (req.ip as string) || 'unknown';
    const userAgent = (req.headers['user-agent'] as string) || undefined;

    // 验证客户端身份
    const client = await this.clientStore.getClient(body.client_id);
    if (!client) {
      throw new UnauthorizedException('Invalid client_id');
    }

    // 公共客户端不需要 client_secret；机密客户端必须校验
    if (!client.isPublic) {
      if (
        !(await this.clientStore.verifyClientSecret(
          body.client_id,
          body.client_secret,
        ))
      ) {
        throw new UnauthorizedException('Invalid client_secret');
      }
    }

    // 根据授权类型分发处理
    switch (body.grant_type) {
      case 'authorization_code':
        return this.handleAuthorizationCode(body, client, ip, userAgent);
      case 'password':
        return this.handlePassword(body, ip, userAgent);
      case 'client_credentials':
        return this.handleClientCredentials(body, ip, userAgent);
      case 'refresh_token':
        return this.handleRefreshToken(body, ip, userAgent);
      case 'device_code':
        return this.handleDeviceCodeToken(body, ip, userAgent);
      default:
        throw new BadRequestException('Unsupported grant_type');
    }
  }

  /**
   * 处理 authorization_code 模式
   * 使用授权码换取访问令牌
   * @param body - Token 请求体
   * @param ip - 客户端 IP 地址
   * @param userAgent - 客户端 User-Agent
   * @returns Token 响应
   */
  private async handleAuthorizationCode(
    body: TokenRequest,
    client: OAuth2Client,
    ip?: string,
    userAgent?: string,
  ): Promise<OAuth2Token> {
    if (!body.code) {
      throw new BadRequestException('Missing code parameter');
    }

    // 消费授权码（一次性使用）
    const authCode = await this.clientStore.consumeAuthorizationCode(body.code);
    if (!authCode) {
      throw new BadRequestException('Invalid or expired authorization code');
    }

    // 验证客户端 ID 是否匹配
    if (authCode.clientId !== body.client_id) {
      throw new BadRequestException('Client ID mismatch');
    }

    // 验证回调地址是否匹配
    if (body.redirect_uri && authCode.redirectUri !== body.redirect_uri) {
      throw new BadRequestException('Redirect URI mismatch');
    }

    // PKCE 校验：公共客户端必须使用 PKCE；若授权码携带 challenge，则必须校验 verifier
    if (authCode.codeChallenge) {
      if (!body.code_verifier) {
        throw new BadRequestException('Missing code_verifier');
      }
      const valid = verifyCodeVerifier(
        body.code_verifier,
        authCode.codeChallenge,
        authCode.codeChallengeMethod || 'S256',
      );
      if (!valid) {
        throw new BadRequestException('Invalid code_verifier');
      }
    } else if (client.isPublic) {
      throw new BadRequestException(
        'Public clients must use PKCE for authorization_code grant',
      );
    }

    // 生成访问令牌和刷新令牌
    const token = await this.generateToken(
      authCode.userId,
      authCode.scope,
      body.client_id,
      authCode.nonce,
      ip,
      userAgent,
    );
    await this.clientStore.saveToken(token);

    return token;
  }

  /**
   * 处理 password 模式
   * 使用用户名密码直接换取 Token
   * @param body - Token 请求体
   * @param ip - 客户端 IP 地址
   * @param userAgent - 客户端 User-Agent
   * @returns Token 响应
   */
  private async handlePassword(
    body: TokenRequest,
    ip?: string,
    userAgent?: string,
  ): Promise<OAuth2Token> {
    // 登录限流检查
    if (this.rateLimiter && ip) {
      const allowed = await this.rateLimiter.allow({
        ip,
        action: 'oauth2:password',
      });
      if (!allowed) {
        throw new AuthException(AuthErrorCode.OAUTH2_RATE_LIMITED, 429);
      }
    }

    if (!this.userValidator) {
      throw new BadRequestException(
        'password grant type requires a user validator',
      );
    }

    if (!body.username || !body.password) {
      throw new BadRequestException('Missing username or password');
    }

    const user = await this.userValidator(body.username, body.password);
    if (!user) {
      throw new UnauthorizedException('Invalid username or password');
    }

    const token = await this.generateToken(
      user.userId,
      body.scope,
      body.client_id,
      undefined,
      ip,
      userAgent,
    );
    await this.clientStore.saveToken(token);

    return token;
  }

  /**
   * 处理 client_credentials 模式
   * 使用客户端凭证换取 Token（无用户上下文）
   * @param body - Token 请求体
   * @param ip - 客户端 IP 地址
   * @param userAgent - 客户端 User-Agent
   * @returns Token 响应
   */
  private async handleClientCredentials(
    body: TokenRequest,
    ip?: string,
    userAgent?: string,
  ): Promise<OAuth2Token> {
    const token = await this.generateToken(
      undefined,
      body.scope,
      body.client_id,
      undefined,
      ip,
      userAgent,
    );
    await this.clientStore.saveToken(token);

    return token;
  }

  /**
   * 处理 refresh_token 模式
   * 使用刷新令牌换取新的访问令牌，支持 refresh token rotation + reuse detection
   * @param body - Token 请求体
   * @param ip - 客户端 IP 地址
   * @param userAgent - 客户端 User-Agent
   * @returns Token 响应
   */
  private async handleRefreshToken(
    body: TokenRequest,
    ip?: string,
    userAgent?: string,
  ): Promise<OAuth2Token> {
    // 刷新令牌限流检查
    if (this.rateLimiter && ip) {
      const allowed = await this.rateLimiter.allow({
        ip,
        action: 'oauth2:refresh',
      });
      if (!allowed) {
        throw new AuthException(AuthErrorCode.OAUTH2_RATE_LIMITED, 429);
      }
    }

    if (!body.refresh_token) {
      throw new BadRequestException('Missing refresh_token parameter');
    }

    const result = await this.clientStore.consumeRefreshToken(
      body.refresh_token,
    );
    if (!result) {
      throw new BadRequestException('Invalid or expired refresh token');
    }

    // 复用检测：若 refresh token 已被使用过，说明可能被盗用
    if (result.reuseDetected) {
      // 吊销整个令牌族，阻止攻击者继续使用任何相关 token
      await this.clientStore.revokeTokenFamily(result.family);
      throw new UnauthorizedException(
        'Refresh token reuse detected. Token family revoked.',
      );
    }

    // 生成新的 Token 对，复用同一令牌族
    const token = await this.generateToken(
      result.token.userId,
      result.token.scope,
      body.client_id,
      undefined,
      ip,
      userAgent,
    );
    await this.clientStore.saveToken(token, result.family);

    return token;
  }

  /**
   * 归一化 PKCE code_challenge_method
   * 未指定时默认使用 S256
   * @param method - 原始 method 字符串
   * @returns 归一化后的 method
   */
  private normalizeCodeChallengeMethod(
    method?: string,
  ): 'plain' | 'S256' | undefined {
    if (!method) {
      return 'S256';
    }

    const normalized = method.toLowerCase();
    if (normalized === 's256') {
      return 'S256';
    }
    if (normalized === 'plain') {
      return 'plain';
    }

    return undefined;
  }

  /**
   * 生成 OAuth2 Token
   * @param userId - 用户 ID（client_credentials 模式可为空）
   * @param scope - 请求的 scope
   * @param clientId - 客户端 ID（用于 OIDC ID Token 的 aud）
   * @param nonce - OIDC nonce（authorization_code 模式使用）
   * @param ip - 客户端 IP 地址
   * @param userAgent - 客户端 User-Agent
   * @returns Token 信息
   */
  private async generateToken(
    userId?: string,
    scope?: string,
    clientId?: string,
    nonce?: string,
    ip?: string,
    userAgent?: string,
  ): Promise<OAuth2Token> {
    const refreshToken = randomUUID();
    const expiresIn = 3600;

    // 用户相关授权使用 AuthService 生成 JWT 访问令牌，并绑定设备指纹
    const accessToken = userId
      ? await this.authService.login(
          userId,
          undefined,
          undefined,
          undefined,
          ip,
          userAgent,
        )
      : randomUUID();

    const token: OAuth2Token = {
      accessToken,
      refreshToken,
      tokenType: 'Bearer',
      expiresIn,
      scope,
      userId,
    };

    // OIDC：当 scope 包含 openid 且配置了 OidcService 时签发 id_token
    if (
      userId &&
      clientId &&
      this.oidcService &&
      scope?.split(' ').includes('openid')
    ) {
      token.idToken = this.oidcService.signIdToken(userId, clientId, nonce);
    }

    return token;
  }

  /**
   * OAuth2 用户信息端点
   * GET /oauth/userinfo
   * 返回当前用户的基本信息
   * @param req - HTTP 请求对象
   * @returns 用户信息
   */
  @Get('userinfo')
  async userinfo(@Req() req: Request): Promise<Record<string, unknown>> {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      throw new UnauthorizedException('Missing authorization header');
    }

    const accessToken = extractBearerToken(authHeader);
    if (!accessToken) {
      throw new UnauthorizedException('Invalid authorization header format');
    }

    // 验证 Token 是否存在
    const token = await this.clientStore.getToken(accessToken);
    if (!token) {
      throw new UnauthorizedException('Invalid access token');
    }

    // 优先通过 AuthService 校验 JWT 并获取用户信息
    // 传入当前请求的 IP / User-Agent 进行设备指纹校验
    try {
      const session = await this.authService.validateToken(
        accessToken,
        req.ip,
        req.headers['user-agent'],
      );
      return {
        sub: session.userId,
        name: session.userId,
        preferred_username: session.userId,
        scope: token.scope,
      };
    } catch {
      throw new UnauthorizedException('Invalid or expired access token');
    }
  }

  /**
   * Device Authorization 端点 (RFC 8628)
   * POST /oauth/device/authorize
   * 输入受限设备发起授权请求，返回 device_code 和 user_code
   * @param req - HTTP 请求对象
   * @returns 设备授权响应
   */
  @Post('device/authorize')
  async deviceAuthorize(@Req() req: Request): Promise<Record<string, unknown>> {
    const body = req.body as {
      client_id: string;
      scope?: string;
    };

    if (!body.client_id) {
      throw new BadRequestException('Missing client_id');
    }

    const client = await this.clientStore.getClient(body.client_id);
    if (!client) {
      throw new UnauthorizedException('Invalid client_id');
    }

    if (
      !(await this.clientStore.supportsGrant(body.client_id, 'device_code'))
    ) {
      throw new BadRequestException(
        'device_code grant not supported for this client',
      );
    }

    const deviceCode = randomUUID();
    const userCode = this.generateUserCode();
    const verificationUri = '/oauth/device/verify';

    const deviceEntry: DeviceCode = {
      deviceCode,
      userCode,
      verificationUri,
      verificationUriComplete: `${verificationUri}?user_code=${userCode}`,
      clientId: body.client_id,
      scope: body.scope,
      interval: 5,
      expiresAt: Date.now() + 10 * 60 * 1000, // 10 分钟有效
    };

    this.deviceCodes.set(deviceCode, deviceEntry);

    return {
      device_code: deviceCode,
      user_code: userCode,
      verification_uri: verificationUri,
      verification_uri_complete: deviceEntry.verificationUriComplete,
      expires_in: 600,
      interval: 5,
    };
  }

  /**
   * Device Verification 端点
   * POST /oauth/device/verify
   * 用户在浏览器端输入 user_code 确认授权
   * @param req - HTTP 请求对象
   * @returns 验证结果
   */
  @Post('device/verify')
  async deviceVerify(@Req() req: Request): Promise<Record<string, unknown>> {
    const body = req.body as {
      user_code: string;
    };

    if (!body.user_code) {
      throw new BadRequestException('Missing user_code');
    }

    const authHeader = req.headers.authorization;
    if (!authHeader) {
      throw new UnauthorizedException('Authentication required');
    }

    const token = extractBearerToken(authHeader);
    if (!token) {
      throw new UnauthorizedException('Invalid authorization header');
    }

    let userId: string;
    try {
      const session = await this.authService.validateToken(
        token,
        req.ip,
        req.headers['user-agent'],
      );
      userId = session.userId;
    } catch {
      throw new UnauthorizedException('Invalid or expired token');
    }

    // 查找匹配的 device code
    for (const [deviceCode, entry] of this.deviceCodes.entries()) {
      if (entry.userCode === body.user_code && !entry.authorized) {
        if (Date.now() > entry.expiresAt) {
          this.deviceCodes.delete(deviceCode);
          throw new BadRequestException('User code expired');
        }
        entry.authorized = true;
        entry.userId = userId;
        return { success: true };
      }
    }

    throw new BadRequestException('Invalid user_code');
  }

  /**
   * 处理 device_code 模式（Token 端点处）
   * 设备轮询 Token 端点，使用 device_code 换取访问令牌
   * @param body - Token 请求体
   * @param ip - 客户端 IP 地址
   * @param userAgent - 客户端 User-Agent
   * @returns Token 响应
   */
  private async handleDeviceCodeToken(
    body: TokenRequest,
    ip?: string,
    userAgent?: string,
  ): Promise<OAuth2Token> {
    const deviceCode = body.code; // device_code 复用 code 字段
    if (!deviceCode) {
      throw new BadRequestException('Missing device_code');
    }

    const entry = this.deviceCodes.get(deviceCode);
    if (!entry) {
      throw new BadRequestException('Invalid device_code');
    }

    if (Date.now() > entry.expiresAt) {
      this.deviceCodes.delete(deviceCode);
      throw new BadRequestException('Device code expired');
    }

    if (!entry.authorized) {
      throw new BadRequestException('authorization_pending');
    }

    // 授权成功，生成 Token
    this.deviceCodes.delete(deviceCode);

    const token = await this.generateToken(
      entry.userId,
      entry.scope,
      body.client_id,
      undefined,
      ip,
      userAgent,
    );
    await this.clientStore.saveToken(token);

    return token;
  }

  /**
   * 生成 8 位易读 user_code（大写字母 + 数字）
   */
  private generateUserCode(): string {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let code = '';
    for (let i = 0; i < 8; i++) {
      code += chars[Math.floor(Math.random() * chars.length)];
    }
    return code;
  }
}
