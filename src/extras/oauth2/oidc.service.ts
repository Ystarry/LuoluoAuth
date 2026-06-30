import { Injectable } from '@nestjs/common';
import { sign, verify } from 'jsonwebtoken';

/**
 * OIDC 配置
 */
export interface OidcConfig {
  /** 发行者标识，必须是一个 HTTPS URL（本地测试可为 http://localhost） */
  issuer: string;
  /** 用于签发 ID Token 的密钥 */
  secret: string;
  /** ID Token 有效期（秒，默认 3600） */
  idTokenExpiresIn?: number;
}

/**
 * OIDC Discovery 元数据
 */
export interface OidcDiscoveryMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri?: string;
  scopes_supported: string[];
  response_types_supported: string[];
  grant_types_supported: string[];
  subject_types_supported: string[];
  id_token_signing_alg_values_supported: string[];
}

/**
 * OIDC 标准 UserInfo  claims
 */
export interface OidcUserInfo {
  sub: string;
  name?: string;
  preferred_username?: string;
  email?: string;
  email_verified?: boolean;
  scope?: string;
}

/**
 * OIDC 服务
 * 负责生成 ID Token 与 OpenID Discovery 元数据
 */
@Injectable()
export class OidcService {
  private readonly idTokenExpiresIn: number;

  constructor(private readonly config: OidcConfig) {
    this.idTokenExpiresIn = config.idTokenExpiresIn ?? 3600;
  }

  /**
   * 生成 ID Token
   * @param sub - 用户唯一标识
   * @param audience - 受众（client_id）
   * @param nonce - 授权请求中传入的 nonce（可选）
   * @param extraClaims - 额外声明（如 name、email 等）
   * @returns ID Token JWT 字符串
   */
  signIdToken(
    sub: string,
    audience: string,
    nonce?: string,
    extraClaims?: Record<string, unknown>,
  ): string {
    const now = Math.floor(Date.now() / 1000);
    const payload: Record<string, unknown> = {
      iss: this.config.issuer,
      sub,
      aud: audience,
      exp: now + this.idTokenExpiresIn,
      iat: now,
      auth_time: now,
      ...extraClaims,
    };

    if (nonce) {
      payload.nonce = nonce;
    }

    return sign(payload, this.config.secret, { algorithm: 'HS256' });
  }

  /**
   * 验证 ID Token 签名并返回 payload
   * 主要用于测试场景
   * verifyIdToken 增加 audience 与 nonce 校验； exp 由 jsonwebtoken.verify 默认校验
   * @param idToken - ID Token 字符串
   * @param audience - 期望的受众（client_id），可选
   * @param nonce - 授权请求中传入的 nonce，可选
   * @returns 解码后的 payload
   * @throws Error 当签名、issuer、audience、nonce 或 exp 校验失败时抛出
   */
  verifyIdToken(
    idToken: string,
    audience?: string,
    nonce?: string,
  ): Record<string, unknown> {
    const payload = verify(idToken, this.config.secret, {
      algorithms: ['HS256'],
      issuer: this.config.issuer,
      ...(audience ? { audience } : {}),
    }) as Record<string, unknown>;

    if (nonce && payload.nonce !== nonce) {
      throw new Error('Invalid nonce in ID Token');
    }

    return payload;
  }

  /**
   * 获取 OIDC Discovery 元数据
   * @returns Discovery 配置
   */
  getDiscoveryMetadata(): OidcDiscoveryMetadata {
    const issuer = this.config.issuer.replace(/\/$/, '');
    return {
      issuer,
      authorization_endpoint: `${issuer}/oauth/authorize`,
      token_endpoint: `${issuer}/oauth/token`,
      userinfo_endpoint: `${issuer}/oauth/userinfo`,
      scopes_supported: ['openid', 'profile', 'email'],
      response_types_supported: ['code'],
      grant_types_supported: [
        'authorization_code',
        'password',
        'client_credentials',
        'refresh_token',
      ],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['HS256'],
    };
  }
}
