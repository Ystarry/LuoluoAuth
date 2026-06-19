import { sign } from 'jsonwebtoken';
import type { OAuth2ProviderConfig } from '../interfaces';

export interface AppleProviderOptions {
  /** Apple Services ID */
  clientId: string;
  /** Apple Team ID */
  teamId: string;
  /** Apple Private Key ID */
  keyId: string;
  /** Apple 私钥（PEM 格式） */
  privateKey: string;
  /** 回调地址 */
  redirectUri: string;
  /** 请求 scope，默认 ['name', 'email'] */
  scopes?: string[];
}

/**
 * Apple Sign In Provider 配置
 * Apple 强制 web 端使用 response_mode=form_post，且 client_secret 必须是 JWT
 */
export function createAppleProvider(
  options: AppleProviderOptions,
): OAuth2ProviderConfig {
  return {
    id: 'apple',
    name: 'Apple',
    authorizationEndpoint: 'https://appleid.apple.com/auth/authorize',
    tokenEndpoint: 'https://appleid.apple.com/auth/token',
    clientId: options.clientId,
    clientSecret: '', // Apple 使用动态 clientSecretGenerator，此处填空
    redirectUri: options.redirectUri,
    scopes: options.scopes ?? ['name', 'email'],
    responseMode: 'form_post',
    idTokenExtractor: (payload) => ({
      provider: 'apple',
      providerUserId: String(payload.sub),
      email: payload.email as string,
    }),
    clientSecretGenerator: () =>
      Promise.resolve(
        generateAppleClientSecret(
          options.teamId,
          options.clientId,
          options.keyId,
          options.privateKey,
        ),
      ),
    callbackBodyExtractor: (body) => {
      // Apple 首次登录时会在 form_post 体中返回 user JSON
      const user = body.user;
      if (typeof user !== 'string' && typeof user !== 'object') {
        return {};
      }
      const parsed =
        typeof user === 'string'
          ? (JSON.parse(user) as Record<string, unknown>)
          : (user as Record<string, unknown>);
      const nameObj = parsed.name as
        | { firstName?: string; lastName?: string }
        | undefined;
      const firstName = nameObj?.firstName ?? '';
      const lastName = nameObj?.lastName ?? '';
      const fullName = `${firstName} ${lastName}`.trim();

      return {
        username: fullName || undefined,
      };
    },
  };
}

/**
 * 生成 Apple client_secret JWT
 * 文档：https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens
 */
function generateAppleClientSecret(
  teamId: string,
  clientId: string,
  keyId: string,
  privateKey: string,
): string {
  const now = Math.floor(Date.now() / 1000);
  return sign(
    {
      iss: teamId,
      iat: now,
      exp: now + 15777000, // 最长 6 个月（180 天）
      aud: 'https://appleid.apple.com',
      sub: clientId,
    },
    privateKey,
    {
      algorithm: 'ES256',
      keyid: keyId,
    },
  );
}
