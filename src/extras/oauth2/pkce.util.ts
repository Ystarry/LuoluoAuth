import { createHash, randomBytes } from 'crypto';

/**
 * 支持的 PKCE code_challenge 算法
 */
export type PkceMethod = 'plain' | 'S256';

/**
 * 生成随机的 code_verifier
 * RFC 7636 要求长度 43-128 字符，这里默认生成 128 字符
 */
export function generateCodeVerifier(length = 128): string {
  return base64UrlEncode(randomBytes(length))
    .slice(0, length)
    .replace(/[^A-Za-z0-9\-_]/g, '');
}

/**
 * 根据 code_verifier 生成 code_challenge
 * @param verifier - code_verifier
 * @param method - 算法，默认 S256
 * @returns code_challenge
 */
export function generateCodeChallenge(
  verifier: string,
  method: PkceMethod = 'S256',
): string {
  if (method === 'plain') {
    return verifier;
  }

  return base64UrlEncode(createHash('sha256').update(verifier).digest());
}

/**
 * 校验 code_verifier 是否与存储的 code_challenge 匹配
 * @param verifier - 客户端提交的 code_verifier
 * @param challenge - 授权码中存储的 code_challenge
 * @param method - 授权码中存储的 code_challenge_method
 * @returns 是否匹配
 */
export function verifyCodeVerifier(
  verifier: string,
  challenge: string,
  method: PkceMethod,
): boolean {
  const computed = generateCodeChallenge(verifier, method);
  return timingSafeEqual(computed, challenge);
}

/**
 * Base64URL 编码（无填充、替换 +/ 为 -_）
 */
function base64UrlEncode(buffer: Buffer): string {
  return buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * 简单的时间安全比较
 */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}
