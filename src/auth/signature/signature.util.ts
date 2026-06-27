import { createHmac } from 'crypto';

/**
 * 签名配置
 */
export interface SignatureConfig {
  /** 签名密钥 */
  secret: string;
  /** 签名请求头字段名（默认 X-Signature） */
  headerName?: string;
  /** 时间戳请求头字段名（默认 X-Timestamp） */
  timestampHeader?: string;
  /** nonce 请求头字段名（默认 X-Nonce） */
  nonceHeader?: string;
  /** 时间戳有效期（毫秒，默认 5 分钟） */
  timestampTolerance?: number;
}

/**
 * 签名参数
 */
export interface SignaturePayload {
  /** HTTP 方法 */
  method: string;
  /** 请求路径 */
  path: string;
  /** 时间戳（毫秒） */
  timestamp: number;
  /** 随机字符串（防重放） */
  nonce: string;
  /** 请求体 JSON 字符串（可选） */
  body?: string;
}

/**
 * 生成 HMAC-SHA256 签名
 * @param payload - 签名参数
 * @param secret - 密钥
 * @returns Base64 编码的签名
 */
export function generateSignature(
  payload: SignaturePayload,
  secret: string,
): string {
  const raw = `${payload.method}\n${payload.path}\n${payload.timestamp}\n${payload.nonce}\n${payload.body || ''}`;
  return createHmac('sha256', secret).update(raw).digest('base64');
}

/**
 * 校验签名
 * @param payload - 签名参数
 * @param signature - 客户端提供的签名
 * @param secret - 密钥
 * @returns 是否匹配
 */
export function verifySignature(
  payload: SignaturePayload,
  signature: string,
  secret: string,
): boolean {
  const expected = generateSignature(payload, secret);
  // 使用 timing-safe 比较防止时序攻击
  try {
    return createHmac('sha256', secret)
      .update(signature)
      .digest()
      .equals(createHmac('sha256', secret).update(expected).digest());
  } catch {
    return signature === expected;
  }
}

/**
 * 校验时间戳是否在允许范围内
 * @param timestamp - 客户端时间戳（毫秒）
 * @param tolerance - 允许偏差（毫秒，默认 5 分钟）
 * @returns 是否有效
 */
export function isTimestampValid(
  timestamp: number,
  tolerance = 5 * 60 * 1000,
): boolean {
  const now = Date.now();
  const diff = Math.abs(now - timestamp);
  return diff <= tolerance;
}
