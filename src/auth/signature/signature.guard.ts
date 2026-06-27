import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Inject,
  Injectable,
} from '@nestjs/common';
import type { Request } from 'express';
import type { SignatureConfig } from './signature.util';
import { verifySignature, isTimestampValid } from './signature.util';
import type { NonceStore } from './nonce-store';

/**
 * 签名认证守卫
 * 基于 HMAC-SHA256 校验 API 请求签名，防止请求篡改和重放攻击
 *
 * 要求请求头携带：
 * - X-Signature: HMAC-SHA256 签名（Base64）
 * - X-Timestamp: 请求时间戳（毫秒）
 * - X-Nonce: 随机字符串（防重放）
 */
@Injectable()
export class SignatureGuard implements CanActivate {
  private readonly headerName: string;
  private readonly timestampHeader: string;
  private readonly nonceHeader: string;
  private readonly timestampTolerance: number;

  /**
   * @param config - 签名配置
   * @param nonceStore - Nonce 存储实例（可选，默认无 Redis 时使用内存兜底）
   */
  constructor(
    @Inject('SIGNATURE_CONFIG')
    private readonly config: SignatureConfig,
    @Inject('NONCE_STORE')
    private readonly nonceStore: NonceStore | undefined,
  ) {
    this.headerName = config.headerName || 'X-Signature';
    this.timestampHeader = config.timestampHeader || 'X-Timestamp';
    this.nonceHeader = config.nonceHeader || 'X-Nonce';
    this.timestampTolerance = config.timestampTolerance || 5 * 60 * 1000;
  }

  /**
   * 校验请求签名
   * @param context - 执行上下文
   * @returns 是否通过
   * @throws ForbiddenException 签名无效或过期时抛出
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();

    const signature = this.extractHeader(request, this.headerName);
    const timestampStr = this.extractHeader(request, this.timestampHeader);
    const nonce = this.extractHeader(request, this.nonceHeader);

    if (!signature || !timestampStr || !nonce) {
      throw new ForbiddenException(
        `Missing signature headers: ${this.headerName}, ${this.timestampHeader}, ${this.nonceHeader}`,
      );
    }

    const timestamp = parseInt(timestampStr, 10);
    if (Number.isNaN(timestamp)) {
      throw new ForbiddenException('Invalid timestamp format');
    }

    // 校验时间戳有效期
    if (!isTimestampValid(timestamp, this.timestampTolerance)) {
      throw new ForbiddenException('Request timestamp expired');
    }

    // 校验 nonce 防重放（使用 NonceStore，无 Redis 时由内存 LRU 兜底）
    if (this.nonceStore) {
      const exists = await this.nonceStore.has(nonce);
      if (exists) {
        throw new ForbiddenException('Duplicate nonce detected');
      }
      // 记录 nonce，过期时间与时间戳容忍度一致
      await this.nonceStore.set(nonce, this.timestampTolerance);
    }

    // 构建签名参数
    const method = request.method.toUpperCase();
    const path = request.originalUrl || request.url;
    const body =
      request.body &&
      typeof request.body === 'object' &&
      Object.keys(request.body as Record<string, unknown>).length > 0
        ? JSON.stringify(request.body)
        : undefined;

    const payload = {
      method,
      path,
      timestamp,
      nonce,
      body,
    };

    // 校验签名
    const valid = verifySignature(payload, signature, this.config.secret);
    if (!valid) {
      throw new ForbiddenException('Invalid signature');
    }

    return true;
  }

  /**
   * 从请求头中提取指定字段（不区分大小写）
   * @param request - HTTP 请求对象
   * @param name - 字段名
   * @returns 字段值，未找到返回 undefined
   */
  private extractHeader(request: Request, name: string): string | undefined {
    const lower = name.toLowerCase();
    const value = request.headers[lower];
    if (typeof value === 'string') {
      return value;
    }
    if (Array.isArray(value) && value.length > 0) {
      return value[0];
    }
    return undefined;
  }
}
