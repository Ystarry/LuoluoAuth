import { AuthErrorCode } from './auth-error-code';

/**
 * 认证框架业务异常
 * 携带标准业务错误码与 HTTP 状态码，供全局异常过滤器统一处理
 */
export class AuthException extends Error {
  /**
   * @param code - 业务错误码
   * @param status - HTTP 状态码（默认 400）
   * @param message - 可选的原始错误描述（默认使用错误码数字）
   * @param args - 可选的模板变量（未来支持占位符替换）
   */
  constructor(
    public readonly code: AuthErrorCode,
    public readonly status: number = 400,
    message?: string,
    public readonly args?: Record<string, string>,
  ) {
    super(message ?? String(code));
    this.name = 'AuthException';
  }
}
