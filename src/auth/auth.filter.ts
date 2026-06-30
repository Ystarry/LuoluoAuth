import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  ForbiddenException,
  HttpException,
  UnauthorizedException,
} from '@nestjs/common';
import { Response, Request } from 'express';
import { AuthErrorCode } from './errors/auth-error-code';
import { AuthException } from './errors/auth.exception';
import { I18nService, SupportedLocale } from './i18n/i18n.service';

/**
 * 统一异常响应体
 */
interface UnifiedErrorResponse {
  /** 业务错误码 */
  code: number;
  /** 多语言错误信息 */
  message: string;
  /** 请求路径 */
  path: string;
  /** 时间戳 */
  timestamp: string;
}

/**
 * 全局认证业务异常过滤器
 * 统一捕获 AuthException、HttpException 及其子类，输出标准 JSON 错误响应
 * 支持根据请求 Accept-Language 头返回对应语言的错误信息
 */
@Catch(AuthException, HttpException)
export class AuthExceptionFilter implements ExceptionFilter {
  /** 按 locale 缓存 I18nService 实例，避免每次请求都新建 */
  private readonly i18nCache = new Map<SupportedLocale, I18nService>();

  /**
   * 获取指定语言的 I18nService 实例
   * @param locale - 语言标识
   * @returns I18nService 实例
   */
  private getI18nService(locale: SupportedLocale): I18nService {
    let service = this.i18nCache.get(locale);
    if (!service) {
      service = new I18nService(locale);
      this.i18nCache.set(locale, service);
    }
    return service;
  }

  /**
   * 解析请求希望使用的语言
   * 仅识别当前支持的语言，否则使用默认语言
   * @param request - HTTP 请求对象
   * @returns 语言标识
   */
  private resolveLocale(request: Request): SupportedLocale {
    const acceptLanguage = request.headers['accept-language'];
    if (!acceptLanguage || typeof acceptLanguage !== 'string') {
      return 'zh-CN';
    }

    const primary = acceptLanguage.split(',')[0]?.trim().toLowerCase();
    if (primary.startsWith('en')) {
      return 'en';
    }
    if (primary.startsWith('zh')) {
      return 'zh-CN';
    }
    return 'zh-CN';
  }

  /**
   * 将常见 HTTP 异常映射为业务错误码
   * @param exception - HTTP 异常对象
   * @returns 对应的业务错误码
   */
  private mapHttpExceptionToCode(exception: HttpException): AuthErrorCode {
    const status = exception.getStatus();

    switch (status) {
      case 401:
        return AuthErrorCode.UNAUTHORIZED;
      case 403:
        return AuthErrorCode.FORBIDDEN;
      case 429:
        return AuthErrorCode.LOGIN_RATE_LIMITED;
      case 400:
        return AuthErrorCode.BAD_REQUEST;
      default:
        return AuthErrorCode.INTERNAL_ERROR;
    }
  }

  /**
   * 从 HTTP 异常中提取可读错误信息
   * @param exception - HTTP 异常对象
   * @returns 错误文本
   */
  private extractHttpMessage(exception: HttpException): string {
    const response = exception.getResponse();
    if (typeof response === 'string') {
      return response;
    }
    if (typeof response === 'object' && response !== null) {
      return (
        (response as Record<string, string>).message ||
        (response as Record<string, string>).error ||
        'Internal server error'
      );
    }
    return 'Internal server error';
  }

  /**
   * 捕获并处理异常
   * @param exception - 异常对象
   * @param host - 参数主机
   */
  catch(exception: AuthException | HttpException, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    const i18n = this.getI18nService(this.resolveLocale(request));

    let status: number;
    let code: AuthErrorCode;

    if (exception instanceof AuthException) {
      status = exception.status;
      code = exception.code;
    } else {
      status = exception.getStatus();
      code = this.mapHttpExceptionToCode(exception);
    }

    // 对 NestJS 标准异常，优先保留其原始 message（仅兜底使用 i18n）
    let message: string;
    if (exception instanceof AuthException) {
      message = i18n.translate(code);
    } else if (
      exception instanceof UnauthorizedException ||
      exception instanceof ForbiddenException
    ) {
      message = this.extractHttpMessage(exception);
    } else {
      message = i18n.translate(code, this.extractHttpMessage(exception));
    }

    const errorResponse: UnifiedErrorResponse = {
      code,
      message,
      path: request.url,
      timestamp: new Date().toISOString(),
    };

    response.status(status).json(errorResponse);
  }
}
