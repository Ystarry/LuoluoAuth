import type { Request, Response } from 'express';
import type { CookieConfig } from './cookie.config';
import { defaultCookieConfig } from './cookie.config';

/**
 * Cookie 操作服务
 * 封装 Token 在 Cookie 中的写入、读取与清除
 */
export class CookieService {
  private readonly config: Required<
    Pick<
      CookieConfig,
      | 'enabled'
      | 'name'
      | 'path'
      | 'httpOnly'
      | 'secure'
      | 'sameSite'
      | 'maxAge'
    >
  > &
    Pick<CookieConfig, 'domain'>;

  /**
   * @param config - Cookie 配置
   */
  constructor(config?: CookieConfig) {
    this.config = {
      ...defaultCookieConfig,
      ...config,
    };
  }

  /**
   * 是否启用 Cookie 模式
   */
  isEnabled(): boolean {
    return this.config.enabled;
  }

  /**
   * 获取当前配置的 Cookie 名称
   */
  getName(): string {
    return this.config.name;
  }

  /**
   * 从请求 Cookie 中读取 Token
   * @param req - HTTP 请求对象
   * @returns Token 字符串，未找到则返回 undefined
   */
  read(req: Request): string | undefined {
    const cookies = req.cookies as Record<string, unknown> | undefined;
    const raw = cookies?.[this.config.name];
    return typeof raw === 'string' ? raw : undefined;
  }

  /**
   * 将 Token 写入响应 Cookie
   * @param res - HTTP 响应对象
   * @param token - Token 字符串
   * @param maxAgeSeconds - 覆盖默认的存活时间（秒）
   */
  write(res: Response, token: string, maxAgeSeconds?: number): void {
    res.cookie(this.config.name, token, {
      domain: this.config.domain,
      path: this.config.path,
      httpOnly: this.config.httpOnly,
      secure: this.config.secure,
      sameSite: this.config.sameSite,
      maxAge: (maxAgeSeconds ?? this.config.maxAge) * 1000,
    });
  }

  /**
   * 清除响应 Cookie
   * @param res - HTTP 响应对象
   */
  clear(res: Response): void {
    res.clearCookie(this.config.name, {
      domain: this.config.domain,
      path: this.config.path,
    });
  }
}
