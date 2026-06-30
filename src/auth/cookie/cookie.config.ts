/**
 * Cookie 认证模式配置
 */
export interface CookieConfig {
  /** 是否启用 Cookie 模式 */
  enabled?: boolean;
  /** Cookie 名称（默认 auth-token） */
  name?: string;
  /** Cookie 域名 */
  domain?: string;
  /** Cookie 路径（默认 /） */
  path?: string;
  /** 是否仅允许 HTTP 读取，禁止前端 JS 访问（默认 true） */
  httpOnly?: boolean;
  /** 是否仅通过 HTTPS 传输（默认 true，生产环境建议保持开启） */
  secure?: boolean;
  /** SameSite 策略（默认 lax） */
  sameSite?: 'strict' | 'lax' | 'none' | boolean;
  /** Cookie 最大存活时间（秒，默认 7 天） */
  maxAge?: number;
}

/**
 * Cookie 默认配置
 */
export const defaultCookieConfig: Required<
  Pick<
    CookieConfig,
    'enabled' | 'name' | 'path' | 'httpOnly' | 'secure' | 'sameSite' | 'maxAge'
  >
> = {
  enabled: false,
  name: 'auth-token',
  path: '/',
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
  maxAge: 7 * 24 * 60 * 60,
};
