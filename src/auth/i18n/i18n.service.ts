import { AuthErrorCode } from '../errors/auth-error-code';
import { en } from './locales/en';
import { zhCN } from './locales/zh-CN';

/**
 * 支持的语言列表
 */
export type SupportedLocale = 'zh-CN' | 'en';

/**
 * 国际化服务
 * 根据当前语言环境返回业务错误码对应的描述文本
 */
export class I18nService {
  /** 默认语言 */
  private static readonly DEFAULT_LOCALE: SupportedLocale = 'zh-CN';

  /** 语言包映射 */
  private static readonly locales: Record<
    SupportedLocale,
    Record<AuthErrorCode, string>
  > = {
    'zh-CN': zhCN,
    en,
  };

  /** 当前语言 */
  private locale: SupportedLocale;

  /**
   * @param locale - 初始语言（默认 zh-CN）
   */
  constructor(locale: SupportedLocale = I18nService.DEFAULT_LOCALE) {
    this.locale = locale;
  }

  /**
   * 切换当前语言
   * @param locale - 目标语言
   */
  setLocale(locale: SupportedLocale): void {
    this.locale = locale;
  }

  /**
   * 获取当前语言
   * @returns 当前语言标识
   */
  getLocale(): SupportedLocale {
    return this.locale;
  }

  /**
   * 翻译错误码为当前语言描述
   * @param code - 业务错误码
   * @param fallback - 找不到翻译时的回退文本
   * @returns 翻译后的文本
   */
  translate(code: AuthErrorCode, fallback?: string): string {
    const messages =
      I18nService.locales[this.locale] ||
      I18nService.locales[I18nService.DEFAULT_LOCALE];
    return messages[code] ?? fallback ?? `Unknown error code: ${code}`;
  }
}
