import { I18nService } from './i18n.service';
import { AuthErrorCode } from '../errors/auth-error-code';

describe('I18nService', () => {
  it('should translate error code in Chinese by default', () => {
    const i18n = new I18nService();
    expect(i18n.translate(AuthErrorCode.TOKEN_EXPIRED)).toBe('令牌已过期');
  });

  it('should translate error code in English', () => {
    const i18n = new I18nService('en');
    expect(i18n.translate(AuthErrorCode.TOKEN_EXPIRED)).toBe(
      'Token has expired',
    );
  });

  it('should switch locale dynamically', () => {
    const i18n = new I18nService();
    i18n.setLocale('en');
    expect(i18n.getLocale()).toBe('en');
    expect(i18n.translate(AuthErrorCode.UNAUTHORIZED)).toBe(
      'Unauthorized, please login first',
    );
  });

  it('should use fallback message when provided', () => {
    const i18n = new I18nService('en');
    const code = 9999 as AuthErrorCode;
    expect(i18n.translate(code, 'custom fallback')).toBe('custom fallback');
  });
});
