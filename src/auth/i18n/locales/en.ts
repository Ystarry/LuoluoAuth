import { AuthErrorCode } from '../../errors/auth-error-code';

/**
 * English locale
 */
export const en: Record<AuthErrorCode, string> = {
  [AuthErrorCode.SUCCESS]: 'Success',
  [AuthErrorCode.TOKEN_EXPIRED]: 'Token has expired',
  [AuthErrorCode.TOKEN_INVALID]: 'Token is invalid or failed to parse',
  [AuthErrorCode.SESSION_NOT_FOUND]: 'Session not found or expired',
  [AuthErrorCode.SESSION_EXPIRED]: 'Session has expired',
  [AuthErrorCode.LOGIN_RATE_LIMITED]:
    'Login rate limit exceeded, please try again later',
  [AuthErrorCode.OAUTH2_RATE_LIMITED]:
    'OAuth2 rate limit exceeded, please try again later',
  [AuthErrorCode.LOGIN_CONCURRENT_LIMIT]:
    'Too many concurrent login attempts, please try again later',
  [AuthErrorCode.FINGERPRINT_MISMATCH]: 'Device fingerprint mismatch',
  [AuthErrorCode.MULTI_ACCOUNT_SWITCH_DISABLED]:
    'Multi-account switching is disabled',
  [AuthErrorCode.MULTI_ACCOUNT_LIMIT_EXCEEDED]:
    'Too many accounts logged in on this device',
  [AuthErrorCode.MULTI_ACCOUNT_TARGET_NOT_FOUND]:
    'Target account is not logged in on this device',
  [AuthErrorCode.USER_BANNED]: 'User has been banned',
  [AuthErrorCode.UNAUTHORIZED]: 'Unauthorized, please login first',
  [AuthErrorCode.FORBIDDEN]: 'Forbidden, insufficient permissions',
  [AuthErrorCode.SAFE_AUTH_REQUIRED]: 'Secondary authentication required',
  [AuthErrorCode.OAUTH2_INVALID_CLIENT]: 'Invalid OAuth2 client',
  [AuthErrorCode.OAUTH2_INVALID_GRANT]: 'Unsupported OAuth2 grant type',
  [AuthErrorCode.OAUTH2_INVALID_REFRESH_TOKEN]:
    'Invalid or expired OAuth2 refresh token',
  [AuthErrorCode.OAUTH2_REFRESH_TOKEN_REUSE]:
    'Refresh token reuse detected, token family revoked',
  [AuthErrorCode.OAUTH2_REDIRECT_URI_MISMATCH]: 'OAuth2 redirect URI mismatch',
  [AuthErrorCode.SIGNATURE_INVALID]: 'Invalid API signature',
  [AuthErrorCode.SIGNATURE_TIMESTAMP_INVALID]:
    'API signature timestamp invalid or expired',
  [AuthErrorCode.BAD_REQUEST]: 'Bad request',
  [AuthErrorCode.MISSING_PARAMETER]: 'Missing required parameter',
  [AuthErrorCode.INTERNAL_ERROR]: 'Internal server error',
};
