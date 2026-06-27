import { AuthErrorCode } from '../../errors/auth-error-code';

/**
 * 中文（简体）语言包
 */
export const zhCN: Record<AuthErrorCode, string> = {
  [AuthErrorCode.SUCCESS]: '成功',
  [AuthErrorCode.TOKEN_EXPIRED]: '令牌已过期',
  [AuthErrorCode.TOKEN_INVALID]: '令牌无效或解析失败',
  [AuthErrorCode.SESSION_NOT_FOUND]: '会话不存在或已过期',
  [AuthErrorCode.SESSION_EXPIRED]: '会话已过期',
  [AuthErrorCode.LOGIN_RATE_LIMITED]: '登录频率超限，请稍后再试',
  [AuthErrorCode.OAUTH2_RATE_LIMITED]: 'OAuth2 请求频率超限，请稍后再试',
  [AuthErrorCode.LOGIN_CONCURRENT_LIMIT]: '登录并发请求过多，请稍后再试',
  [AuthErrorCode.FINGERPRINT_MISMATCH]: '设备指纹不匹配',
  [AuthErrorCode.MULTI_ACCOUNT_SWITCH_DISABLED]: '多账号切换未启用',
  [AuthErrorCode.MULTI_ACCOUNT_LIMIT_EXCEEDED]: '同一设备登录账号数量超过上限',
  [AuthErrorCode.MULTI_ACCOUNT_TARGET_NOT_FOUND]: '目标账号在当前设备上未登录',
  [AuthErrorCode.USER_BANNED]: '用户已被封禁',
  [AuthErrorCode.UNAUTHORIZED]: '未授权，请先登录',
  [AuthErrorCode.FORBIDDEN]: '禁止访问，权限不足',
  [AuthErrorCode.SAFE_AUTH_REQUIRED]: '需要通过二级认证',
  [AuthErrorCode.OAUTH2_INVALID_CLIENT]: 'OAuth2 客户端无效',
  [AuthErrorCode.OAUTH2_INVALID_GRANT]: 'OAuth2 授权类型不支持',
  [AuthErrorCode.OAUTH2_INVALID_REFRESH_TOKEN]: 'OAuth2 刷新令牌无效或已过期',
  [AuthErrorCode.OAUTH2_REFRESH_TOKEN_REUSE]:
    '检测到刷新令牌复用，令牌族已吊销',
  [AuthErrorCode.OAUTH2_REDIRECT_URI_MISMATCH]: 'OAuth2 回调地址不匹配',
  [AuthErrorCode.SIGNATURE_INVALID]: 'API 签名无效',
  [AuthErrorCode.SIGNATURE_TIMESTAMP_INVALID]: 'API 签名时间戳无效或已过期',
  [AuthErrorCode.BAD_REQUEST]: '请求参数错误',
  [AuthErrorCode.MISSING_PARAMETER]: '缺少必要参数',
  [AuthErrorCode.INTERNAL_ERROR]: '服务端内部错误',
};
