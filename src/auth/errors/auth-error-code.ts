/**
 * 认证框架业务错误码
 * 统一使用 4 位数字，按模块分段：
 * - 100x：Token / Session
 * - 101x：限流
 * - 102x：设备指纹
 * - 103x：黑名单 / 封禁
 * - 110x：认证 / 授权
 * - 120x：OAuth2
 * - 130x：API 签名
 * - 140x：请求参数
 * - 150x：服务端内部
 */
export enum AuthErrorCode {
  /** 成功 */
  SUCCESS = 1000,

  /** Token 已过期 */
  TOKEN_EXPIRED = 1001,
  /** Token 无效或解析失败 */
  TOKEN_INVALID = 1002,
  /** 会话不存在或已过期 */
  SESSION_NOT_FOUND = 1003,
  /** 会话已过期 */
  SESSION_EXPIRED = 1004,

  /** 登录频率超限 */
  LOGIN_RATE_LIMITED = 1010,
  /** OAuth2 Token 端点频率超限 */
  OAUTH2_RATE_LIMITED = 1011,
  /** 登录并发锁获取失败，请稍后重试 */
  LOGIN_CONCURRENT_LIMIT = 1012,

  /** 设备指纹不匹配 */
  FINGERPRINT_MISMATCH = 1020,
  /** 多账号切换未启用 */
  MULTI_ACCOUNT_SWITCH_DISABLED = 1021,
  /** 同一设备账号数量超过上限 */
  MULTI_ACCOUNT_LIMIT_EXCEEDED = 1022,
  /** 目标账号在当前设备上未登录 */
  MULTI_ACCOUNT_TARGET_NOT_FOUND = 1023,

  /** 用户已被封禁 */
  USER_BANNED = 1030,

  /** 未授权（未登录或 Token 缺失） */
  UNAUTHORIZED = 1100,
  /** 禁止访问（权限不足） */
  FORBIDDEN = 1101,
  /** 二级认证未通过 */
  SAFE_AUTH_REQUIRED = 1102,

  /** OAuth2 客户端无效 */
  OAUTH2_INVALID_CLIENT = 1200,
  /** OAuth2 授权类型不支持 */
  OAUTH2_INVALID_GRANT = 1201,
  /** OAuth2 刷新令牌无效或过期 */
  OAUTH2_INVALID_REFRESH_TOKEN = 1202,
  /** OAuth2 刷新令牌被复用 */
  OAUTH2_REFRESH_TOKEN_REUSE = 1203,
  /** OAuth2 回调地址不匹配 */
  OAUTH2_REDIRECT_URI_MISMATCH = 1204,

  /** API 签名无效 */
  SIGNATURE_INVALID = 1300,
  /** API 签名时间戳无效或已过期 */
  SIGNATURE_TIMESTAMP_INVALID = 1301,

  /** 请求参数错误 */
  BAD_REQUEST = 1400,
  /** 缺少必要参数 */
  MISSING_PARAMETER = 1401,

  /** 服务端内部错误 */
  INTERNAL_ERROR = 1500,
}
