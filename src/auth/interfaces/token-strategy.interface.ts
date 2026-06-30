/**
 * Token 载荷数据
 */
export interface TokenPayload {
  /** 会话 ID */
  sessionId: string;
  /** 用户 ID */
  userId: string;
  /** 设备标识（可选） */
  device?: string;
  /** 签发时间戳 */
  iat?: number;
  /** 过期时间戳 */
  exp?: number;
}

/**
 * Token 策略接口
 * 定义了 Token 的生成和校验操作
 */
export interface TokenStrategy {
  /**
   * 生成 Token
   * @param payload - 载荷数据
   * @returns 生成的 Token 字符串
   */
  generate(payload: TokenPayload): string;

  /**
   * 校验并解析 Token
   * @param token - Token 字符串
   * @returns 解析后的载荷数据（支持同步或异步实现）
   * @throws 校验失败时抛出异常
   */
  verify(token: string): TokenPayload | Promise<TokenPayload>;

  /**
   * 从 Token 中提取会话 ID
   * JWT 等自包含 Token 可省略，由调用方使用 verify 返回的 sessionId
   * 随机 Token 策略通常直接返回 token 本身
   * @param token - Token 字符串
   * @returns 会话 ID
   */
  extractSessionId?(token: string): string | Promise<string>;

  /**
   * 轮换 Token（Cookie 模式自动续期时使用）
   * 返回新的 Token 字符串；若策略不支持轮换（如 JWT），返回 undefined
   * @param token - 旧 Token 字符串
   * @returns 新 Token 字符串，或 undefined
   */
  rotate?(token: string): string | Promise<string | undefined>;
}
