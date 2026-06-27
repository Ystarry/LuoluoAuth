/**
 * 密码加密器接口
 * 提供统一的密码哈希与校验抽象，便于切换 BCrypt / Argon2 等算法
 */
export interface PasswordEncoder {
  /**
   * 对明文密码进行哈希
   * @param password - 明文密码
   * @returns 密码哈希字符串
   */
  hash(password: string): Promise<string>;

  /**
   * 校验明文密码与哈希是否匹配
   * @param password - 明文密码
   * @param hash - 密码哈希字符串
   * @returns 是否匹配
   */
  verify(password: string, hash: string): Promise<boolean>;
}
