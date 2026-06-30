import * as bcrypt from 'bcrypt';
import { PasswordEncoder } from './password-encoder.interface';

/**
 * BCrypt 密码加密器
 * 依赖: bcrypt
 */
export class BcryptPasswordEncoder implements PasswordEncoder {
  /**
   * @param rounds - 计算成本（salt rounds），默认 12（OWASP 推荐）
   */
  constructor(private readonly rounds = 12) {}

  async hash(password: string): Promise<string> {
    return bcrypt.hash(password, this.rounds);
  }

  async verify(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }
}
