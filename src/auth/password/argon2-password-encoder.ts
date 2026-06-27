import * as argon2 from 'argon2';
import { PasswordEncoder } from './password-encoder.interface';

/**
 * Argon2 密码加密器
 * 依赖: argon2
 */
export class Argon2PasswordEncoder implements PasswordEncoder {
  /**
   * @param options - Argon2 哈希选项，默认使用 argon2id
   */
  constructor(private readonly options?: argon2.Options) {}

  async hash(password: string): Promise<string> {
    return argon2.hash(password, this.options);
  }

  async verify(password: string, hash: string): Promise<boolean> {
    return argon2.verify(hash, password, this.options);
  }
}
