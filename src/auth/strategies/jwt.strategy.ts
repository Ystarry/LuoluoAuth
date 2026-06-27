import jwt from 'jsonwebtoken';
import type { SignOptions } from 'jsonwebtoken';
import type {
  TokenPayload,
  TokenStrategy,
} from '../interfaces/token-strategy.interface';
import { AuthErrorCode } from '../errors/auth-error-code';
import { AuthException } from '../errors/auth.exception';

/**
 * JWT 策略配置选项
 */
export interface JwtStrategyOptions {
  /** JWT 密钥 */
  secret: string;
  /** Token 过期时间（如 '1h', '7d'） */
  expiresIn?: SignOptions['expiresIn'];
}

/**
 * 基于 JWT 的 Token 策略实现
 * 使用 jsonwebtoken 库进行 Token 的生成和校验
 */
export class JwtStrategy implements TokenStrategy {
  /**
   * @param options - JWT 配置选项
   */
  constructor(private readonly options: JwtStrategyOptions) {}

  /**
   * 生成 JWT Token
   * @param payload - 载荷数据
   * @returns 生成的 Token 字符串
   */
  generate(payload: TokenPayload): string {
    const signOptions: SignOptions = {};
    if (this.options.expiresIn) {
      signOptions.expiresIn = this.options.expiresIn;
    }
    return jwt.sign(payload, this.options.secret, signOptions);
  }

  /**
   * 校验并解析 JWT Token
   * @param token - Token 字符串
   * @returns 解析后的载荷数据
   * @throws AuthException Token 无效或过期时抛出业务异常
   */
  verify(token: string): TokenPayload {
    try {
      return jwt.verify(token, this.options.secret, {
        algorithms: ['HS256'],
      }) as TokenPayload;
    } catch (error: unknown) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new AuthException(AuthErrorCode.TOKEN_EXPIRED, 401);
      }
      throw new AuthException(AuthErrorCode.TOKEN_INVALID, 401);
    }
  }
}
