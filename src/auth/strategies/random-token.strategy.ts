import { randomBytes } from 'crypto';
import { ulid } from 'ulid';
import { AuthErrorCode } from '../errors/auth-error-code';
import { AuthException } from '../errors/auth.exception';
import type { SessionStore } from '../interfaces/session-store.interface';
import type {
  TokenPayload,
  TokenStrategy,
} from '../interfaces/token-strategy.interface';

/**
 * 生成 UUID Version 7
 * 48 位 Unix 毫秒时间戳 + 74 位随机数，兼容 RFC 9562
 * @returns UUID v7 字符串
 */
function uuidv7(): string {
  const now = Date.now();
  const rand = randomBytes(10);

  const buf = Buffer.alloc(16);
  // 高 48 位：时间戳；低 16 位用随机数填充
  const timestamp = BigInt(now);
  buf.writeBigUInt64BE(
    (timestamp << 16n) | BigInt((rand[0] << 8) | rand[1]),
    0,
  );
  rand.copy(buf, 6, 2);

  // version = 7 (0x7xxx)
  buf[6] = (buf[6] & 0x0f) | 0x70;
  // variant = 10 (0x8xxx - 0xbxxx)
  buf[8] = (buf[8] & 0x3f) | 0x80;

  return [
    buf.subarray(0, 4).toString('hex'),
    buf.subarray(4, 6).toString('hex'),
    buf.subarray(6, 8).toString('hex'),
    buf.subarray(8, 10).toString('hex'),
    buf.subarray(10, 16).toString('hex'),
  ].join('-');
}

/**
 * 随机 Token 风格
 * - uuid-v7：UUID Version 7（时间排序 + 随机）
 * - ulid：Universally Unique Lexicographically Sortable Identifier
 * - random-32：32 位十六进制随机字符串
 * - random-64：64 位十六进制随机字符串
 * - random-128：128 位十六进制随机字符串
 */
export type RandomTokenStyle =
  | 'uuid-v7'
  | 'ulid'
  | 'random-32'
  | 'random-64'
  | 'random-128';

/**
 * 随机 Token 策略配置选项
 */
export interface RandomTokenStrategyOptions {
  /** Token 风格 */
  style: RandomTokenStyle;
  /** Token 前缀（如 sa、luoluo 等） */
  prefix?: string;
}

/**
 * 随机 Token 策略
 * 生成无状态短 Token，服务端通过 SessionStore 校验 Token 是否有效
 * 对标 Sa-Token 的随机 Token 风格
 */
export class RandomTokenStrategy implements TokenStrategy {
  /**
   * @param sessionStore - 会话存储实例
   * @param options - 随机 Token 策略选项
   */
  constructor(
    private readonly sessionStore: SessionStore,
    private readonly options: RandomTokenStrategyOptions,
  ) {}

  /**
   * 生成随机 Token
   * @param payload - 载荷数据（会话 ID 作为 Token 主键）
   * @returns Token 字符串
   */
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  generate(_payload: TokenPayload): string {
    let token: string;

    switch (this.options.style) {
      case 'uuid-v7':
        token = uuidv7();
        break;
      case 'ulid':
        token = ulid();
        break;
      case 'random-32':
        token = randomBytes(16).toString('hex');
        break;
      case 'random-64':
        token = randomBytes(32).toString('hex');
        break;
      case 'random-128':
        token = randomBytes(64).toString('hex');
        break;
      default:
        throw new AuthException(
          AuthErrorCode.BAD_REQUEST,
          400,
          `Unsupported random token style: ${String(this.options.style)}`,
        );
    }

    return this.options.prefix ? `${this.options.prefix}:${token}` : token;
  }

  /**
   * 校验 Token 是否有效
   * 通过 SessionStore 查询对应会话，若不存在则视为无效 Token
   * @param token - Token 字符串
   * @returns 解析后的载荷数据
   */
  async verify(token: string): Promise<TokenPayload> {
    const session = await this.sessionStore.get(token);
    if (!session) {
      throw new AuthException(AuthErrorCode.SESSION_NOT_FOUND, 401);
    }

    return {
      sessionId: token,
      userId: session.userId,
      device: session.device,
    };
  }

  /**
   * 随机 Token 本身即会话 ID
   * @param token - Token 字符串
   * @returns 会话 ID
   */
  extractSessionId(token: string): string {
    return token;
  }

  /**
   * 轮换随机 Token
   * 复制旧会话数据到新 Token，并删除旧 Token，防止 Cookie 泄露后长期有效
   * @param token - 旧 Token 字符串
   * @returns 新 Token 字符串
   */
  async rotate(token: string): Promise<string | undefined> {
    const session = await this.sessionStore.get(token);
    if (!session) {
      return undefined;
    }

    const newToken = this.generate({
      sessionId: token,
      userId: session.userId,
      device: session.device,
    });

    await this.sessionStore.set(newToken, session);
    await this.sessionStore.delete(token);

    return newToken;
  }
}
