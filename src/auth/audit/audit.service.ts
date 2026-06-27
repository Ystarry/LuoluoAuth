import { Inject, Injectable, Optional } from '@nestjs/common';
import { appendFile, mkdir, readFile } from 'fs/promises';
import { dirname } from 'path';
import type Redis from 'ioredis'; // 需安装: ioredis

/**
 * 审计日志动作类型
 */
export type AuditAction =
  | 'login'
  | 'logout'
  | 'force_logout'
  | 'kick'
  | 'ban'
  | 'unban'
  | 'switch_identity'
  | 'renew'
  | 'open_safe_auth'
  | 'close_safe_auth'
  | 'rpc_call'
  | 'signature_auth'
  | 'fingerprint_mismatch_warn'
  | 'fingerprint_mismatch_reject';

/**
 * 单条审计日志记录
 */
export interface AuditLog {
  /** 用户 ID */
  userId: string;
  /** 动作类型 */
  action: AuditAction;
  /** 设备标识（浏览器 UA / 设备 ID 等） */
  device?: string;
  /** 客户端 IP */
  ip?: string;
  /** 时间戳（毫秒） */
  timestamp: number;
  /** 会话 ID */
  sessionId?: string;
  /** 额外详情 */
  details?: Record<string, unknown>;
}

/**
 * 审计日志配置
 */
export interface AuditConfig {
  /** 是否启用审计日志 */
  enabled?: boolean;
  /** 日志存储方式：console | file | redis（默认 console） */
  storage?: 'console' | 'file' | 'redis';
  /** 日志文件路径（storage 为 file 时生效） */
  logFilePath?: string;
}

/**
 * 审计日志服务
 * 提供统一的日志记录能力，支持 console / file / redis 三种存储方式
 */
@Injectable()
export class AuditService {
  private readonly enabled: boolean;
  private readonly storage: 'console' | 'file' | 'redis';
  private readonly logFilePath?: string;

  /**
   * @param config - 审计日志配置
   * @param redis - Redis 连接实例（storage 为 redis 时必需）
   */
  constructor(
    @Inject('AUDIT_CONFIG')
    @Optional()
    config: AuditConfig | undefined,
    @Inject('REDIS_CLIENT')
    @Optional()
    private readonly redis: Redis | undefined,
  ) {
    this.enabled = config?.enabled ?? false;
    this.storage = config?.storage ?? 'console';
    this.logFilePath = config?.logFilePath;
  }

  /**
   * 记录审计日志
   * @param log - 审计日志记录
   */
  async log(log: AuditLog): Promise<void> {
    if (!this.enabled) {
      return;
    }

    switch (this.storage) {
      case 'file':
        await this.logToFile(log);
        break;
      case 'redis':
        await this.logToRedis(log);
        break;
      case 'console':
      default:
        this.logToConsole(log);
        break;
    }
  }

  /**
   * 批量记录审计日志
   * @param logs - 审计日志记录列表
   */
  async logBatch(logs: AuditLog[]): Promise<void> {
    if (!this.enabled || logs.length === 0) {
      return;
    }

    for (const log of logs) {
      await this.log(log);
    }
  }

  /**
   * 输出到控制台
   */
  private logToConsole(log: AuditLog): void {
    console.log(`[AUDIT] ${JSON.stringify(log)}`);
  }

  /**
   * 追加到文件
   */
  private async logToFile(log: AuditLog): Promise<void> {
    const path = this.logFilePath || './logs/audit.log';
    const dir = dirname(path);
    await mkdir(dir, { recursive: true });
    await appendFile(path, `${JSON.stringify(log)}\n`, 'utf-8');
  }

  /**
   * 写入 Redis List
   */
  private async logToRedis(log: AuditLog): Promise<void> {
    if (!this.redis) {
      this.logToConsole(log);
      return;
    }

    const key = `auth:audit:${log.userId}`;
    const value = JSON.stringify(log);
    await this.redis.lpush(key, value);
    // 保留最近 1000 条
    await this.redis.ltrim(key, 0, 999);
  }

  /**
   * 查询用户登录历史
   * 仅当审计日志启用时返回数据；console 存储不支持查询，返回空数组
   * @param userId - 用户 ID
   * @param limit - 最大返回条数（默认 100）
   * @returns 登录历史记录列表，按时间倒序
   */
  async getLoginHistory(userId: string, limit = 100): Promise<AuditLog[]> {
    if (!this.enabled) {
      return [];
    }

    switch (this.storage) {
      case 'redis':
        return this.getLoginHistoryFromRedis(userId, limit);
      case 'file':
        return this.getLoginHistoryFromFile(userId, limit);
      case 'console':
      default:
        return [];
    }
  }

  /**
   * 从 Redis List 读取登录历史
   */
  private async getLoginHistoryFromRedis(
    userId: string,
    limit: number,
  ): Promise<AuditLog[]> {
    if (!this.redis) {
      return [];
    }

    const key = `auth:audit:${userId}`;
    const values = await this.redis.lrange(key, 0, limit - 1);
    return values
      .map((value) => {
        try {
          return JSON.parse(value) as AuditLog;
        } catch {
          return undefined;
        }
      })
      .filter(
        (log): log is AuditLog => log !== undefined && log.action === 'login',
      );
  }

  /**
   * 从审计日志文件读取登录历史
   */
  private async getLoginHistoryFromFile(
    userId: string,
    limit: number,
  ): Promise<AuditLog[]> {
    const path = this.logFilePath || './logs/audit.log';

    let content: string;
    try {
      content = await readFile(path, 'utf-8');
    } catch (error: unknown) {
      // 文件不存在时返回空数组
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return [];
      }
      throw error;
    }

    const logs: AuditLog[] = [];
    const lines = content.split('\n');
    for (const line of lines) {
      if (!line.trim()) {
        continue;
      }
      try {
        const log = JSON.parse(line) as AuditLog;
        if (log.userId === userId && log.action === 'login') {
          logs.push(log);
        }
      } catch {
        // 忽略无法解析的行
      }
    }

    return logs.sort((a, b) => b.timestamp - a.timestamp).slice(0, limit);
  }
}
