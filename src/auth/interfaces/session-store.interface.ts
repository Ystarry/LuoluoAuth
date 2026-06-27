/**
 * Session 数据存储结构
 */
export interface SessionData {
  /** 用户 ID */
  userId: string;
  /** 设备标识（可选） */
  device?: string;
  /** 会话创建时间戳 */
  createTime: number;
  /** 角色列表（可选） */
  roles?: string[];
  /** 权限列表（可选） */
  permissions?: string[];
  /** 切换身份时的原始用户 ID（可选） */
  originalUserId?: string;
  /** 身份切换时间戳（可选） */
  switchTime?: number;
  /** 是否已开启二级认证（可选） */
  safeAuth?: boolean;
  /** 二级认证开启时间戳（可选） */
  safeAuthTime?: number;
  /** 登录时绑定的客户端 IP（设备指纹） */
  ip?: string;
  /** 登录时绑定的 User-Agent（设备指纹） */
  userAgent?: string;
  /** 是否为 Remember Me 长期会话 */
  rememberMe?: boolean;
}

/**
 * 黑名单存储接口
 * 支持在内存或 Redis 中按 userId 封禁用户
 */
export interface BlacklistStore {
  /**
   * 封禁用户
   * @param userId - 用户 ID
   * @param duration - 封禁时长（秒）
   */
  ban(userId: string, duration: number): Promise<void>;

  /**
   * 解除封禁
   * @param userId - 用户 ID
   */
  unban?(userId: string): Promise<void>;

  /**
   * 检查用户是否被封禁
   * @param userId - 用户 ID
   * @returns 是否被封禁
   */
  isBanned(userId: string): Promise<boolean>;
}

/**
 * Session 存储接口
 * 定义了会话数据的增删改查操作
 */
export interface SessionStore {
  /**
   * 存储会话数据
   * @param sessionId - 会话唯一标识
   * @param data - 会话数据
   * @param ttl - 过期时间（毫秒）
   */
  set(sessionId: string, data: SessionData, ttl?: number): Promise<void>;

  /**
   * 获取会话数据
   * @param sessionId - 会话唯一标识
   * @returns 会话数据，不存在则返回 null
   */
  get(sessionId: string): Promise<SessionData | null>;

  /**
   * 删除指定会话
   * @param sessionId - 会话唯一标识
   */
  delete(sessionId: string): Promise<void>;

  /**
   * 根据用户 ID 删除所有会话
   * @param userId - 用户 ID
   */
  deleteByUserId(userId: string): Promise<void>;

  /**
   * 查询用户的所有在线会话
   * @param userId - 用户 ID
   * @returns 会话数据数组
   */
  listByUserId?(userId: string): Promise<SessionData[]>;

  /**
   * 根据设备标识查询所有会话 ID
   * 用于多账号切换场景下统计/清理同一设备上的登录账号
   * @param device - 设备标识
   * @returns 会话 ID 数组
   */
  listByDevice?(device: string): Promise<string[]>;

  /**
   * 刷新会话过期时间
   * @param sessionId - 会话唯一标识
   * @param ttl - 新的过期时间（毫秒）
   */
  renew?(sessionId: string, ttl?: number): Promise<void>;
}
