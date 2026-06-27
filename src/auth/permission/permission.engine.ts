import { Injectable } from '@nestjs/common';

/**
 * 扩展的 Session 数据接口
 * 包含角色和权限信息
 */
export interface SessionWithPermissions {
  /** 用户 ID */
  userId: string;
  /** 设备标识（可选） */
  device?: string;
  /** 会话创建时间戳 */
  createTime: number;
  /** 角色列表 */
  roles?: string[];
  /** 权限列表 */
  permissions?: string[];
}

/**
 * 权限校验引擎
 * 提供基于 RBAC 的角色和权限校验功能
 */
@Injectable()
export class PermissionEngine {
  /**
   * 检查用户是否拥有指定角色（满足其一即可）
   * @param session - 会话数据
   * @param requiredRoles - 要求的角色列表
   * @returns 是否拥有至少一个指定角色
   */
  hasRole(session: SessionWithPermissions, requiredRoles: string[]): boolean {
    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }

    const userRoles = session.roles || [];
    return requiredRoles.some((role) => userRoles.includes(role));
  }

  /**
   * 检查用户是否拥有指定权限（需全部满足）
   * 支持通配符匹配，如 user:* 可匹配 user:add、user:delete
   * @param session - 会话数据
   * @param requiredPermissions - 要求的权限列表
   * @returns 是否拥有所有指定权限
   */
  hasPermission(
    session: SessionWithPermissions,
    requiredPermissions: string[],
  ): boolean {
    if (!requiredPermissions || requiredPermissions.length === 0) {
      return true;
    }

    const userPermissions = session.permissions || [];
    return requiredPermissions.every((required) =>
      userPermissions.some((userPerm) =>
        this.matchPermission(userPerm, required),
      ),
    );
  }

  /**
   * 权限通配符匹配
   * - 精确匹配：user:add 匹配 user:add
   * - 单级通配：user:* 匹配 user:add、user:delete，但不匹配 user:admin:delete
   * - 全局通配：* 匹配所有权限
   * @param userPerm - 用户拥有的权限（可包含通配符）
   * @param required - 要求的权限
   * @returns 是否匹配
   */
  private matchPermission(userPerm: string, required: string): boolean {
    // 全局通配符
    if (userPerm === '*') {
      return true;
    }

    // 精确匹配
    if (userPerm === required) {
      return true;
    }

    // 分段匹配（支持单级 * 通配符）
    const userParts = userPerm.split(':');
    const reqParts = required.split(':');

    if (userParts.length !== reqParts.length) {
      return false;
    }

    return userParts.every((part, index) => {
      return part === '*' || part === reqParts[index];
    });
  }
}
