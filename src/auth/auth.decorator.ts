import { SetMetadata } from '@nestjs/common';

/**
 * 认证元数据键
 */
export const AUTH_METADATA_KEY = 'auth';

/**
 * 角色元数据键
 */
export const ROLES_METADATA_KEY = 'roles';

/**
 * 权限元数据键
 */
export const PERMISSIONS_METADATA_KEY = 'permissions';

/**
 * 二级认证元数据键
 */
export const SAFE_AUTH_METADATA_KEY = 'safe_auth';

/**
 * 要求登录装饰器
 * 标记需要认证的路由或控制器
 * @returns 方法装饰器 / 类装饰器
 */
export const RequireLogin = () => SetMetadata(AUTH_METADATA_KEY, true);

/**
 * 要求角色装饰器
 * 标记需要指定角色的路由或控制器（满足其一即可）
 * @param roles - 要求的角色列表
 * @returns 方法装饰器 / 类装饰器
 */
export const RequireRoles = (...roles: string[]) =>
  SetMetadata(ROLES_METADATA_KEY, roles);

/**
 * 要求权限装饰器
 * 标记需要指定权限的路由或控制器（需全部满足）
 * @param permissions - 要求的权限列表
 * @returns 方法装饰器 / 类装饰器
 */
export const RequirePermissions = (...permissions: string[]) =>
  SetMetadata(PERMISSIONS_METADATA_KEY, permissions);

/**
 * 要求二级认证装饰器
 * 标记需要二级认证的路由或控制器（如修改密码、转账等敏感操作）
 * @returns 方法装饰器 / 类装饰器
 */
export const RequireSafeAuth = () => SetMetadata(SAFE_AUTH_METADATA_KEY, true);

/**
 * 签名认证元数据键
 */
export const SIGNATURE_METADATA_KEY = 'signature';

/**
 * 要求签名认证装饰器
 * 标记需要 HMAC-SHA256 签名校验的路由或控制器
 * @returns 方法装饰器 / 类装饰器
 */
export const RequireSignature = () => SetMetadata(SIGNATURE_METADATA_KEY, true);
