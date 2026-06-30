import {
  CallHandler,
  ExecutionContext,
  Inject,
  Injectable,
  NestInterceptor,
  Optional,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { Request } from 'express';
import { AsyncLocalStorage } from 'async_hooks';
import { Metadata } from '@grpc/grpc-js'; // 需安装: @grpc/grpc-js
import { AuthService } from '../../auth/auth.service';

/**
 * Token 提取函数类型
 * 允许业务方自定义如何从当前上下文中解析 Token
 */
export type RpcTokenResolver = () => string | undefined;

/**
 * 微服务认证拦截器配置
 */
export interface MicroserviceAuthInterceptorConfig {
  /**
   * 是否在附加 Token 前调用 AuthService.validateToken 校验 Token 有效性
   * 默认 false，避免每次 RPC 调用都产生额外开销
   */
  validateToken?: boolean;
}

/**
 * 微服务认证拦截器
 * 用于微服务 Consumer（调用方），自动从当前上下文中获取 Token
 * 并附加到 gRPC metadata 或 TCP 数据包中
 */
@Injectable()
export class MicroserviceAuthInterceptor implements NestInterceptor {
  /**
   * 全局 AsyncLocalStorage，用于在异步调用链路中透传 Token
   */
  static readonly tokenStore = new AsyncLocalStorage<string>();

  /**
   * @param authService - 认证服务实例
   * @param tokenResolver - 自定义 Token 解析函数
   * @param config - 拦截器配置
   */
  constructor(
    @Inject(AuthService)
    private readonly authService: AuthService,
    @Optional()
    @Inject('RPC_TOKEN_RESOLVER')
    private readonly tokenResolver?: RpcTokenResolver,
    @Optional()
    @Inject('RPC_AUTH_INTERCEPTOR_CONFIG')
    private readonly config?: MicroserviceAuthInterceptorConfig,
  ) {}

  /**
   * 拦截请求，自动注入认证信息
   * @param context - 执行上下文
   * @param next - 调用处理器
   * @returns Observable
   */
  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const type = context.getType<'http' | 'rpc'>();

    if (type === 'http') {
      // HTTP 场景：从请求头中提取 Token 并缓存到上下文中
      this.attachTokenFromHttp(context);
      return next.handle();
    }

    if (type === 'rpc') {
      // RPC 场景：将 Token 附加到 gRPC metadata 或 TCP 数据包
      return new Observable((subscriber) => {
        this.attachTokenToRpc(context)
          .then(() => {
            next.handle().subscribe(subscriber);
          })
          .catch((err) => {
            subscriber.error(err);
          });
      });
    }

    return next.handle();
  }

  /**
   * 从 HTTP 请求中提取 Token 并缓存
   * 供后续 RPC 调用使用
   * @param context - 执行上下文
   */
  private attachTokenFromHttp(context: ExecutionContext): void {
    const request = context.switchToHttp().getRequest<Request>();
    const authHeader = request.headers.authorization;

    if (authHeader) {
      const token = authHeader.startsWith('Bearer ')
        ? authHeader.slice(7)
        : authHeader;
      // 将 Token 缓存到请求对象中，供后续 RPC 调用使用
      (request as unknown as Record<string, unknown>)['__rpc_auth_token'] =
        token;
    }
  }

  /**
   * 将 Token 附加到 RPC 请求中
   * 支持 gRPC metadata 和 TCP 数据包
   * @param context - 执行上下文
   */
  private async attachTokenToRpc(context: ExecutionContext): Promise<void> {
    const rpcContext: unknown = context.switchToRpc().getContext();
    const token = this.resolveTokenForRpc();

    if (!token) {
      return;
    }

    if (this.config?.validateToken) {
      try {
        await this.authService.validateToken(token);
      } catch {
        return;
      }
    }

    // gRPC 场景：附加到 metadata
    if (rpcContext instanceof Metadata) {
      rpcContext.add('authorization', `Bearer ${token}`);
      return;
    }

    // 如果 rpcContext 是 Metadata 构造函数的实例（某些版本的 gRPC）
    if (
      rpcContext &&
      typeof rpcContext === 'object' &&
      'add' in rpcContext &&
      typeof (rpcContext as Record<string, unknown>)['add'] === 'function'
    ) {
      (rpcContext as { add: (k: string, v: string) => void }).add(
        'authorization',
        `Bearer ${token}`,
      );
      return;
    }

    // TCP / Redis / MQTT 等场景：附加到 context 对象
    if (rpcContext && typeof rpcContext === 'object') {
      (rpcContext as Record<string, string>)['authorization'] =
        `Bearer ${token}`;
    }
  }

  /**
   * 解析用于 RPC 调用的 Token
   * 优先级：1. 自定义 resolver  2. AsyncLocalStorage  3. HTTP 请求头缓存
   * @returns Token 字符串，未找到则返回 undefined
   */
  private resolveTokenForRpc(): string | undefined {
    // 1. 业务方自定义 Token 解析
    if (this.tokenResolver) {
      const token = this.tokenResolver();
      if (token) {
        return token;
      }
    }

    // 2. AsyncLocalStorage 中透传的 Token
    const storedToken = MicroserviceAuthInterceptor.tokenStore.getStore();
    if (storedToken) {
      return storedToken;
    }

    // 3. 当前 HTTP 请求对象中缓存的 Token（attachTokenFromHttp 写入）
    const req = this.getCurrentHttpRequest?.();
    if (req) {
      return (req as unknown as Record<string, unknown>)['__rpc_auth_token'] as
        | string
        | undefined;
    }

    return undefined;
  }

  /**
   * 获取当前 HTTP 请求对象
   * 子类或扩展实现可覆盖此方法以支持不同上下文
   */
  protected getCurrentHttpRequest?(): Request | undefined {
    return undefined;
  }

  /**
   * 在指定的 Token 上下文中执行异步任务
   * 用于在微服务调用链路中透传 Token
   * @param token - 当前用户的认证 Token
   * @param task - 需要执行的异步任务
   */
  static runWithToken<T>(token: string, task: () => Promise<T>): Promise<T> {
    return this.tokenStore.run(token, task);
  }
}
