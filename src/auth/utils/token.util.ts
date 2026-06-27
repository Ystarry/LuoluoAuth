/**
 * 类 gRPC Metadata 对象
 */
interface GrpcMetadataLike {
  /** 获取 metadata 键值映射 */
  getMap(): Record<string, unknown>;
}

/**
 * 从请求头中提取 Bearer Token
 * @param authHeader - Authorization 请求头值
 * @returns Token 字符串，未找到则返回 undefined
 */
export function extractBearerToken(
  authHeader: string | undefined,
): string | undefined {
  if (!authHeader) {
    return undefined;
  }

  const [type, token] = authHeader.split(' ');
  return type === 'Bearer' ? token : undefined;
}

/**
 * 判断对象是否为类 gRPC Metadata
 * @param value - 待检测值
 * @returns 是否为类 gRPC Metadata
 */
function isGrpcMetadata(value: unknown): value is GrpcMetadataLike {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as GrpcMetadataLike).getMap === 'function'
  );
}

/**
 * 从 gRPC metadata 或 TCP 上下文中提取 Token
 * @param rpcContext - RPC 上下文对象
 * @returns Token 字符串，未找到则返回 undefined
 */
export function extractTokenFromRpcContext(
  rpcContext: unknown,
): string | undefined {
  if (!rpcContext) {
    return undefined;
  }

  // gRPC 场景：从 metadata 中提取
  if (isGrpcMetadata(rpcContext)) {
    const metadata = rpcContext.getMap();
    const authHeader = metadata['authorization'] || metadata['Authorization'];
    if (typeof authHeader === 'string') {
      return extractBearerToken(authHeader) || authHeader;
    }
    return undefined;
  }

  // TCP / Redis / MQTT 等场景：从 context 对象中提取
  if (typeof rpcContext === 'object') {
    const ctx = rpcContext as Record<string, unknown>;
    const authHeader = ctx['authorization'] || ctx['Authorization'];
    if (typeof authHeader === 'string') {
      return extractBearerToken(authHeader) || authHeader;
    }
  }

  return undefined;
}
