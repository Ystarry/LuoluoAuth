import { Injectable, Inject } from '@nestjs/common';
import type {
  SamlAuthModuleOptions,
  SamlIdentityProviderConfig,
  SamlLoginRequest,
} from './interfaces';
import type { ThirdPartyUserInfo } from '../interfaces';

/**
 * SAML 服务
 * 依赖 samlify（可选 peer dependency），运行时动态导入
 */
@Injectable()
export class SamlService {
  private readonly idpMap: Map<string, SamlIdentityProviderConfig>;

  constructor(
    @Inject('SAML_MODULE_OPTIONS')
    private readonly options: SamlAuthModuleOptions,
  ) {
    this.idpMap = new Map();
    for (const idp of options.identityProviders) {
      this.idpMap.set(idp.id, idp);
    }
  }

  /**
   * 创建向指定 IdP 的登录请求
   * @param idpId IdP 标识
   */
  async createLoginRequest(idpId: string): Promise<SamlLoginRequest> {
    const idp = this.getIdp(idpId);
    const samlify = this.loadSamlify();
    const sp = this.buildServiceProvider(samlify);
    const idpInstance = this.buildIdentityProvider(samlify, idp);

    const binding =
      idp.binding === 'post'
        ? samlify.Constants.namespace.binding.post
        : samlify.Constants.namespace.binding.redirect;

    const { context, entityEndpoint } = sp.createLoginRequest(
      idpInstance,
      binding,
    ) as {
      context: string;
      entityEndpoint: string;
    };

    if (idp.binding === 'post') {
      return {
        postForm: {
          action: entityEndpoint,
          samlRequest: context,
        },
      };
    }

    return {
      redirectUrl: `${entityEndpoint}?${context}`,
    };
  }

  /**
   * 解析 IdP 通过 ACS 回调返回的 SAML Response
   * @param idpId IdP 标识
   * @param samlResponse Base64 编码的 SAMLResponse
   * @param relayState 可选 relay state
   */
  async parseLoginResponse(
    idpId: string,
    samlResponse: string,
    relayState?: string,
  ): Promise<ThirdPartyUserInfo> {
    const idp = this.getIdp(idpId);
    const samlify = this.loadSamlify();
    const sp = this.buildServiceProvider(samlify);
    const idpInstance = this.buildIdentityProvider(samlify, idp);

    const parsed = (await sp.parseLoginResponse(
      idpInstance,
      'post',
      {
        body: {
          SAMLResponse: samlResponse,
          RelayState: relayState,
        },
        query: {},
      } as unknown as Record<string, unknown>,
    )) as {
      extract: {
        nameID?: string;
        attributes?: Record<string, unknown>;
        conditions?: Record<string, unknown>;
      };
    };

    const nameId = parsed.extract.nameID ?? '';
    const attrs = parsed.extract.attributes ?? {};

    return {
      provider: idpId,
      providerUserId: nameId,
      email: this.firstString(attrs, 'email', 'mail', 'Email'),
      username: this.firstString(
        attrs,
        'name',
        'displayName',
        'cn',
        'UserName',
      ),
      raw: {
        nameID: nameId,
        attributes: attrs,
        conditions: parsed.extract.conditions,
      },
    };
  }

  /**
   * 生成 SP metadata XML
   */
  async getServiceProviderMetadata(): Promise<string> {
    const samlify = this.loadSamlify();
    const sp = this.buildServiceProvider(samlify);
    return sp.getMetadata();
  }

  private getIdp(idpId: string): SamlIdentityProviderConfig {
    const idp = this.idpMap.get(idpId);
    if (!idp) {
      throw new Error(`Unknown SAML Identity Provider: ${idpId}`);
    }
    return idp;
  }

  private async loadSamlify(): Promise<SamlifyLike> {
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      return require('samlify') as unknown as SamlifyLike;
    } catch (error) {
      throw new Error(
        'samlify is required for SAML support. Please install it: npm install samlify',
      );
    }
  }

  private buildServiceProvider(samlify: SamlifyLike): SamlEntityLike {
    const { serviceProvider } = this.options;
    return new samlify.ServiceProvider({
      entityID: serviceProvider.entityId,
      assertionConsumerService: [
        {
          Binding: samlify.Constants.namespace.binding.post,
          Location: serviceProvider.assertEndpoint,
        },
      ],
      privateKey: serviceProvider.privateKey,
      signingCert: serviceProvider.certificate,
      wantAssertionsSigned: true,
      wantMessageSigned: false,
    });
  }

  private buildIdentityProvider(
    samlify: SamlifyLike,
    idp: SamlIdentityProviderConfig,
  ): SamlEntityLike {
    if (idp.metadata) {
      return new samlify.IdentityProvider({
        metadata: idp.metadata,
      });
    }

    return new samlify.IdentityProvider({
      entityID: idp.name,
      singleSignOnService: [
        {
          Binding:
            idp.binding === 'post'
              ? samlify.Constants.namespace.binding.post
              : samlify.Constants.namespace.binding.redirect,
          Location: idp.ssoLoginUrl ?? '',
        },
      ],
      signingCert: idp.certificate,
      wantAuthnRequestsSigned: false,
    });
  }

  private firstString(
    attrs: Record<string, unknown>,
    ...keys: string[]
  ): string | undefined {
    for (const key of keys) {
      const value = attrs[key];
      if (typeof value === 'string' && value) {
        return value;
      }
      if (Array.isArray(value) && typeof value[0] === 'string') {
        return value[0];
      }
    }
    return undefined;
  }
}

/**
 * 最小化的 samlify 类型
 */
interface SamlifyLike {
  ServiceProvider: new (config: Record<string, unknown>) => SamlEntityLike;
  IdentityProvider: new (config: Record<string, unknown>) => SamlEntityLike;
  Constants: {
    namespace: {
      binding: {
        post: string;
        redirect: string;
      };
    };
  };
}

interface SamlEntityLike {
  createLoginRequest(
    idp: SamlEntityLike,
    binding: string,
  ): { context: string; entityEndpoint: string };
  parseLoginResponse(
    idp: SamlEntityLike,
    binding: string,
    request: Record<string, unknown>,
  ): Promise<{ extract: { nameID?: string; attributes?: Record<string, unknown>; conditions?: Record<string, unknown> } }>;
  getMetadata(): string;
}
