import { Test, TestingModule } from '@nestjs/testing';
import { SamlService } from './saml.service';
import type { SamlAuthModuleOptions } from './interfaces';

const spConfig: SamlAuthModuleOptions['serviceProvider'] = {
  entityId: 'https://app.example.com/sp',
  assertEndpoint: 'https://app.example.com/auth/saml/okta/acs',
};

const idpConfig: SamlAuthModuleOptions['identityProviders'][0] = {
  id: 'okta',
  name: 'Okta',
  ssoLoginUrl: 'https://okta.example.com/app/saml/sso',
  certificate: undefined,
};

const options: SamlAuthModuleOptions = {
  serviceProvider: spConfig,
  identityProviders: [idpConfig],
  loginHandler: async (userInfo) => ({
    userId: `saml_${userInfo.providerUserId}`,
    roles: ['user'],
  }),
};

describe('SamlService', () => {
  let service: SamlService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SamlService,
        { provide: 'SAML_MODULE_OPTIONS', useValue: options },
      ],
    }).compile();

    service = module.get<SamlService>(SamlService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('should throw for unknown idp', async () => {
    await expect(service.createLoginRequest('unknown')).rejects.toThrow(
      'Unknown SAML Identity Provider: unknown',
    );
  });

  it('should create redirect login request', async () => {
    const request = await service.createLoginRequest('okta');
    expect(request.redirectUrl).toBeDefined();
    expect(request.redirectUrl).toContain('okta.example.com');
    expect(request.redirectUrl).toContain('SAMLRequest=');
  });

  it('should generate SP metadata', async () => {
    const metadata = await service.getServiceProviderMetadata();
    expect(metadata).toContain('EntityDescriptor');
    expect(metadata).toContain(spConfig.entityId);
    expect(metadata).toContain(spConfig.assertEndpoint);
  });
});
