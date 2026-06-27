# Changelog

## [0.1.0] - 2026-06-26

### Added
- JWT token strategy with HS256 signature and configurable expiration
- Random token strategy with UUID-v7 generation
- Session storage: MemoryStore (LRU eviction) and RedisStore (Set-based index with zombie cleanup)
- Login policies: single, multiple, mutual-exclusion with maxSameDeviceSessions support
- RBAC permission engine with wildcard support (e.g. `user:*`)
- Session management: force logout, kick user, ban user, identity switch, sliding renewal, online session query, login history query
- Secondary authentication with independent TTL
- SSO single sign-on with multi-source token extraction (header / cookie / query)
- OAuth2 / OIDC authorization server: authorization_code, password, client_credentials, refresh_token grants
- Refresh Token Rotation with reuse detection
- PKCE support for public clients (SPA/mobile)
- OIDC Discovery endpoint (/.well-known/openid-configuration) and ID Token issuance
- Microservice authentication with gRPC/TCP metadata token extraction and AsyncLocalStorage propagation
- API signature verification: HMAC-SHA256 with timestamp & nonce replay protection
- Login rate limiting: IP + account dual-dimensional, Redis/memory backends
- Device fingerprint binding: IP + User-Agent, strict/warn modes
- Distributed lock: race-condition protection for high-concurrency logins
- Cookie mode: dual token source (Authorization header + Cookie), automatic Cookie expiration refresh
- Remember Me: temporary and long-term session distinction
- Multi-account switching: maintain multiple account login states on same client
- Password encoding: BCrypt and Argon2 encoders
- Data persistence layer: MySQL, PostgreSQL, Oracle, SQLite, MongoDB, in-memory adapters (driver-agnostic design)
- WebSocket authentication: Socket.IO and native WebSocket support
- Unified error codes: module-segmented business error codes with i18n (Chinese/English)
- Audit logging: console, file, and Redis storage backends
- Complete NestJS module system with dynamic registration (register/forConfig)
- Example application in examples/sample-app
- Performance benchmarks using autocannon and k6
- CI/CD pipeline with GitHub Actions (lint, test, build with node_modules cache)
- Bilingual documentation (README.md, README.zh-CN.md)

### Quality
- 31 test suites, 359 test cases, all passing
- Code coverage: 80.97% statements / 65.81% branches / 69.75% functions / 81.97% lines
- Core business logic coverage: >90% (PermissionEngine, RedisStore, Signature, OAuth2, SSO, WebSocket, Microservice)
- Persistence layer modules (factory, module) at 100% coverage
- ESLint zero errors, Nest.js build pass