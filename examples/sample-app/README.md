# Sample Auth App

A complete NestJS example demonstrating `luoluo-auth` features:

- JWT login with cookie support
- Role / permission guards
- Online session query
- Multi-account switching
- OAuth2 / OIDC authorization server

## Run

```bash
# From repository root
npm run build
npm run example:start
```

The app starts on `http://localhost:3100`.

## Demo Accounts

| userId  | roles | permissions       |
|---------|-------|-------------------|
| alice   | user  | profile:read      |
| admin   | admin | *                 |

## Example Requests

```bash
# Login
curl -X POST http://localhost:3100/user/login \
  -H 'Content-Type: application/json' \
  -d '{"userId":"alice","device":"web"}'

# Access protected route
curl http://localhost:3100/user/profile \
  -H 'Authorization: Bearer <token>'

# OAuth2 password grant
curl -X POST http://localhost:3100/oauth/token \
  -H 'Content-Type: application/json' \
  -d '{
    "grant_type":"password",
    "client_id":"sample-confidential-client",
    "client_secret":"sample-confidential-secret",
    "username":"alice",
    "password":"secret"
  }'
```
