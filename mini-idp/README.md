# mini-idp

A minimal local OIDC-style issuer for JWT testing.

## Features

- `/.well-known/openid-configuration`
- `/jwks.json`
- `/token` to mint real RS256 JWTs
- `/rotate` to rotate signing keys
- `/keys` to inspect current/generated keys as PEM + JWK

## Requirements

- Node.js 18+

## Install

```bash
npm install
```

## Run

```bash
npm start
```

By default it runs on `http://localhost:8080`.

## Endpoints

### Discovery

```bash
curl http://localhost:8080/.well-known/openid-configuration
```

### JWKS

```bash
curl http://localhost:8080/jwks.json
```

### Mint a token

```bash
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/json" \
  -d '{
    "sub": "alice",
    "aud": "test-api",
    "scope": "read write",
    "expires_in": 3600,
    "claims": {
      "preferred_username": "alice",
      "groups": ["admin", "dev"]
    }
  }'
```

### Rotate active key

```bash
curl -X POST http://localhost:8080/rotate \
  -H "Content-Type: application/json" \
  -d '{"kid":"key2","keep_old":true}'
```

### Inspect keys

```bash
curl http://localhost:8080/keys
```

## Environment variables

- `PORT` default `8080`
- `HOST` default `localhost`
- `ISSUER` default `http://localhost:$PORT`
- `AUDIENCE` default `test-api`
- `SCOPE` default `read write`
- `KID` default `key1`
- `EXPIRES_IN` default `3600`

## Spring Boot

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://localhost:8080
```

## Quarkus

```properties
quarkus.oidc.application-type=service
quarkus.oidc.auth-server-url=http://localhost:8080
quarkus.oidc.client-id=test-api
```
