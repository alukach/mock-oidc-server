# Mock OIDC Server

A simple mock OpenID Connect server for development and testing purposes.

## Features

- OpenID Connect Authorization Code Flow
- PKCE Support
- JWT Token Generation
- CORS Support
- Simple Login UI

## Running with Docker

```bash
docker run -it --rm -p 8080:8080 ghcr.io/alukach/mock-oidc-server:latest
```

## Development Setup

### Local installation

1. Install dependencies:

   ```bash
   uv sync
   ```

2. Run the server:

   ```bash
   uv run python -m app
   ```

## Configuration

The server can be configured using environment variables:

- `ISSUER`: The OIDC issuer URL (default: http://localhost:3000)
- `SCOPES`: Additional scopes to support (comma-separated)
- `PORT`: The port to run on (default: 8888)
- `ROOT_PATH`: Optional path at which the mokc server should be served from; useful when serving behind a reverse proxy

## Endpoints

- `/.well-known/openid-configuration`: OIDC configuration endpoint
- `/.well-known/jwks.json`: JSON Web Key Set endpoint
- `/authorize`: Authorization endpoint
- `/token`: Token endpoint

## Warning

This is a mock server intended for development and testing purposes only. Do not use in production environments.
