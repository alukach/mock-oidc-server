# Mock OIDC Server

A simple mock OpenID Connect server for development and testing purposes.

## Features

- OpenID Connect Authorization Code Flow
- PKCE Support
- JWT Token Generation
- CORS Support
- Simple Login UI

## Development Setup

### Using uv (Recommended)

1. Install dependencies:

   ```bash
   uv sync
   ```

2. Run the server:

```bash
uv run app.py
```

### Using Docker

1. Build the image:

```bash
docker build -t mock-oidc-server .
```

2. Run the container:

```bash
docker run -p 8888:8888 mock-oidc-server
```

## Configuration

The server can be configured using environment variables:

- `ISSUER`: The OIDC issuer URL (default: http://localhost:3000)
- `SCOPES`: Additional scopes to support (comma-separated)
- `PORT`: The port to run on (default: 8888)

## Endpoints

- `/.well-known/openid-configuration`: OIDC configuration endpoint
- `/.well-known/jwks.json`: JSON Web Key Set endpoint
- `/authorize`: Authorization endpoint
- `/token`: Token endpoint

## Warning

This is a mock server intended for development and testing purposes only. Do not use in production environments.
