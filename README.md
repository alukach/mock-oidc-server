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

- `ISSUER`: The OIDC issuer URL, including path when served at non-root (default: http://localhost:8888)
- `SCOPES`: Additional scopes to support (comma-separated)
- `PORT`: The port to run on (default: 8888)

## Usage

### Generate a token via CLI

```bash
curl http://localhost:8888/ \
  --data-raw 'username=testuser&scopes=openid+profile&claims={"email":"test@example.com"}' \
  -H "Accept: application/json"
```

The response includes the signed JWT and decoded token body:

```json
{
  "token": "eyJhbGciOiJS...",
  "token_body": {
    "iss": "http://localhost:8888",
    "sub": "testuser",
    "scope": "openid profile",
    "email": "test@example.com"
  }
}
```

### Generate a token via browser

Open `http://localhost:8888/` in your browser. Fill in the username, scopes, and any custom claims in the form, then submit to receive a signed JWT.

### Authorization Code Flow

The server implements the standard OIDC Authorization Code Flow for use with applications that need to authenticate users:

1. Your app redirects the user to `/authorize` with the required parameters (`response_type=code`, `client_id`, `redirect_uri`, `state`, and optionally `scope`, `nonce`, `code_challenge`, `code_challenge_method`).
2. The user sees a login form and submits a username and optional custom claims.
3. The server redirects back to your app's `redirect_uri` with an authorization `code` and `state`.
4. Your app exchanges the code for tokens by POSTing to `/token`.

PKCE (`S256`) is supported.

### Discovery endpoints

- `/.well-known/openid-configuration` — OIDC discovery document with all supported endpoints, scopes, and capabilities.
- `/.well-known/jwks.json` — The public key set used to verify token signatures.

## Warning

This is a mock server intended for development and testing purposes only. Do not use in production environments.
