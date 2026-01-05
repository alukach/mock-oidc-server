# type: ignore
# ruff: noqa
"""Mock OIDC server for demo/experimentation."""

import base64
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jose import jwt

# Configuration
ISSUER = os.environ.get("ISSUER", "http://localhost:3000")
AVAILABLE_SCOPES = os.environ.get("SCOPES", "")
STATIC_PATH_PREFIX = os.environ.get("STATIC_PATH_PREFIX", "")

# Prefix validation
VALID_PREFIX_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$")

app = FastAPI()


def validate_prefix(prefix: str) -> str:
    """Validate and normalize path prefix."""
    if not prefix:
        return ""
    prefix = prefix.strip("/")
    if not VALID_PREFIX_PATTERN.match(prefix):
        raise HTTPException(
            400, "Invalid prefix: must be alphanumeric with hyphens/underscores"
        )
    return prefix


def build_url(endpoint: str, prefix: str = "") -> str:
    """Build endpoint URL with optional prefix."""
    base = ISSUER.rstrip("/")
    prefix = validate_prefix(prefix)
    endpoint = endpoint.lstrip("/")
    return f"{base}/{prefix}/{endpoint}" if prefix else f"{base}/{endpoint}"


# Configure static files
static_mount_path = (
    f"/{STATIC_PATH_PREFIX.strip('/')}/static"
    if STATIC_PATH_PREFIX
    else "/static"
)
app.mount(
    static_mount_path,
    StaticFiles(directory=str(Path(__file__).parent / "static")),
    name="static",
)

# Configure templates
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Type"],
    max_age=86400,  # 24 hours
)


@dataclass
class KeyPair:
    cache_dir: Path
    key_id: str = "1"

    jwks: dict = field(init=False)
    private_key: str = field(init=False)

    def __post_init__(self):
        private_key_path = self.cache_dir / "private_key.pem"
        jwks_path = self.cache_dir / "jwks.json"

        if private_key_path.exists() and jwks_path.exists():
            self.jwks = json.loads(jwks_path.read_text())
            self.private_key = private_key_path.read_text()
            return

        # Generate keys
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()

        self.jwks = {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": self.key_id,
                    "alg": "RS256",
                    "n": self.int_to_base64url(public_numbers.n),
                    "e": self.int_to_base64url(public_numbers.e),
                }
            ]
        }
        self.private_key = private_pem.decode("utf-8")

        private_key_path.write_text(self.private_key)
        jwks_path.write_text(json.dumps(self.jwks, indent=2))

    @staticmethod
    def int_to_base64url(value):
        """Convert an integer to base64url format."""
        value_hex = format(value, "x")
        # Ensure even length
        if len(value_hex) % 2 == 1:
            value_hex = "0" + value_hex
        value_bytes = bytes.fromhex(value_hex)
        return (
            base64.urlsafe_b64encode(value_bytes).rstrip(b"=").decode("ascii")
        )


# Load or generate key pair on startup
KEY_PAIR = KeyPair(Path(__file__).parent)

# In-memory storage
authorization_codes = {}
pkce_challenges = {}
access_tokens = {}
auth_requests = {}


@app.get("/.well-known/openid-configuration")
async def openid_configuration(prefix: str = ""):
    """Return OpenID Connect configuration."""
    prefix = validate_prefix(prefix)
    scopes_set = set(["openid", "profile", *AVAILABLE_SCOPES.split(",")])
    return {
        "issuer": ISSUER,
        "authorization_endpoint": build_url("authorize", prefix),
        "token_endpoint": build_url("token", prefix),
        "userinfo_endpoint": build_url("userinfo", prefix),
        "jwks_uri": build_url(".well-known/jwks.json", prefix),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": sorted(scopes_set),
        "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
        "claims_supported": [
            "sub",
            "iss",
            "aud",
            "iat",
            "exp",
            "nonce",
            "name",
            "preferred_username",
            "email",
            "email_verified",
            "picture",
        ],
        "code_challenge_methods_supported": ["S256"],
        "grant_types_supported": ["authorization_code"],
        "response_modes_supported": ["query"],
    }


@app.get("/{prefix:path}/.well-known/openid-configuration")
async def openid_configuration_prefixed(prefix: str):
    """Return OpenID Connect configuration with path prefix support."""
    return await openid_configuration(prefix)


@app.get("/.well-known/jwks.json")
async def jwks():
    """Return JWKS (JSON Web Key Set)."""
    return KEY_PAIR.jwks


@app.get("/{prefix:path}/.well-known/jwks.json")
async def jwks_prefixed(prefix: str):
    """Return JWKS with path prefix support for ingress routing."""
    validate_prefix(prefix)
    return KEY_PAIR.jwks


@app.get("/authorize")
async def authorize(
    request: Request,
    response_type: str,
    client_id: str,
    redirect_uri: str,
    state: str,
    scope: str = "",
    code_challenge: Optional[str] = None,
    code_challenge_method: Optional[str] = None,
    nonce: Optional[str] = None,
    prefix: str = "",
):
    """Handle authorization request."""
    if response_type != "code":
        raise HTTPException(status_code=400, detail="Invalid response type")

    # Validate PKCE if provided
    if code_challenge is not None:
        if code_challenge_method != "S256":
            raise HTTPException(
                status_code=400, detail="Only S256 PKCE is supported"
            )

    # Store the auth request details
    request_id = os.urandom(16).hex()
    auth_requests[request_id] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "scope": scope,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "nonce": nonce,
    }

    # Show login page
    prefix = validate_prefix(prefix)
    login_url = build_url("login", prefix)
    scopes = sorted(set(("openid profile " + scope).split()))
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "request_id": request_id,
            "client_id": client_id,
            "scopes": scopes,
            "login_url": login_url,
        },
    )


@app.get("/{prefix:path}/authorize")
async def authorize_prefixed(
    request: Request,
    prefix: str,
    response_type: str,
    client_id: str,
    redirect_uri: str,
    state: str,
    scope: str = "",
    code_challenge: Optional[str] = None,
    code_challenge_method: Optional[str] = None,
    nonce: Optional[str] = None,
):
    """Handle authorization request with path prefix support."""
    return await authorize(
        request,
        response_type,
        client_id,
        redirect_uri,
        state,
        scope,
        code_challenge,
        code_challenge_method,
        nonce,
        prefix,
    )


@app.post("/login")
async def login(request_id: str = Form(...), username: str = Form(...)):
    """Handle login form submission."""
    # Retrieve the stored auth request
    if request_id not in auth_requests:
        raise HTTPException(status_code=400, detail="Invalid request")

    auth_request = auth_requests.pop(request_id)

    # Generate authorization code
    code = os.urandom(32).hex()

    # Store authorization details
    authorization_codes[code] = {
        "client_id": auth_request["client_id"],
        "redirect_uri": auth_request["redirect_uri"],
        "scope": " ".join(
            sorted(set(("openid profile " + auth_request["scope"]).split(" ")))
        ),
        "username": username,
        "nonce": auth_request.get("nonce"),
        "created_at": datetime.now(UTC),
    }

    # Store PKCE challenge if provided
    if auth_request["code_challenge"]:
        pkce_challenges[code] = auth_request["code_challenge"]

    # Redirect back to client with the code
    params = {"code": code, "state": auth_request["state"]}
    return RedirectResponse(
        url=f"{auth_request['redirect_uri']}?{urlencode(params)}",
        status_code=303,
    )


@app.post("/{prefix:path}/login")
async def login_prefixed(
    prefix: str, request_id: str = Form(...), username: str = Form(...)
):
    """Handle login form submission with path prefix support."""
    validate_prefix(prefix)
    return await login(request_id, username)


@app.get("/")
async def token_form(request: Request):
    """Show token generation form."""
    return templates.TemplateResponse(
        "token.html",
        {
            "request": request,
            "token": None,
        },
    )


@app.post("/")
async def generate_token(
    request: Request,
    username: str = Form(...),
    scopes: str = Form(...),
):
    """Generate a JWT token with the specified parameters."""
    now = datetime.now(UTC)
    expires_delta = timedelta(minutes=15)

    token = jwt.encode(
        {
            "iss": ISSUER,
            "sub": username,
            "iat": now,
            "exp": now + expires_delta,
            "scope": scopes,
            "kid": KEY_PAIR.key_id,
        },
        KEY_PAIR.private_key,
        algorithm="RS256",
        headers={"kid": KEY_PAIR.key_id},
    )

    return templates.TemplateResponse(
        "token.html",
        {
            "request": request,
            "token": token,
        },
    )


@app.post("/token")
async def token(
    grant_type: str = Form(...),
    code: str = Form(...),
    redirect_uri: str = Form(...),
    client_id: str = Form(...),
    client_secret: Optional[str] = Form(None),
    code_verifier: Optional[str] = Form(None),
):
    """Handle token request."""
    if grant_type != "authorization_code":
        raise HTTPException(status_code=400, detail="Invalid grant type")

    # Verify the authorization code exists
    if code not in authorization_codes:
        raise HTTPException(
            status_code=400, detail="Invalid authorization code"
        )

    auth_details = authorization_codes[code]

    # Check if authorization code has expired (10 minute lifetime)
    code_age = datetime.now(UTC) - auth_details["created_at"]
    if code_age > timedelta(minutes=10):
        del authorization_codes[code]
        if code in pkce_challenges:
            del pkce_challenges[code]
        raise HTTPException(
            status_code=400, detail="Authorization code expired"
        )

    # Verify client_id matches the stored one
    if client_id != auth_details["client_id"]:
        raise HTTPException(status_code=400, detail="Client ID mismatch")

    # Verify redirect_uri matches the stored one
    if redirect_uri != auth_details["redirect_uri"]:
        raise HTTPException(status_code=400, detail="Redirect URI mismatch")

    # Check if PKCE was used in the authorization request
    if code in pkce_challenges:
        if not code_verifier:
            raise HTTPException(
                status_code=400, detail="Code verifier required"
            )

        # Verify the code verifier
        code_challenge = pkce_challenges[code]
        computed_challenge = hashlib.sha256(code_verifier.encode()).digest()
        computed_challenge = (
            base64.urlsafe_b64encode(computed_challenge).decode().rstrip("=")
        )

        if computed_challenge != code_challenge:
            raise HTTPException(status_code=400, detail="Invalid code verifier")

    # Clean up the used code and PKCE challenge
    del authorization_codes[code]
    if code in pkce_challenges:
        del pkce_challenges[code]

    # Generate tokens
    now = datetime.now(UTC)
    expires_delta = timedelta(minutes=15)
    username = auth_details.get("username", "user123")

    # Generate access token
    access_token = jwt.encode(
        {
            "iss": ISSUER,
            "sub": username,
            "iat": now,
            "exp": now + expires_delta,
            "scope": auth_details["scope"],
            "kid": KEY_PAIR.key_id,
        },
        KEY_PAIR.private_key,
        algorithm="RS256",
        headers={"kid": KEY_PAIR.key_id},
    )

    # Generate ID token (required for OIDC)
    id_token_claims = {
        "iss": ISSUER,
        "sub": username,
        "aud": client_id,
        "iat": now,
        "exp": now + expires_delta,
    }

    # Include nonce if it was provided in the auth request
    if auth_details.get("nonce"):
        id_token_claims["nonce"] = auth_details["nonce"]

    id_token = jwt.encode(
        id_token_claims,
        KEY_PAIR.private_key,
        algorithm="RS256",
        headers={"kid": KEY_PAIR.key_id},
    )

    # Store access token for userinfo endpoint
    access_tokens[access_token] = {
        "username": username,
        "scope": auth_details["scope"],
        "client_id": client_id,
        "expires_at": now + expires_delta,
    }

    return JSONResponse(
        content={
            "access_token": access_token,
            "id_token": id_token,
            "token_type": "Bearer",
            "expires_in": expires_delta.seconds,
            "scope": auth_details["scope"],
        }
    )


@app.post("/{prefix:path}/token")
async def token_prefixed(
    prefix: str,
    grant_type: str = Form(...),
    code: str = Form(...),
    redirect_uri: str = Form(...),
    client_id: str = Form(...),
    client_secret: Optional[str] = Form(None),
    code_verifier: Optional[str] = Form(None),
):
    """Handle token request with path prefix support."""
    validate_prefix(prefix)
    return await token(
        grant_type, code, redirect_uri, client_id, client_secret, code_verifier
    )


@app.get("/userinfo")
async def userinfo(request: Request):
    """Return user claims based on the access token."""
    # Extract the access token from the Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401, detail="Missing or invalid Authorization header"
        )

    access_token = auth_header[7:]  # Remove "Bearer " prefix

    # Verify the access token exists and is valid
    if access_token not in access_tokens:
        raise HTTPException(status_code=401, detail="Invalid access token")

    token_data = access_tokens[access_token]

    # Check if token has expired
    if datetime.now(UTC) > token_data["expires_at"]:
        del access_tokens[access_token]
        raise HTTPException(status_code=401, detail="Access token expired")

    # Return user claims
    # In a real implementation, you would fetch these from a user database
    # and filter based on the requested scopes
    user_info = {
        "sub": token_data["username"],
    }

    # Add profile claims if profile scope is requested
    scopes = token_data["scope"].split()
    if "profile" in scopes:
        user_info.update(
            {
                "name": token_data["username"],
                "preferred_username": token_data["username"],
            }
        )

    if "email" in scopes:
        user_info.update(
            {
                "email": f"{token_data['username']}@example.com",
                "email_verified": True,
            }
        )

    return user_info


@app.get("/{prefix:path}/userinfo")
async def userinfo_prefixed(prefix: str, request: Request):
    """Return user claims with path prefix support."""
    validate_prefix(prefix)
    return await userinfo(request)
