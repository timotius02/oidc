from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from app.config import settings
from app.oauth.errors import register_oauth_exception_handlers
from app.oauth.jwt import KEYS, create_access_token
from app.oauth.routes import router as oauth_router
from app.routes import auth

app = FastAPI()

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SESSION_SECRET_KEY,
)

app.include_router(auth.router)
app.include_router(oauth_router)

register_oauth_exception_handlers(app)


@app.get("/.well-known/jwks.json")
def jwks():
    """
    OIDC JWKS Endpoint per OpenID Connect Discovery §3.

    Returns the JSON Web Key Set containing public keys
    that clients use to verify JWT tokens.
    """
    return {"keys": [key.to_jwk() for key in KEYS]}


@app.get("/.well-known/openid-configuration")
def openid_configuration():
    """
    OpenID Connect Discovery Document per OpenID Connect Discovery §3.

    Returns metadata about the authorization server including
    endpoint URLs, supported features, and capabilities.
    """
    issuer = settings.JWT_ISSUER

    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oauth/authorize",
        "token_endpoint": f"{issuer}/oauth/token",
        "userinfo_endpoint": f"{issuer}/oauth/userinfo",
        "jwks_uri": f"{issuer}/.well-known/jwks.json",
        "revocation_endpoint": f"{issuer}/oauth/revoke",
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
        ],
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
        ],
        "revocation_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
        ],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": [
            "openid",
            "profile",
            "email",
            "offline_access",
        ],
        "claim_types_supported": ["normal"],
        "claims_supported": [
            "sub",
            "iss",
            "aud",
            "exp",
            "iat",
            "name",
            "family_name",
            "given_name",
            "email",
            "email_verified",
        ],
        "code_challenge_methods_supported": ["S256"],
        "service_documentation": None,
        "ui_locales_supported": ["en"],
    }


@app.get("/")
def root():
    return {"status": "ok"}


@app.get("/test-token")
def test_token():
    token, jti = create_access_token("user123", "client123", "openid profile email")
    return {"access_token": token, "jti": jti}
