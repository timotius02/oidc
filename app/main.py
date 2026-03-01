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


@app.get("/")
def root():
    return {"status": "ok"}


@app.get("/test-token")
def test_token():
    token, jti = create_access_token("user123", "client123", "openid profile email")
    return {"access_token": token, "jti": jti}
