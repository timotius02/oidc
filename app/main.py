from fastapi import FastAPI
from fastapi.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware

from app.routes import auth
from app.services.jwt import create_access_token
from app.oauth.routes import router as oauth_router
from app.oauth.errors import OAuthError, create_token_error_response

app = FastAPI()

app.add_middleware(
    SessionMiddleware,
    secret_key="dev-secret-session",
)

app.include_router(auth.router)
app.include_router(oauth_router)


@app.exception_handler(OAuthError)
async def oauth_error_handler(request, exc: OAuthError):
    """Handle OAuth errors and return proper error responses."""
    return create_token_error_response(
        error_code=exc.error_code,
        description=exc.description,
        uri=exc.uri
    )


@app.get("/")
def root():
    return {"status": "ok"}


@app.get("/test-token")
def test_token():
    token = create_access_token("user123", "client123")
    return {"access_token": token}