from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from app.oauth.errors import register_oauth_exception_handlers
from app.oauth.jwt import create_access_token
from app.oauth.routes import router as oauth_router
from app.routes import auth

app = FastAPI()

app.add_middleware(
    SessionMiddleware,
    secret_key="dev-secret-session",
)

app.include_router(auth.router)
app.include_router(oauth_router)

# Register OAuth exception handlers from the oauth module
register_oauth_exception_handlers(app)


@app.get("/")
def root():
    return {"status": "ok"}


@app.get("/test-token")
def test_token():
    token, jti = create_access_token("user123", "client123", "openid profile email")
    return {"access_token": token, "jti": jti}
