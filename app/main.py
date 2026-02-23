from fastapi import FastAPI

from app.routes import auth
from app.services.jwt import create_access_token

app = FastAPI()

app.include_router(auth.router)

@app.get("/")
def root():
    return {"status": "ok"}

@app.get("/test-token")
def test_token():
    token = create_access_token("user123", "client123")
    return {"access_token": token}