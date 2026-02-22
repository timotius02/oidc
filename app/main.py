from fastapi import FastAPI

from app.jwt import create_access_token

app = FastAPI()

@app.get("/")
def root():
    return {"status": "ok"}

@app.get("/test-token")
def test_token():
    token = create_access_token("user123", "client123")
    return {"access_token": token}