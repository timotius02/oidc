from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql://postgres:postgres@localhost:5432/authdb"
    JWT_ISSUER: str = "http://localhost:8000"
    ACCESS_TOKEN_EXPIRE_SECONDS: int = 3600

    PRIVATE_KEY_PATH: str = "private.pem"
    PUBLIC_KEY_PATH: str = "public.pem"


settings = Settings()