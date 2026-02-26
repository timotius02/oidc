from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql://postgres:postgres@localhost:5432/authdb"
    JWT_ISSUER: str = "http://localhost:8000"
    ACCESS_TOKEN_EXPIRE_SECONDS: int = 300  # 5 minutes
    REFRESH_TOKEN_EXPIRE_SECONDS: int = 7 * 24 * 3600
    CODE_EXPIRY_SECONDS: int = 600

    PRIVATE_KEY_PATH: str = "private.pem"
    PUBLIC_KEY_PATH: str = "public.pem"


settings = Settings()
