from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql://postgres:postgres@localhost:5432/authdb"
    JWT_ISSUER: str = "http://localhost:8000"
    ACCESS_TOKEN_EXPIRE_SECONDS: int = 300  # 5 minutes
    ID_TOKEN_EXPIRE_SECONDS: int = 3600  # 1 hour
    REFRESH_TOKEN_EXPIRE_SECONDS: int = 7 * 24 * 3600
    CODE_EXPIRY_SECONDS: int = 600

    # Current signing key (active)
    PRIVATE_KEY_PATH: str = "private.pem"
    PUBLIC_KEY_PATH: str = "public.pem"
    CURRENT_KEY_ID: str = "current-key-1"

    # Next key for rotation (optional - leave empty if not using dual keys)
    NEXT_PRIVATE_KEY_PATH: str = "private-next.pem"
    NEXT_PUBLIC_KEY_PATH: str = "public-next.pem"
    NEXT_KEY_ID: str = "next-key-1"

    SESSION_SECRET_KEY: str = "dev-secret-session"


settings = Settings()
