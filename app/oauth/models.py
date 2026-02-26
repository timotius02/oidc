import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, String, Text
from sqlalchemy.dialects.postgresql import UUID

from app.db import Base


class OAuthClient(Base):
    __tablename__ = "oauth_clients"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    client_id = Column(String, unique=True, nullable=False)
    client_secret = Column(String, nullable=False)
    redirect_uri = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    name = Column(String, nullable=False)
    logo_uri = Column(Text, nullable=True)
    scopes = Column(Text, nullable=False)

    client_type = Column(String, nullable=False, default="confidential")


class AuthorizationCode(Base):
    __tablename__ = "authorization_codes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    code = Column(String, unique=True, nullable=False)

    user_id = Column(UUID(as_uuid=True), nullable=False)

    redirect_uri = Column(Text, nullable=False)
    scope = Column(Text, nullable=False)
    nonce = Column(Text, nullable=True)  # For OIDC id_token
    client_id = Column(String, nullable=False)

    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    code_challenge = Column(String, nullable=True)  # For PKCE
    code_challenge_method = Column(String, nullable=True)  # For PKCE


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    token = Column(String, unique=True, nullable=False)
    user_id = Column(UUID(as_uuid=True), nullable=False)
    client_id = Column(String, nullable=False)
    scope = Column(Text, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    revoked_at = Column(DateTime, nullable=True)
    revoked_reason = Column(Text, nullable=True)
    is_active = Column(
        String, nullable=False, default="true"
    )  # "true", "revoked", "replaced"
    parent_token_id = Column(UUID(as_uuid=True), nullable=True)
    replaced_by_token_id = Column(UUID(as_uuid=True), nullable=True)
