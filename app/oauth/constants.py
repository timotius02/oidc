from enum import Enum


class GrantType(str, Enum):
    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"
    CLIENT_CREDENTIALS = "client_credentials"


class ResponseType(str, Enum):
    CODE = "code"


class ClientType(str, Enum):
    CONFIDENTIAL = "confidential"
    PUBLIC = "public"


class CodeChallengeMethod(str, Enum):
    S256 = "S256"
    PLAIN = "plain"
