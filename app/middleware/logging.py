import json
import logging
import sys
from datetime import UTC, datetime

# Configure root logger for JSON output
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

# Create dedicated loggers
auth_logger = logging.getLogger("auth")
oauth_logger = logging.getLogger("oauth")
security_logger = logging.getLogger("security")


def _json_log(
    logger: logging.Logger,
    level: int,
    event: str,
    **kwargs,
) -> None:
    """Emit a structured JSON log entry."""
    record = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event": event,
        **kwargs,
    }
    logger.log(level, json.dumps(record))


def log_auth_success(user_id: str, email: str, request_id: str | None = None) -> None:
    """Log successful authentication."""
    _json_log(
        auth_logger,
        logging.INFO,
        "auth_success",
        user_id=user_id,
        email=email,
        request_id=request_id,
    )


def log_auth_failure(email: str, reason: str, request_id: str | None = None) -> None:
    """Log failed authentication attempt."""
    _json_log(
        auth_logger,
        logging.WARNING,
        "auth_failure",
        email=email,
        reason=reason,
        request_id=request_id,
    )


def log_token_issued(
    grant_type: str,
    client_id: str,
    user_id: str | None,
    scope: str,
    request_id: str | None = None,
) -> None:
    """Log token issuance."""
    _json_log(
        oauth_logger,
        logging.INFO,
        "token_issued",
        grant_type=grant_type,
        client_id=client_id,
        user_id=user_id,
        scope=scope,
        request_id=request_id,
    )


def log_token_revoked(
    client_id: str,
    token_type: str,
    reason: str,
    request_id: str | None = None,
) -> None:
    """Log token revocation."""
    _json_log(
        oauth_logger,
        logging.INFO,
        "token_revoked",
        client_id=client_id,
        token_type=token_type,
        reason=reason,
        request_id=request_id,
    )


def log_consent_action(
    user_id: str,
    client_id: str,
    action: str,
    scope: str,
    request_id: str | None = None,
) -> None:
    """Log user consent decisions."""
    _json_log(
        oauth_logger,
        logging.INFO,
        "consent_action",
        user_id=user_id,
        client_id=client_id,
        action=action,
        scope=scope,
        request_id=request_id,
    )


def log_security_event(
    event: str,
    client_id: str | None = None,
    ip: str | None = None,
    details: str | None = None,
    request_id: str | None = None,
) -> None:
    """Log security-relevant events (replay attacks, invalid tokens, etc.)."""
    _json_log(
        security_logger,
        logging.WARNING,
        event,
        client_id=client_id,
        ip=ip,
        details=details,
        request_id=request_id,
    )


def log_logout(
    user_id: str,
    client_id: str | None = None,
    request_id: str | None = None,
) -> None:
    """Log user logout events."""
    _json_log(
        auth_logger,
        logging.INFO,
        "logout",
        user_id=user_id,
        client_id=client_id,
        request_id=request_id,
    )
