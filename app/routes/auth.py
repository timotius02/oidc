from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.params import Query
from fastapi.responses import HTMLResponse, RedirectResponse

from app.schemas.user import UserCreate, UserLogin
from app.security.csrf import generate_csrf_token, verify_csrf
from app.services.auth import UserService
from app.templates_config import templates

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register")
def register(
    data: UserCreate,
    user_service: Annotated[UserService, Depends(UserService)],
):
    existing = user_service.get_user_by_email(data.email)
    if existing:
        raise HTTPException(400, "Email already registered")

    user = user_service.create_user(data.email, data.password)

    return {"id": user.id, "email": user.email}


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = Query("/")):
    csrf_token = generate_csrf_token(request)
    return templates.TemplateResponse(
        request,
        "login.html",
        {"next": next, "csrf_token": csrf_token},
    )


@router.post("/login")
def login(
    request: Request,
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    user_service: Annotated[UserService, Depends(UserService)],
    next: Annotated[str, Form()] = "/",
    _: None = Depends(verify_csrf),
):
    # Validate via schema (optional but good for consistency)
    data = UserLogin(email=email, password=password)
    user = user_service.authenticate_user(data.email, data.password)

    if not user:
        # Re-render login page with error (and new CSRF token)
        csrf_token = generate_csrf_token(request)
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "next": next,
                "error": "Invalid email or password",
                "csrf_token": csrf_token,
            },
        )

    request.session["user_id"] = str(user.id)

    # Redirect to the next page (authorize or default)
    return RedirectResponse(next, status_code=302)
