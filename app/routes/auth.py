from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.params import Query
from fastapi.responses import HTMLResponse, RedirectResponse

from app.schemas.user import UserCreate
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
    return templates.TemplateResponse(
        request,
        "login.html",
        {"next": next},
    )


@router.post("/login")
def login(
    request: Request,
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    user_service: Annotated[UserService, Depends(UserService)],
    next: Annotated[str, Form()] = "/",
):
    user = user_service.authenticate_user(email, password)

    if not user:
        # Re-render login page with error
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "next": next,
                "error": "Invalid email or password",
            },
        )

    request.session["user_id"] = str(user.id)

    # Redirect to the next page (authorize or default)
    return RedirectResponse(next, status_code=302)
