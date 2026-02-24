from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.params import Query
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.user import User
from app.schemas.user import UserCreate
from app.services.auth import hash_password, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register")
def register(data: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == data.email).first()
    if existing:
        raise HTTPException(400, "Email already registered")

    user = User(
        email=data.email,
        password_hash=hash_password(data.password),
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return {"id": user.id, "email": user.email}


@router.get("/login", response_class=HTMLResponse)
def login_page(next: str = Query("/")):  # default redirect is "/"
    return f"""
    <html>
        <body>
            <h2>Login</h2>
            <form method="post" action="/auth/login">
                <input name="email" placeholder="Email" />
                <input name="password" type="password" placeholder="Password" />
                <input type="hidden" name="next" value="{next}" />
                <button type="submit">Login</button>
            </form>
        </body>
    </html>
    """


@router.post("/login")
def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    next: str = Form("/"),  # get from the hidden input
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.email == email).first()

    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(401, "Invalid credentials")

    request.session["user_id"] = str(user.id)

    # Redirect to the next page (authorize or default)
    return RedirectResponse(next, status_code=302)
