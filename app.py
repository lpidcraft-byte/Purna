import os
import uuid
import time
import json
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import jwt

from fastapi import (
    FastAPI, HTTPException, Depends,
    UploadFile, File, Request
)
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy import (
    create_engine, Column, String,
    Text, LargeBinary, DateTime,
    ForeignKey, select
)
from sqlalchemy.orm import (
    declarative_base, sessionmaker,
    Session
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


# ==============================
# CONFIGURATION
# ==============================

DATABASE_URL = os.environ["DATABASE_URL"]
MASTER_KEY = os.environ["MASTER_KEY"]
JWT_SECRET = os.environ["JWT_SECRET"]

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace(
        "postgres://", "postgresql+psycopg://", 1
    )

if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace(
        "postgresql://", "postgresql+psycopg://", 1
    )

if len(MASTER_KEY) < 32 or len(JWT_SECRET) < 32:
    raise RuntimeError("Secrets must be at least 32 characters")

KEY = hashlib.sha256(MASTER_KEY.encode()).digest()
cipher = AESGCM(KEY)
password_hasher = PasswordHasher()

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=3,
    max_overflow=2
)

SessionLocal = sessionmaker(
    bind=engine,
    expire_on_commit=False
)

Base = declarative_base()

app = FastAPI(
    title="VANTORIUM CLOUD API",
    description="Secure application backend",
    version="1.0.0"
)


# ==============================
# ENCRYPTION
# ==============================

def encrypt(data: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    return nonce + cipher.encrypt(nonce, data, None)


def decrypt(data: bytes) -> bytes:
    if len(data) < 29:
        raise ValueError("Invalid encrypted data")

    nonce = data[:12]
    return cipher.decrypt(nonce, data[12:], None)


def encrypt_json(value) -> bytes:
    return encrypt(
        json.dumps(value, ensure_ascii=False).encode()
    )


def decrypt_json(value: bytes):
    return json.loads(decrypt(value).decode())


# ==============================
# DATABASE MODELS
# ==============================

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True)
    email = Column(String, unique=True, index=True)
    password = Column(String, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class Project(Base):
    __tablename__ = "projects"

    id = Column(String, primary_key=True)
    owner_id = Column(String, ForeignKey("users.id"), index=True)
    name = Column(String, nullable=False)
    package_name = Column(String, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class Storage(Base):
    __tablename__ = "storage"

    id = Column(String, primary_key=True)
    project_id = Column(String, ForeignKey("projects.id"), index=True)
    key = Column(String, nullable=False)
    value = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class Media(Base):
    __tablename__ = "media"

    id = Column(String, primary_key=True)
    project_id = Column(String, ForeignKey("projects.id"), index=True)
    filename = Column(String, nullable=False)
    content_type = Column(String, nullable=False)
    content = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


Base.metadata.create_all(engine)


# ==============================
# DATABASE SESSION
# ==============================

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ==============================
# RATE LIMITING
# ==============================

requests = {}


def rate_limit(request: Request):
    ip = request.client.host if request.client else "unknown"
    now = time.time()

    record = requests.get(ip, [])

    record = [
        t for t in record
        if now - t < 60
    ]

    if len(record) >= 60:
        raise HTTPException(
            status_code=429,
            detail="Too many requests"
        )

    record.append(now)
    requests[ip] = record


# ==============================
# AUTHENTICATION
# ==============================

def create_token(user_id):
    payload = {
        "sub": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(hours=12),
        "iat": datetime.now(timezone.utc)
    }

    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def current_user(
    request: Request,
    db: Session = Depends(get_db)
):
    authorization = request.headers.get("Authorization", "")

    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authentication required")

    token = authorization[7:]

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"]
        )
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid or expired token")

    user = db.get(User, payload["sub"])

    if not user:
        raise HTTPException(401, "User not found")

    return user


# ==============================
# REQUEST SCHEMAS
# ==============================

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ProjectRequest(BaseModel):
    name: str
    package_name: str


class StorageRequest(BaseModel):
    key: str
    value: dict


# ==============================
# HEALTH
# ==============================

@app.get("/health")
def health(db: Session = Depends(get_db)):
    from sqlalchemy import text

    db.execute(text("SELECT 1"))

    return {
        "status": "online",
        "service": "VANTORIUM CLOUD",
        "database": "connected",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/")
def home():
    return {
        "name": "VANTORIUM CLOUD",
        "version": "1.0.0",
        "status": "online",
        "documentation": "/docs",
        "health": "/health"
    }


# ==============================
# REGISTER
# ==============================

@app.post("/auth/register")
def register(
    data: RegisterRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    rate_limit(request)

    if len(data.password) < 10:
        raise HTTPException(
            400, "Password must have at least 10 characters"
        )

    email = data.email.lower().strip()

    existing = db.scalar(
        select(User).where(User.email == email)
    )

    if existing:
        raise HTTPException(409, "Email already registered")

    user = User(
        id=str(uuid.uuid4()),
        email=email,
        password=password_hasher.hash(data.password)
    )

    db.add(user)
    db.commit()

    return {
        "success": True,
        "token": create_token(user.id),
        "user_id": user.id
    }


# ==============================
# LOGIN
# ==============================

@app.post("/auth/login")
def login(
    data: LoginRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    rate_limit(request)

    user = db.scalar(
        select(User).where(
            User.email == data.email.lower().strip()
        )
    )

    if not user:
        raise HTTPException(401, "Invalid credentials")

    try:
        password_hasher.verify(
            user.password,
            data.password
        )
    except VerifyMismatchError:
        raise HTTPException(401, "Invalid credentials")

    if password_hasher.check_needs_rehash(user.password):
        user.password = password_hasher.hash(data.password)
        db.commit()

    return {
        "success": True,
        "token": create_token(user.id),
        "user_id": user.id
    }


# ==============================
# USER PROFILE
# ==============================

@app.get("/user/me")
def profile(user: User = Depends(current_user)):
    return {
        "id": user.id,
        "email": user.email,
        "created_at": user.created_at
    }


# ==============================
# CREATE PROJECT
# ==============================

@app.post("/projects")
def create_project(
    data: ProjectRequest,
    user: User = Depends(current_user),
    db: Session = Depends(get_db)
):
    if not data.name.strip():
        raise HTTPException(400, "Project name required")

    if len(data.name) > 60:
        raise HTTPException(400, "Project name too long")

    if len(data.package_name) > 150:
        raise HTTPException(400, "Package name too long")

    project = Project(
        id=str(uuid.uuid4()),
        owner_id=user.id,
        name=data.name.strip(),
        package_name=data.package_name.strip()
    )

    db.add(project)
    db.commit()

    return {
        "success": True,
        "project_id": project.id,
        "name": project.name,
        "package_name": project.package_name
    }


# ==============================
# LIST PROJECTS
# ==============================

@app.get("/projects")
def list_projects(
    user: User = Depends(current_user),
    db: Session = Depends(get_db)
):
    projects = db.scalars(
        select(Project).where(
            Project.owner_id == user.id
        )
    ).all()

    return [
        {
            "id": p.id,
            "name": p.name,
            "package_name": p.package_name,
            "created_at": p.created_at
        }
        for p in projects
    ]


# ==============================
# PROJECT PERMISSION
# ==============================

def get_project(project_id, user, db):
    project = db.get(Project, project_id)

    if not project or project.owner_id != user.id:
        raise HTTPException(404, "Project not found")

    return project


# ==============================
# ENCRYPTED STORAGE
# ==============================

@app.put("/projects/{project_id}/storage")
def save_storage(
    project_id: str,
    data: StorageRequest,
    user: User = Depends(current_user),
    db: Session = Depends(get_db)
):
    get_project(project_id, user, db)

    if not data.key or len(data.key) > 100:
        raise HTTPException(400, "Invalid storage key")

    encoded = encrypt_json(data.value)

    entry = db.scalar(
        select(Storage).where(
            Storage.project_id == project_id,
            Storage.key == data.key
        )
    )

    if entry:
        entry.value = encoded
    else:
        db.add(Storage(
            id=str(uuid.uuid4()),
            project_id=project_id,
            key=data.key,
            value=encoded
        ))

    db.commit()

    return {"success": True}


@app.get("/projects/{project_id}/storage/{key}")
def read_storage(
    project_id: str,
    key: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db)
):
    get_project(project_id, user, db)

    entry = db.scalar(
        select(Storage).where(
            Storage.project_id == project_id,
            Storage.key == key
        )
    )

    if not entry:
        raise HTTPException(404, "Data not found")

    return {
        "success": True,
        "key": key,
        "value": decrypt_json(entry.value)
    }


# ==============================
# ENCRYPTED MEDIA STORAGE
# ==============================

@app.post("/projects/{project_id}/media")
async def upload_media(
    project_id: str,
    file: UploadFile = File(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db)
):
    get_project(project_id, user, db)

    allowed = {
        "image/jpeg",
        "image/png",
        "image/webp",
        "video/mp4"
    }

    if file.content_type not in allowed:
        raise HTTPException(415, "Unsupported media type")

    content = await file.read(5 * 1024 * 1024 + 1)

    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(413, "Maximum upload size is 5 MB")

    media = Media(
        id=str(uuid.uuid4()),
        project_id=project_id,
        filename=os.path.basename(file.filename or "upload"),
        content_type=file.content_type,
        content=encrypt(content)
    )

    db.add(media)
    db.commit()

    return {
        "success": True,
        "media_id": media.id
    }


@app.get("/projects/{project_id}/media/{media_id}")
def get_media(
    project_id: str,
    media_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db)
):
    from fastapi.responses import Response

    get_project(project_id, user, db)

    media = db.scalar(
        select(Media).where(
            Media.id == media_id,
            Media.project_id == project_id
        )
    )

    if not media:
        raise HTTPException(404, "Media not found")

    return Response(
        content=decrypt(media.content),
        media_type=media.content_type,
        headers={"X-Content-Type-Options": "nosniff"}
    )


# ==============================
# GAME API
# ==============================

@app.get("/projects/{project_id}/game/status")
def game_status(
    project_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db)
):
    get_project(project_id, user, db)

    return {
        "success": True,
        "project_id": project_id,
        "game_backend": "online"
    }


# ==============================
# SECURITY HEADERS
# ==============================

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"

    return response
