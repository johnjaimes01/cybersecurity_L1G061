import os
from dotenv import load_dotenv
from fastapi import FastAPI, Form, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base
from pydantic import EmailStr
import hashlib, re

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL") or RuntimeError("DATABASE_URL no definida")
engine = create_engine(DATABASE_URL, echo=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

class Usuario(Base):
    __tablename__ = "usuarios"
    id       = Column(Integer, primary_key=True, index=True)
    nombre   = Column(String(100), nullable=False)
    email    = Column(String(255), unique=True, index=True, nullable=False)
    password = Column(String(64), nullable=False)  

Base.metadata.create_all(engine)
app = FastAPI()
app.add_middleware(
    CORSMiddleware, 
    allow_origins=["http://127.0.0.1:5500","http://localhost:5500","http://127.0.0.1:8000",], 
    allow_methods=["*"], 
    allow_headers=["*"])

def validar_contraseña(pw: str) -> bool:
    return not (len(pw) < 8 
                or not re.search(r"[A-Z]", pw)
                or not re.search(r"[a-z]", pw)
                or not re.search(r"[0-9]", pw)
                or not re.search(r"[!@#\$%\^&\*\,]", pw))

@app.post("/register")
def register(
    nombre: str      = Form(...),
    email: EmailStr  = Form(...),
    password: str    = Form(...)
):
    if not validar_contraseña(password):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Contraseña débil")
    db = SessionLocal()
    try:
        sha = hashlib.sha256(password.encode()).hexdigest()
        nuevo = Usuario(nombre=nombre, email=email, password=sha)
        db.add(nuevo); db.commit()
        db.refresh(nuevo)
    except Exception as e:
        db.rollback()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"No se pudo registrar: {e}")
    finally:
        db.close()
    return {"message": f"Usuario registrado: {email}"}

@app.post("/login")
def login(
    email: EmailStr = Form(...),
    password: str   = Form(...)
):
    db = SessionLocal()
    usuario = db.query(Usuario).filter_by(email=email).first()
    db.close()
    if not usuario:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Usuario no encontrado")
    digest = hashlib.sha256(password.encode()).hexdigest()
    if digest != usuario.password:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Credenciales inválidas")
    return {"message": f"Bienvenido, {usuario.nombre}!"}
