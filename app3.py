import os
import pyodbc
import struct
import jwt
import bcrypt
from datetime import datetime, timedelta
from azure.identity import ManagedIdentityCredential
from typing import Union
from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel

# JWT Secret Key
SECRET_KEY = "43581f2ce3c30dac3191986e251dba7a8802ad7aa73641265d14744b24f18bdc"

class Person(BaseModel):
    first_name: str
    last_name: Union[str, None] = None

class User(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

connection_string = "Driver={ODBC Driver 18 for SQL Server};Server=tcp:hawkeye-server-test.database.windows.net,1433;Database=hawkeye-DB-test;Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;"
app = FastAPI()

@app.get("/")
def root():
    return {"message": "Person API root"}

@app.post("/register", response_model=Token)
def register_user(user: User):
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())
    try:
        with get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO Users (Email, HashedPassword) VALUES (?, ?)", user.email, hashed_password.decode('utf-8'))
            conn.commit()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error creating user: {str(e)}")

    token = create_access_token(data={"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/login", response_model=Token)
def login_user(user: User):
    try:
        with get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT HashedPassword FROM Users WHERE Email = ?", user.email)
            db_user = cursor.fetchone()
            if not db_user or not bcrypt.checkpw(user.password.encode('utf-8'), db_user.HashedPassword.encode('utf-8')):
                raise HTTPException(status_code=401, detail="Invalid credentials")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error logging in: {str(e)}")

    token = create_access_token(data={"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}

def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=30)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")
    return encoded_jwt

def get_conn():
    credential = ManagedIdentityCredential(client_id="56c8d02d-a909-4474-877e-bce444dfc54e")
    token_bytes = credential.get_token("https://database.windows.net/.default").token.encode("UTF-16-LE")
    token_struct = struct.pack(f'<I{len(token_bytes)}s', len(token_bytes), token_bytes)
    SQL_COPT_SS_ACCESS_TOKEN = 1256  # Connection option defined in msodbcsql.h
    conn = pyodbc.connect(connection_string, attrs_before={SQL_COPT_SS_ACCESS_TOKEN: token_struct})
    return conn
