import os
import pyodbc
import jwt
import bcrypt
from datetime import datetime, timedelta
from typing import Union
from fastapi import FastAPI, HTTPException
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

# Updated connection string with SQL authentication
connection_string = "Driver={ODBC Driver 18 for SQL Server};Server=tcp:hawkeye-server-test.database.windows.net,1433;Database=hawkeye-DB-test;Uid=Your_Sql_Admin_Username;Pwd=Your_Sql_Admin_Password;Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;"

app = FastAPI()

@app.get("/")
def root():
    return {"message": "Person API root"}

# Person-related endpoints

@app.get("/persons")
def get_persons():
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Persons")
        rows = [{"ID": row.ID, "FirstName": row.FirstName, "LastName": row.LastName} for row in cursor.fetchall()]
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error fetching persons: {str(e)}")
    return rows

@app.get("/person/{person_id}")
def get_person(person_id: int):
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Persons WHERE ID = ?", person_id)
        row = cursor.fetchone()
        if row:
            return {"ID": row.ID, "FirstName": row.FirstName, "LastName": row.LastName}
        else:
            return {"message": "Person not found"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error fetching person: {str(e)}")

@app.post("/person")
def create_person(item: Person):
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO Persons (FirstName, LastName) VALUES (?, ?)", item.first_name, item.last_name)
        conn.commit()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error creating person: {str(e)}")
    return {"message": f"Inserted: {item.first_name} {item.last_name}"}

# User-related endpoints

@app.post("/register", response_model=Token)
def register_user(user: User):
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO Users (Email, HashedPassword) VALUES (?, ?)", user.email, hashed_password)
        conn.commit()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error creating user: {str(e)}")

    token = create_access_token(data={"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/login", response_model=Token)
def login_user(user: User):
    try:
        conn = get_conn()
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
    conn = pyodbc.connect(connection_string)
    return conn
