import os
import pyodbc
import jwt
import bcrypt
from datetime import datetime, timedelta
from typing import Union
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel

# JWT Secret Key
SECRET_KEY = "43581f2ce3c30dac3191986e251dba7a8802ad7aa73641265d14744b24f18bdc"
ALGORITHM = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

class Person(BaseModel):
    first_name: str
    last_name: Union[str, None] = None

class User(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

# Update the connection string with the new admin username and password
connection_string = (
    "Driver={ODBC Driver 18 for SQL Server};"
    "Server=tcp:hawkeye-server-test.database.windows.net,1433;"
    "Database=hawkeye-DB-test;"
    "Uid=CloudSA1dee5af2;"
    "Pwd=Hanav@1811;"
    "Encrypt=yes;"
    "TrustServerCertificate=no;"
    "Connection Timeout=30;"
)

app = FastAPI()

# Authentication Helper Functions

def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=30)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )

def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    user_email = payload.get("sub")
    if user_email is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user_email

# Routes

@app.get("/")
def root():
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute("""
            IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='Persons' and xtype='U')
            CREATE TABLE Persons (
                ID int NOT NULL PRIMARY KEY IDENTITY,
                FirstName varchar(255),
                LastName varchar(255)
            );
        """)
        conn.commit()
    except Exception as e:
        print(f"Error: {e}")
    return {"message": "Person API root"}

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

@app.get("/all", dependencies=[Depends(get_current_user)])
def get_persons():
    rows = []
    try:
        with get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM Persons")
            rows = [{"ID": row.ID, "FirstName": row.FirstName, "LastName": row.LastName} for row in cursor.fetchall()]
    except Exception as e:
        print(f"Error: {e}")
    return rows

@app.get("/person/{person_id}", dependencies=[Depends(get_current_user)])
def get_person(person_id: int):
    try:
        with get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM Persons WHERE ID = ?", person_id)
            row = cursor.fetchone()
            if row:
                return {"ID": row.ID, "FirstName": row.FirstName, "LastName": row.LastName}
            else:
                return {"message": "Person not found"}
    except Exception as e:
        print(f"Error: {e}")
    return {"error": "Unable to fetch person"}

@app.post("/person", dependencies=[Depends(get_current_user)])
def create_person(item: Person):
    try:
        with get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO Persons (FirstName, LastName) VALUES (?, ?)", item.first_name, item.last_name)
            conn.commit()
            print(f"Inserted: {item.first_name} {item.last_name}")
    except Exception as e:
        print(f"Error inserting person: {e}")
        return {"error": str(e)}
    return item

def get_conn():
    conn = pyodbc.connect(connection_string)
    return conn
