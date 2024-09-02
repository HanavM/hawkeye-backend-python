import os
import pyodbc
import struct
from azure.identity import DefaultAzureCredential
from typing import Union
from fastapi import FastAPI
from pydantic import BaseModel

class Person(BaseModel):
    first_name: str
    last_name: Union[str, None] = None

connection_string = "Driver={ODBC Driver 18 for SQL Server};Server=tcp:hawkeye-server-test.database.windows.net,1433;Database=hawkeye-DB-test;Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;"

app = FastAPI()

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

@app.get("/all")
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

@app.get("/person/{person_id}")
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

@app.post("/person")
def create_person(item: Person):
    try:
        with get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(f"INSERT INTO Persons (FirstName, LastName) VALUES (?, ?)", item.first_name, item.last_name)
            conn.commit()
            print(f"Inserted: {item.first_name} {item.last_name}")
    except Exception as e:
        print(f"Error inserting person: {e}")
    return item


def get_conn():
    credential = DefaultAzureCredential(exclude_interactive_browser_credential=False)
    token_bytes = credential.get_token("https://database.windows.net/.default").token.encode("UTF-16-LE")
    token_struct = struct.pack(f'<I{len(token_bytes)}s', len(token_bytes), token_bytes)
    SQL_COPT_SS_ACCESS_TOKEN = 1256  # Connection option defined in msodbcsql.h
    conn = pyodbc.connect(connection_string, attrs_before={SQL_COPT_SS_ACCESS_TOKEN: token_struct})
    return conn
