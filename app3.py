import os
import pyodbc
import jwt
import bcrypt
from datetime import datetime, timedelta
from typing import Union
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
import requests
from apify_client import ApifyClient

# JWT Secret Key
SECRET_KEY = "43581f2ce3c30dac3191986e251dba7a8802ad7aa73641265d14744b24f18bdc"
ALGORITHM = "HS256"

client = ApifyClient("apify_api_dqcBpWGk8J2tcMR3GfBk2oSFv7xtal2D85Me")

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

class UserProfile(BaseModel):
    username: str
    age: int
    state: str
    snapchat_username: Union[str, None] = None
    instagram_username: Union[str, None] = None
    tinder_username: Union[str, None] = None

class UserProfileRequest(BaseModel):
    user: User
    profile: UserProfile

class ReportRequest(BaseModel):
    reported_username: str
    report_cause: str
    report_description: str
    platform: str  # Add platform field here


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

@app.post("/reportUser")
def report_user(report_request: ReportRequest, token: str = Depends(oauth2_scheme)):
    try:
        # Extract the reporter's email from the authenticated token
        payload = verify_token(token)
        reporter_email = payload.get("sub")
        if not reporter_email:
            raise HTTPException(status_code=401, detail="Invalid token")

        # Validate platform input
        platform = report_request.platform.lower()
        valid_platforms = ["snapchat", "instagram", "tinder"]
        if platform not in valid_platforms:
            raise HTTPException(status_code=400, detail="Invalid platform. Use 'snapchat', 'instagram', or 'tinder'.")

        # Get the reporter's username from the UserProfiles table
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT Username FROM UserProfiles WHERE Email = ?", reporter_email)
        reporter_row = cursor.fetchone()
        if not reporter_row:
            raise HTTPException(status_code=404, detail="Reporter not found")
        
        reporter_username = reporter_row[0]

        # Fetch the reporter's ID
        cursor.execute("SELECT ID FROM UserProfiles WHERE Email = ?", reporter_email)
        reporter_row = cursor.fetchone()
        if not reporter_row:
            raise HTTPException(status_code=404, detail="Reporter not found")
        
        reporter_id = reporter_row[0]

        first_name = ""
        last_name = ""

        # Handle Snapchat: Call Snapchat API first to validate the reported username
        if platform == "snapchat":
            run_input = { "username": [report_request.reported_username] }
            try:
                run = client.actor("VqN0mxdFMwxVabq1T").call(run_input=run_input)
                dataset_id = run["defaultDatasetId"]

                # Fetch the dataset items
                dataset_items = client.dataset(run['defaultDatasetId']).list_items().items
                
                if not dataset_items:
                    raise Exception("No data retrieved from Snapchat API")
                
                # Accessing the first item from the dataset items
                first_item = dataset_items[0] if dataset_items else None

                if first_item and 'result' in first_item:
                    result = first_item['result'][0]  # Access the first result dictionary

                    # Check if the account is "no_exist_or_banned"
                    if result.get("accountType", "") == "no_exist_or_banned":
                        return {"message": "This account does not exist, the report was not submitted."}

                    # Extract the name
                    full_name = result.get('name', '')
                    if full_name:
                        name_parts = full_name.split(" ")
                        first_name = name_parts[0]
                        last_name = name_parts[1] if len(name_parts) > 1 else ""
                    else:
                        first_name, last_name = "", ""

            except Exception as e:
                print(f"Error retrieving data from Snapchat API: {str(e)}")
                raise HTTPException(status_code=500, detail="Error retrieving data from Snapchat API")

        # Determine which table to interact with based on the platform
        if platform == "snapchat":
            table_name = "ReportedUsersSnapchat"
            first_name_field = "Snapchat_Account_FirstName"
            last_name_field = "Snapchat_Account_LastName"
            foreign_key_column = "SnapchatUserID"  # Updated from UserID to SnapchatUserID
        elif platform == "instagram":
            table_name = "ReportedUsersInstagram"
            first_name_field = "Instagram_Account_FirstName"
            last_name_field = "Instagram_Account_LastName"
            foreign_key_column = "InstagramUserID"
        elif platform == "tinder":
            table_name = "ReportedUsersTinder"
            first_name_field = "Tinder_Account_FirstName"
            last_name_field = "Tinder_Account_LastName"
            foreign_key_column = "TinderUserID"

        # Step 1: Check if the reported username already exists in the platform-specific table
        cursor.execute(f"SELECT ID, Report_Counts, {first_name_field}, {last_name_field} FROM {table_name} WHERE Username = ?", report_request.reported_username)
        existing_user = cursor.fetchone()

        if existing_user:
            # The user already exists in the database
            user_id, report_counts, db_first_name, db_last_name = existing_user

            # If the user doesn't have a name in the database and the platform is Snapchat, update it
            if platform == "snapchat" and (not db_first_name or not db_last_name):
                cursor.execute(f"""
                    UPDATE {table_name}
                    SET {first_name_field} = ?, {last_name_field} = ?
                    WHERE ID = ?
                """, (first_name, last_name, user_id))

            # Increment the report counts
            new_report_count = report_counts + 1
            cursor.execute(f"UPDATE {table_name} SET Report_Counts = ? WHERE ID = ?", (new_report_count, user_id))

        else:
            # Step 2: If the user doesn't exist in the platform-specific table, insert them
            cursor.execute(f"""
                INSERT INTO {table_name} (Username, {first_name_field}, {last_name_field}, Report_Counts)
                OUTPUT INSERTED.ID
                VALUES (?, ?, ?, ?)
            """, (report_request.reported_username, first_name, last_name, 1))
            new_user_id_row = cursor.fetchone()
            if new_user_id_row is None:
                raise HTTPException(status_code=500, detail="Failed to retrieve User ID")
            user_id = new_user_id_row[0]

        # Step 3: Insert the report into the Reports table and fetch the new Report ID
        report_date = datetime.now()
        cursor.execute("""
            INSERT INTO Reports (Reported_Username, Reporter_Username, Report_Cause, Report_Date, Report_Description, Platform)
            OUTPUT INSERTED.ID
            VALUES (?, ?, ?, ?, ?, ?)
        """, (report_request.reported_username, reporter_username, report_request.report_cause, report_date, report_request.report_description, platform.capitalize()))

        report_id_row = cursor.fetchone()
        if report_id_row is None:
            raise HTTPException(status_code=500, detail="Failed to retrieve Report ID")
        report_id = report_id_row[0]

        # Step 4: Link the report to the user with the correct foreign key column for the platform
        cursor.execute(f"INSERT INTO ReportedUsersReports ({foreign_key_column}, ReportID, UserReportingID) VALUES (?, ?, ?)", (user_id, report_id, reporter_id))

        conn.commit()
        return {"message": "Report submitted successfully", "Report ID": report_id}
    
    except Exception as e:
        import traceback
        traceback.print_exc()  # Log full exception
        raise HTTPException(status_code=400, detail=f"Error submitting report: {str(e)}")

@app.get("/getReportsByUsername/{platform}/{reported_username}", dependencies=[Depends(get_current_user)])
def get_reports_by_username(platform: str, reported_username: str, user_email: str = Depends(get_current_user)):
    try:
        conn = get_conn()
        cursor = conn.cursor()

        # Validate platform input
        platform = platform.lower()
        valid_platforms = ["snapchat", "instagram", "tinder"]
        if platform not in valid_platforms:
            raise HTTPException(status_code=400, detail="Invalid platform. Use 'snapchat', 'instagram', or 'tinder'.")

        # Determine the correct table and foreign key column based on the platform
        if platform == "snapchat":
            table_name = "ReportedUsersSnapchat"
            foreign_key_column = "SnapchatUserID"
        elif platform == "instagram":
            table_name = "ReportedUsersInstagram"
            foreign_key_column = "InstagramUserID"
        elif platform == "tinder":
            table_name = "ReportedUsersTinder"
            foreign_key_column = "TinderUserID"

        # Check if the user exists in the platform-specific table
        cursor.execute(f"SELECT ID FROM {table_name} WHERE Username = ?", reported_username)
        user_row = cursor.fetchone()

        if not user_row:
            return {"message": "User not found"}

        user_id = user_row[0]

        # Fetch all Report IDs linked to the user in the platform-specific foreign key column
        cursor.execute(f"SELECT ReportID FROM ReportedUsersReports WHERE {foreign_key_column} = ?", user_id)
        report_ids = [row[0] for row in cursor.fetchall()]

        if not report_ids:
            return {"message": "No reports found for this user"}

        # Fetch all the reports using the report IDs
        cursor.execute(f"SELECT * FROM Reports WHERE ID IN ({','.join('?' * len(report_ids))})", *report_ids)
        reports = cursor.fetchall()

        # Format the results
        reports_data = []
        for report in reports:
            reports_data.append({
                "ID": report.ID,
                "Reported_Username": report.Reported_Username,
                "Reporter_Username": report.Reporter_Username,
                "Report_Cause": report.Report_Cause,
                "Report_Date": report.Report_Date,
                "Report_Description": report.Report_Description
            })

        # Fetch the user's profile to update the Previously_Searched field
        cursor.execute("SELECT Previously_Searched FROM UserProfiles WHERE Email = ?", user_email)
        user_profile = cursor.fetchone()

        if user_profile and user_profile[0]:
            previously_searched = user_profile[0].split(',')  # Assume it's stored as a comma-separated string

            # Check if the username|platform combo already exists
            search_entry = f"{reported_username}|{platform}"
            if search_entry in previously_searched:
                previously_searched.remove(search_entry)

            # Keep only the last 10 searches
            if len(previously_searched) >= 10:
                previously_searched = previously_searched[:9]
            
            # Add the new search entry
            previously_searched.insert(0, search_entry)

            updated_searched = ','.join(previously_searched)
        else:
            # If the user hasn't searched before, start with the current search
            updated_searched = f"{reported_username}|{platform}"

        # Update the Previously_Searched field in the database
        cursor.execute("UPDATE UserProfiles SET Previously_Searched = ? WHERE Email = ?", updated_searched, user_email)

        conn.commit()

        return {"reports": reports_data}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error retrieving reports: {str(e)}")




@app.get("/getPreviouslySearched", dependencies=[Depends(get_current_user)])
def get_previously_searched(user_email: str = Depends(get_current_user)):
    try:
        conn = get_conn()
        cursor = conn.cursor()

        # Fetch the previously searched values from the UserProfiles table
        cursor.execute("SELECT Previously_Searched FROM UserProfiles WHERE Email = ?", user_email)
        user_profile = cursor.fetchone()

        if user_profile and user_profile[0]:
            # Split the previously searched string into an array
            previously_searched_raw = user_profile[0].split(',')

            # Create a list to store previously searched usernames along with their platforms
            previously_searched = []

            for search_item in previously_searched_raw:
                # Check if the stored value contains both the username and the platform
                if '|' in search_item:
                    username, platform = search_item.split('|')
                    previously_searched.append({
                        "username": username,
                        "platform": platform
                    })
                else:
                    # If the platform is missing (for older entries), default to "unknown"
                    previously_searched.append({
                        "username": search_item,
                        "platform": "unknown"
                    })
        else:
            previously_searched = []

        return {"previously_searched": previously_searched}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error retrieving previously searched: {str(e)}")





@app.get("/getReportsByUser", dependencies=[Depends(get_current_user)])
def get_reports_by_user(user_email: str = Depends(get_current_user)):
    try:
        conn = get_conn()
        cursor = conn.cursor()

        # Get the User ID from the UserProfiles table using the email
        cursor.execute("SELECT ID FROM UserProfiles WHERE Email = ?", user_email)
        user_row = cursor.fetchone()
        
        if not user_row:
            return {"message": "User not found"}

        reporter_user_id = user_row[0]

        # Fetch all Report IDs linked to the user (reports submitted by this user)
        cursor.execute("SELECT ReportID FROM ReportedUsersReports WHERE UserReportingID = ?", reporter_user_id)
        report_ids = [row[0] for row in cursor.fetchall()]
        
        if not report_ids:
            return {"message": "No reports found for this user"}

        # Fetch all the reports using the report IDs
        cursor.execute(f"SELECT * FROM Reports WHERE ID IN ({','.join('?' * len(report_ids))})", report_ids)
        reports = cursor.fetchall()

        # Format the results
        reports_data = []
        for report in reports:
            reports_data.append({
                "ID": report.ID,
                "Reported_Username": report.Reported_Username,
                "Reporter_Username": report.Reporter_Username,
                "Report_Cause": report.Report_Cause,
                "Report_Date": report.Report_Date,
                "Report_Description": report.Report_Description
            })

        return {"reports": reports_data}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error retrieving reports: {str(e)}")


@app.get("/searchUsersByPrefix/{prefix}")
def search_users_by_prefix(prefix: str):
    try:
        conn = get_conn()
        cursor = conn.cursor()

        # Query to find all users whose Username starts with the prefix
        cursor.execute("SELECT * FROM ReportedUsersSnapchat WHERE Username LIKE ?", prefix + '%')
        users = cursor.fetchall()

        if not users:
            return {"message": "No users found with the given prefix"}

        # Format the result
        users_data = []
        for user in users:
            users_data.append({
                "ID": user.ID,
                "Username": user.Username,
                "Snapchat_Account_FirstName": user.Snapchat_Account_FirstName,
                "Snapchat_Account_LastName": user.Snapchat_Account_LastName,
                "Report_Counts": user.Report_Counts
            })

        return {"users": users_data}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error retrieving users: {str(e)}")


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

@app.post("/set-profile")
def set_user_profile(user_profile: UserProfileRequest):
    try:
        email = user_profile.user.email
        password = user_profile.user.password
        profile_data = user_profile.profile
        
        conn = get_conn()
        cursor = conn.cursor()

        # Ensure the user exists before setting profile
        cursor.execute("SELECT * FROM Users WHERE Email = ?", email)
        db_user = cursor.fetchone()
        if not db_user or not bcrypt.checkpw(password.encode('utf-8'), db_user.HashedPassword.encode('utf-8')):
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # Insert or update the profile information
        cursor.execute("""
    MERGE INTO UserProfiles AS target
    USING (VALUES (?, ?, ?, ?, ?, ?, ?)) AS source (Email, Username, Age, State, SnapchatUsername, InstagramUsername, TinderUsername)
    ON target.Email = source.Email
    WHEN MATCHED THEN 
        UPDATE SET 
            Username = source.Username, 
            Age = source.Age, 
            State = source.State, 
            SnapchatUsername = source.SnapchatUsername, 
            InstagramUsername = source.InstagramUsername, 
            TinderUsername = source.TinderUsername
    WHEN NOT MATCHED THEN
        INSERT (Email, Username, Age, State, SnapchatUsername, InstagramUsername, TinderUsername)
        VALUES (source.Email, source.Username, source.Age, source.State, source.SnapchatUsername, source.InstagramUsername, source.TinderUsername);
""", (email, profile_data.username, profile_data.age, profile_data.state, profile_data.snapchat_username, profile_data.instagram_username, profile_data.tinder_username))
        
        conn.commit()
        return {"message": "Profile updated successfully"}
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error setting profile: {str(e)}")



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
