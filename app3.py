import os
import pyodbc
import traceback
import logging
from typing import Optional
import jwt
import bcrypt
from datetime import datetime, timedelta
from typing import Union
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi import Form
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
import requests
from apify_client import ApifyClient
import json
import cv2
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from azure.storage.blob import BlobServiceClient, ContentSettings
from instagram import Instagram
from bs4 import BeautifulSoup

def get_display_name(username):
    # Construct the Snapchat profile URL using the username
    url = f"https://www.snapchat.com/add/{username}"

    # Headers to mimic a browser request
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
    }

    # Sending the request
    response = requests.get(url, headers=headers)

    # Check if the request was successful
    if response.status_code == 200:
        # Parse the HTML content with BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Try to extract the display name using h1
        display_name = soup.select_one("h1")
        
        # Fallback to .Heading_h400Emphasis__SQXxl span if h1 is not found
        if not display_name:
            display_name = soup.select_one(".Heading_h400Emphasis__SQXxl span")
        
        if display_name:
            # Get the text and split into first and last name
            full_name = display_name.get_text().strip()
            name_parts = full_name.split(" ", 1)  # Split into two parts: first name and last name
            
            first_name = name_parts[0]  # First part is the first name
            last_name = name_parts[1] if len(name_parts) > 1 else ""  # Second part if exists is the last name
            
            return first_name, last_name
        else:
            return None, None
    else:
        return None, None

logging.basicConfig(level=logging.INFO)


# JWT Secret Key
SECRET_KEY = "43581f2ce3c30dac3191986e251dba7a8802ad7aa73641265d14744b24f18bdc"
REFRESH_SECRET_KEY = "0e5faaf7ff563aee3370140cd4c61b78097b700185bb655cda70ff47e83ff2bc88df468885df169dc96e8d84689a037942c5e72517d2ebb71239322789845da0"
ALGORITHM = "HS256"

connection_string_blob = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
container_name = "reports-to-be-validated"
subscription_key = os.getenv("AZURE_SUBSCRIPTION_KEY")
ocr_endpoint = "https://hawkeye-cv-test2-hanavmodasiya.cognitiveservices.azure.com/vision/v3.2/ocr"
frame_output_dir = "frames"

blob_service_client = BlobServiceClient.from_connection_string(connection_string_blob)

client = ApifyClient("apify_api_dqcBpWGk8J2tcMR3GfBk2oSFv7xtal2D85Me")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

class Person(BaseModel):
    first_name: str
    last_name: Union[str, None] = None

class User(BaseModel):
    email: Union[str, None] = None
    password: Union[str, None] = None


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class UserProfile(BaseModel):
    username: Union[str, None] = None
    age: Union[int, None] = None
    state: Union[str, None] = None
    snapchat_username: Union[str, None] = None
    instagram_username: Union[str, None] = None
    tinder_username: Union[str, None] = None
    is_premium: Union[bool, None] = None
    first_name: Union[str, None] = None
    last_name: Union[str, None] = None
    phone_number: Union[str, None] = None

class UserProfileRequest(BaseModel):
    user: Union[User, None] = None
    profile: Union[UserProfile, None] = None

class UserProfileResponse(BaseModel):
    user_id: int
    username: str = None
    age: int = None
    state: str = None
    snapchat_username: str = None
    instagram_username: str = None
    tinder_username: str = None
    email: str
    previously_searched: str = None
    is_premium: bool = False
    searched_count: int = 0
    first_name: str = ""
    last_name: str = ""
    phone_number: str = ""


class ReportRequest(BaseModel):
    reported_username: str
    report_cause: str
    report_description: str
    platform: str  # Add platform field here

#edf
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

def create_refresh_token(data: dict, expires_delta: timedelta = timedelta(days=7)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, REFRESH_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/refresh-token")
def refresh_token(refresh_token: str):
    try:
        # Verify the refresh token
        payload = jwt.decode(refresh_token, REFRESH_SECRET_KEY, algorithms=[ALGORITHM])
        user_email = payload.get("sub")
        if not user_email:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Generate a new access token
        access_token = create_access_token(data={"sub": user_email})
        return {"access_token": access_token}
    
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")


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

# instagram script




#User authentication routes
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

    # Generate access and refresh tokens
    access_token = create_access_token(data={"sub": user.email})
    refresh_token = create_refresh_token(data={"sub": user.email})
    
    return {
        "access_token": access_token, 
        "refresh_token": refresh_token,  # Include refresh token
        "token_type": "bearer"
    }

@app.post("/set-profile")
def set_user_profile(user_profile: UserProfileRequest):
    try:
        # Check for email in user payload to proceed
        if not user_profile.user or not user_profile.user.email:
            raise HTTPException(status_code=422, detail="Email is required.")
        
        email = user_profile.user.email
        password = user_profile.user.password if user_profile.user else None
        profile_data = user_profile.profile if user_profile.profile else None
        
        conn = get_conn()
        cursor = conn.cursor()

        # Ensure the user exists and validate credentials if password is provided
        cursor.execute("SELECT * FROM Users WHERE Email = ?", email)
        db_user = cursor.fetchone()
        
        if not db_user:
            raise HTTPException(status_code=404, detail="User not found")

        if password and not bcrypt.checkpw(password.encode('utf-8'), db_user.HashedPassword.encode('utf-8')):
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # Prepare values for SQL query, using None where fields are missing
        cursor.execute("""
            MERGE INTO UserProfiles AS target
            USING (VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)) AS source 
            (Email, Username, Age, State, SnapchatUsername, InstagramUsername, TinderUsername, is_premium, searched_count, firstName, lastName, phoneNumber)
            ON target.Email = source.Email
            WHEN MATCHED THEN 
                UPDATE SET 
                    Username = COALESCE(source.Username, target.Username), 
                    Age = COALESCE(source.Age, target.Age), 
                    State = COALESCE(source.State, target.State), 
                    SnapchatUsername = COALESCE(source.SnapchatUsername, target.SnapchatUsername), 
                    InstagramUsername = COALESCE(source.InstagramUsername, target.InstagramUsername), 
                    TinderUsername = COALESCE(source.TinderUsername, target.TinderUsername),
                    is_premium = COALESCE(source.is_premium, target.is_premium),
                    firstName = COALESCE(source.firstName, target.firstName),
                    lastName = COALESCE(source.lastName, target.lastName),
                    phoneNumber = COALESCE(source.phoneNumber, target.phoneNumber)
            WHEN NOT MATCHED THEN
                INSERT (Email, Username, Age, State, SnapchatUsername, InstagramUsername, TinderUsername, is_premium, searched_count, firstName, lastName, phoneNumber)
                VALUES (source.Email, source.Username, source.Age, source.State, source.SnapchatUsername, source.InstagramUsername, source.TinderUsername, source.is_premium, 0, source.firstName, source.lastName, source.phoneNumber);  -- Initialize searched_count to 0
        """, (
            email,
            profile_data.username if profile_data else None, 
            profile_data.age if profile_data else None, 
            profile_data.state if profile_data else None, 
            profile_data.snapchat_username if profile_data else None, 
            profile_data.instagram_username if profile_data else None, 
            profile_data.tinder_username if profile_data else None, 
            profile_data.is_premium if profile_data else None,
            0,
            profile_data.first_name if profile_data else None,
            profile_data.last_name if profile_data else None,
            profile_data.phone_number if profile_data else None
        ))

        conn.commit()
        return {"message": "Profile updated successfully"}
        
    except Exception as e:
        import traceback
        traceback.print_exc()  # Log the full traceback for better error visibility
        raise HTTPException(status_code=400, detail=f"Error setting profile: {str(e)}")





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

    # Generate access and refresh tokens
    access_token = create_access_token(data={"sub": user.email})
    refresh_token = create_refresh_token(data={"sub": user.email})
    
    return {
        "access_token": access_token, 
        "refresh_token": refresh_token,  # Include refresh token
        "token_type": "bearer"
    }


@app.get("/fetch-user-profile/{email}", response_model=UserProfileResponse)
def fetch_user_profile(email: str):
    conn = get_conn()
    cursor = conn.cursor()
    
    query = """
        SELECT UserID, Username, Age, State, SnapchatUsername, InstagramUsername, TinderUsername, Email, 
               Previously_Searched, is_premium, searched_count, firstName, lastName, phoneNumber
        FROM dbo.UserProfiles
        WHERE Email = ?
    """
    
    cursor.execute(query, email)
    row = cursor.fetchone()
    
    if row:
        # Handle the case where fields might be None
        if row.Username is None:
            raise HTTPException(status_code=404, detail="User profile not found or missing username")

        return UserProfileResponse(
            user_id=-1,
            username=row.Username if row.Username else "",
            age=row.Age if row.Age else 0,
            state=row.State if row.State else "",
            snapchat_username=row.SnapchatUsername if row.SnapchatUsername else "",
            instagram_username=row.InstagramUsername if row.InstagramUsername else "",
            tinder_username=row.TinderUsername if row.TinderUsername else "",
            email=row.Email,
            previously_searched=row.Previously_Searched if row.Previously_Searched else "",
            is_premium=row.is_premium if row.is_premium is not None else False,
            searched_count=row.searched_count if row.searched_count is not None else 0,
            first_name=row.firstName if row.firstName else "",
            last_name=row.lastName if row.lastName else "",
            phone_number=row.phoneNumber if row.phoneNumber else ""
        )
    else:
        raise HTTPException(status_code=404, detail="User profile not found")



#Reporting routes
@app.post("/reportUser")
async def report_user(
    reported_username: str = Form(...),
    report_cause: str = Form(...),
    report_description: str = Form(...),
    platform: str = Form(...),
    video: Optional[UploadFile] = File(None),  # Make video optional
    token: str = Depends(oauth2_scheme)
):
    try:
        # Step 1: Extract the reporter's email from the authenticated token
        payload = verify_token(token)
        reporter_email = payload.get("sub")
        if not reporter_email:
            raise HTTPException(status_code=401, detail="Invalid token")

        # Step 2: Fetch the reporter's username from the UserProfiles table
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT Username FROM UserProfiles WHERE Email = ?", (reporter_email,))
        reporter_row = cursor.fetchone()
        if not reporter_row:
            raise HTTPException(status_code=404, detail="Reporter not found")

        reporter_username = reporter_row[0]

        # Step 3: Validate platform input
        platform = platform.lower()
        valid_platforms = ["snapchat", "instagram", "tinder"]
        if platform not in valid_platforms:
            raise HTTPException(status_code=400, detail="Invalid platform. Use 'snapchat', 'instagram', or 'tinder'.")

        # Step 4: Handle Snapchat API validation with fallback if API fails
        first_name = ""
        last_name = ""
        if platform == "snapchat":
            try:

                first_name, last_name = get_display_name(reported_username)
                if (first_name == None):
                    return {"message": "This account does not exist, the report was not submitted."}
                # run_input = {"username": [reported_username]}
                # run = client.actor("VqN0mxdFMwxVabq1T").call(run_input=run_input)
                # dataset_items = client.dataset(run['defaultDatasetId']).list_items().items

                # if not dataset_items:
                #     raise Exception("No data retrieved from Snapchat API")

                # first_item = dataset_items[0]
                # if first_item and 'result' in first_item:
                #     result = first_item['result'][0]
                #     if result.get("accountType", "") == "no_exist_or_banned":
                #         return {"message": "This account does not exist, the report was not submitted."}

                #     full_name = result.get('name', '')
                #     if full_name:
                #         name_parts = full_name.split(" ")
                #         first_name = name_parts[0]
                #         last_name = name_parts[1] if len(name_parts) > 1 else ""
            except Exception as e:
                print(f"Error retrieving data from Snapchat API: {str(e)}")
                # Fallback: assume account exists if API fails
                print("Assuming Snapchat account exists due to API failure")
        
        if platform == "instagram":
            try:
                profile_data = Instagram.scrap(reported_username)
                profile_data = json.loads(profile_data)
                full_name = profile_data["full_name"]
                if full_name:
                    name_parts = full_name.split(" ")
                    first_name = name_parts[0]
                    last_name = name_parts[1] if len(name_parts) > 1 else ""
            except Exception as e:
                return {"message": "This account does not exist, the report was not submitted."}


        # Step 5: Ensure the directory for video files exists if video is provided
        video_path = None
        if video:
            video_dir = "temp_videos"
            if not os.path.exists(video_dir):
                os.makedirs(video_dir)

            # Step 6: Save the video locally
            video_path = f"{video_dir}/{reported_username}_{datetime.now().strftime('%Y%m%d-%H%M%S')}.mp4"
            with open(video_path, "wb") as f:
                f.write(await video.read())

            # Step 7: Extract text from the video frames
            extracted_text = process_video(video_path, frame_interval=120)

        else:
            extracted_text = ""  # If no video, no text extraction is done

        # Step 8: Prepare the report data
        report_data = {
            "reported_username": reported_username,
            "report_cause": report_cause,
            "report_description": report_description,
            "report_date": str(datetime.now()),
            "platform": platform.capitalize(),
            "extracted_text": extracted_text,
            "reporter_username": reporter_username,
            "first_name": first_name,
            "last_name": last_name
        }

        # Step 9: Upload report data and video to Azure Blob Storage if video exists
        if video_path:
            with open(video_path, "rb") as video_file:
                upload_report_to_blob(report_data, video_file)
            # Clean up: Remove the local video file after upload
            if os.path.exists(video_path):
                os.remove(video_path)
        else:
            upload_report_to_blob_without_video(report_data)

        return {"message": "Report has been submitted for validation"}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error submitting report: {str(e)}")



@app.post("/reportUserAdmin")
def report_user_admin(blob_entry_name: str = Form(...)):
    try:
        logging.info(f"Received request to process blob entry: {blob_entry_name}")

        # Validate input early
        if not blob_entry_name:
            logging.error("Input error: Blob entry name is missing")
            raise HTTPException(status_code=400, detail="Blob entry name is required")
        blob_entry_name = blob_entry_name.strip()

        # Step 1: Access the blob metadata
        container_name = "reports-to-be-validated"
        logging.info(f"Attempting to access blob in container {container_name} with entry name {blob_entry_name}")
        logging.info(f"Blob entry to be fetched: '{blob_entry_name}'")

        blob_client = blob_service_client.get_blob_client(container_name, blob_entry_name + "/metadata.json")
        
        if not blob_client.exists():
            logging.error(f"Blob entry {blob_entry_name} not found")
            raise HTTPException(status_code=404, detail="Blob entry not found")
        
        logging.info(f"Blob entry {blob_entry_name} found. Fetching metadata.")
        
        # Fetch metadata from the blob
        blob_metadata = blob_client.download_blob().readall()
        blob_metadata = json.loads(blob_metadata.decode('utf-8'))  # Convert byte data to JSON

        # Ensure metadata is present
        if not blob_metadata:
            logging.error(f"Metadata for blob entry {blob_entry_name} is missing")
            raise HTTPException(status_code=400, detail="Metadata is missing for the specified blob entry")

        logging.info(f"Blob metadata retrieved: {blob_metadata}")

        # Extract necessary fields from metadata
        reported_username = blob_metadata.get("reported_username")
        report_cause = blob_metadata.get("report_cause")
        report_description = blob_metadata.get("report_description")
        platform = blob_metadata.get("platform")
        reporter_username = blob_metadata.get("reporter_username")
        extracted_text_list = blob_metadata.get("extracted_text")
        first_name = blob_metadata.get("first_name")
        last_name = blob_metadata.get("last_name")

        # Check for required fields in metadata
        if not all([reported_username, report_cause, platform, reporter_username]):
            logging.error(f"Incomplete metadata in blob entry {blob_entry_name}")
            raise HTTPException(status_code=400, detail="Incomplete metadata in blob")

        logging.info(f"All required metadata fields are present for {reported_username}. Proceeding to validation.")

        # Step 2: Validate platform input
        platform = platform.lower()
        valid_platforms = ["snapchat", "instagram", "tinder"]
        if platform not in valid_platforms:
            logging.error(f"Invalid platform: {platform}")
            raise HTTPException(status_code=400, detail="Invalid platform. Use 'snapchat', 'instagram', or 'tinder'.")
        
        logging.info(f"Platform {platform} is valid. Connecting to database.")

        # Step 3: Connect to the database and get reporter's ID
        conn = get_conn()
        cursor = conn.cursor()

        cursor.execute("SELECT ID FROM UserProfiles WHERE Username = ?", reporter_username)
        reporter_row = cursor.fetchone()
        if not reporter_row:
            logging.error(f"Reporter {reporter_username} not found in the database")
            raise HTTPException(status_code=404, detail="Reporter not found")

        reporter_id = reporter_row[0]
        logging.info(f"Reporter ID retrieved: {reporter_id}")

        # Step 4: Determine the platform-specific table and fields
        if platform == "snapchat":
            table_name = "ReportedUsersSnapchat"
            first_name_field = "Snapchat_Account_FirstName"
            last_name_field = "Snapchat_Account_LastName"
            foreign_key_column = "SnapchatUserID"
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

        first_name = ""
        last_name = ""
        if platform == "instagram":
            try:
                profile_data = Instagram.scrap(reported_username)
                profile_data = json.loads(profile_data)
                full_name = profile_data["full_name"]
                if full_name:
                    name_parts = full_name.split(" ")
                    first_name = name_parts[0]
                    last_name = name_parts[1] if len(name_parts) > 1 else ""
            except Exception as e:
                return {"message": "This account does not exist, the report was not submitted."}

        logging.info(f"Table determined: {table_name}")

        # Step 5: Check if the reported username already exists in the platform-specific table
        cursor.execute(f"SELECT ID, Report_Counts, {first_name_field}, {last_name_field} FROM {table_name} WHERE Username = ?", reported_username)
        existing_user = cursor.fetchone()

        if existing_user:
            user_id, report_counts, db_first_name, db_last_name = existing_user
            if (first_name != ""):
                db_first_name = first_name
            if (last_name != ""):
                db_last_name = last_name
            new_report_count = report_counts + 1
            cursor.execute(f"""
                UPDATE {table_name}
                SET Report_Counts = ?, {first_name_field} = ?, {last_name_field} = ?
                WHERE ID = ?
            """, (new_report_count, db_first_name, db_last_name, user_id))
            # cursor.execute(f"UPDATE {table_name} SET Report_Counts = ? WHERE ID = ?", (new_report_count, user_id))
            logging.info(f"Updated report count for {reported_username}")
        else:
            cursor.execute(f"""
                INSERT INTO {table_name} (Username, {first_name_field}, {last_name_field}, Report_Counts)
                OUTPUT INSERTED.ID
                VALUES (?, ?, ?, ?)
            """, (reported_username, first_name, last_name, 1))
            new_user_id_row = cursor.fetchone()
            if new_user_id_row is None:
                logging.error("Failed to retrieve User ID after insertion")
                raise HTTPException(status_code=500, detail="Failed to retrieve User ID")
            user_id = new_user_id_row[0]
            logging.info(f"Inserted new user {reported_username} into {table_name}")

        # Step 6: Concatenate extracted text entries into a single string
        if extracted_text_list:
            extracted_text_str = "\n".join([f"Frame {entry['frame']}: {entry['text']}" for entry in extracted_text_list])
        else:
            extracted_text_str = ""

        logging.info(f"Concatenated extracted text: {extracted_text_str}")

        # Step 7: Insert the report into the Reports table with the concatenated extracted_text
        cursor.execute("""
            INSERT INTO Reports (Reported_Username, Reporter_Username, Report_Cause, Report_Date, Report_Description, Platform, Extracted_Text)
            OUTPUT INSERTED.ID
            VALUES (?, ?, ?, GETDATE(), ?, ?, ?)
        """, (reported_username, reporter_username, report_cause, report_description, platform.capitalize(), extracted_text_str))

        report_id_row = cursor.fetchone()
        if report_id_row is None:
            logging.error("Failed to retrieve Report ID after inserting the report")
            raise HTTPException(status_code=500, detail="Failed to retrieve Report ID")
        report_id = report_id_row[0]
        logging.info(f"Report ID {report_id} created for {reported_username}")

        # Step 8: Link the report to the user
        cursor.execute(f"INSERT INTO ReportedUsersReports ({foreign_key_column}, ReportID, UserReportingID) VALUES (?, ?, ?)", (user_id, report_id, reporter_id))
        logging.info(f"Linked report ID {report_id} to user ID {user_id}")

        conn.commit()

        # Step 9: Delete the corresponding blob folder
        deleted = delete_blob_folder(container_name, blob_entry_name)
        if not deleted:
            logging.error(f"Failed to delete blob folder {blob_entry_name}")
            raise HTTPException(status_code=500, detail="Failed to delete the associated blob folder.")
        
        logging.info(f"Blob entry {blob_entry_name} deleted successfully.")
        
        return {"message": "Report submitted successfully and blob entry deleted.", "Report ID": report_id}

    except Exception as e:
        logging.error(f"Error submitting report: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Error submitting report: {str(e)}")






@app.post("/checkBlob")
async def check_blob(blob_entry_name: str = Form(...)):
    try:
        # Define the container name
        container_name = "reports-to-be-validated"

        # Log the blob name being checked
        logging.info(f"Checking if blob exists: {blob_entry_name}")
        
        # Get the blob client
        blob_client = blob_service_client.get_blob_client(container_name, blob_entry_name.strip())

        # Check if the blob exists
        if blob_client.exists():
            logging.info(f"Blob {blob_entry_name} found.")
            return {"message": f"Blob '{blob_entry_name}' was found."}
        else:
            logging.error(f"Blob {blob_entry_name} not found.")
            raise HTTPException(status_code=404, detail=f"Blob '{blob_entry_name}' not found.")

    except Exception as e:
        logging.error(f"Error checking blob {blob_entry_name}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error checking blob: {str(e)}")





#Searching routes
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

        # Fetch the user's profile to update the Previously_Searched field and increment searched_count
        cursor.execute("SELECT Previously_Searched, searched_count FROM UserProfiles WHERE Email = ?", user_email)
        user_profile = cursor.fetchone()

        if user_profile:
            previously_searched = user_profile[0].split(',') if user_profile[0] else []

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

            # Check if searched_count is None and set it to 0 if necessary
            searched_count = user_profile[1] if user_profile[1] is not None else 0
            searched_count += 1

            # Update the Previously_Searched and searched_count fields in the database
            cursor.execute("UPDATE UserProfiles SET Previously_Searched = ?, searched_count = ? WHERE Email = ?", updated_searched, searched_count, user_email)
        else:
            # If the user hasn't searched before, start with the current search and set the searched_count to 1
            updated_searched = f"{reported_username}|{platform}"
            searched_count = 1

            # Update the Previously_Searched and searched_count fields in the database
            cursor.execute("UPDATE UserProfiles SET Previously_Searched = ?, searched_count = ? WHERE Email = ?", updated_searched, searched_count, user_email)

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

        # Fetch all the reports using the report IDs, along with the platform field
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
                "Report_Description": report.Report_Description,
                "Platform": report.Platform  # Adding platform to the response
            })

        return {"reports": reports_data}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error retrieving reports: {str(e)}")

@app.get("/searchUsersByPrefix/{platform}/{prefix}")
def search_users_by_prefix(platform: str, prefix: str):
    try:
        conn = get_conn()
        cursor = conn.cursor()

        # Validate platform input
        platform = platform.lower()
        valid_platforms = ["snapchat", "instagram", "tinder"]
        if platform not in valid_platforms:
            raise HTTPException(status_code=400, detail="Invalid platform. Use 'snapchat', 'instagram', or 'tinder'.")

        # Determine the correct table and columns based on the platform
        if platform == "snapchat":
            table_name = "ReportedUsersSnapchat"
            first_name_field = "Snapchat_Account_FirstName"
            last_name_field = "Snapchat_Account_LastName"
        elif platform == "instagram":
            table_name = "ReportedUsersInstagram"
            first_name_field = "Instagram_Account_FirstName"
            last_name_field = "Instagram_Account_LastName"
        elif platform == "tinder":
            table_name = "ReportedUsersTinder"
            first_name_field = "Tinder_Account_FirstName"
            last_name_field = "Tinder_Account_LastName"

        # Query to find all users whose Username starts with the prefix for the specified platform
        query = f"SELECT * FROM {table_name} WHERE Username LIKE ?"
        cursor.execute(query, prefix + '%')
        users = cursor.fetchall()

        if not users:
            return {"message": "No users found with the given prefix"}

        # Format the result
        users_data = []
        for user in users:
            users_data.append({
                "ID": user.ID,
                "Username": user.Username,
                first_name_field: getattr(user, first_name_field),
                last_name_field: getattr(user, last_name_field),
                "Report_Counts": user.Report_Counts
            })

        return {"users": users_data}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error retrieving users: {str(e)}")





# Set connected social media accounts
@app.post("/setConnectedSnapchat", dependencies=[Depends(oauth2_scheme)])
def set_connected_snapchat(username: str, token: str = Depends(oauth2_scheme)):
    try:
        # Extract the reporter's email from the authenticated token
        payload = verify_token(token)
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")

        # Connect to the database
        conn = get_conn()
        cursor = conn.cursor()

        # Update the Snapchat username in UserProfiles
        cursor.execute("UPDATE UserProfiles SET SnapchatUsername = ? WHERE Email = ?", username, email)
        conn.commit()

        return {"message": "Snapchat username updated successfully"}
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error updating Snapchat username: {str(e)}")


@app.post("/setConnectedInstagram", dependencies=[Depends(oauth2_scheme)])
def set_connected_instagram(username: str, token: str = Depends(oauth2_scheme)):
    try:
        # Extract the reporter's email from the authenticated token
        payload = verify_token(token)
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")

        # Connect to the database
        conn = get_conn()
        cursor = conn.cursor()

        # Update the Instagram username in UserProfiles
        cursor.execute("UPDATE UserProfiles SET InstagramUsername = ? WHERE Email = ?", username, email)
        conn.commit()

        return {"message": "Instagram username updated successfully"}
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error updating Instagram username: {str(e)}")


@app.post("/setConnectedTinder", dependencies=[Depends(oauth2_scheme)])
def set_connected_tinder(username: str, token: str = Depends(oauth2_scheme)):
    try:
        # Extract the reporter's email from the authenticated token
        payload = verify_token(token)
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")

        # Connect to the database
        conn = get_conn()
        cursor = conn.cursor()

        # Update the Tinder username in UserProfiles
        cursor.execute("UPDATE UserProfiles SET TinderUsername = ? WHERE Email = ?", username, email)
        conn.commit()

        return {"message": "Tinder username updated successfully"}
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error updating Tinder username: {str(e)}")

# Get connected social media accounts report counts
@app.get("/getConnectedSnapchat", dependencies=[Depends(oauth2_scheme)])
def get_connected_snapchat(token: str = Depends(oauth2_scheme)):
    try:
        # Extract the user's email from the authenticated token
        payload = verify_token(token)
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")

        # Connect to the database
        conn = get_conn()
        cursor = conn.cursor()

        # Fetch the connected Snapchat username from UserProfiles
        cursor.execute("SELECT SnapchatUsername FROM UserProfiles WHERE Email = ?", email)
        user_profile = cursor.fetchone()

        if not user_profile or not user_profile[0]:
            raise HTTPException(status_code=404, detail="Snapchat username not found for the user.")

        snapchat_username = user_profile[0]

        # Fetch the number of reports for this Snapchat username
        cursor.execute("SELECT Report_Counts FROM ReportedUsersSnapchat WHERE Username = ?", snapchat_username)
        report_row = cursor.fetchone()

        if not report_row:
            return {"message": "Snapchat username has no reports.", "report_count": 0}

        report_count = report_row[0]
        return {"message": f"Snapchat username '{snapchat_username}' has {report_count} reports.", "report_count": report_count}
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error retrieving Snapchat report count: {str(e)}")

@app.get("/getConnectedInstagram", dependencies=[Depends(oauth2_scheme)])
def get_connected_instagram(token: str = Depends(oauth2_scheme)):
    try:
        # Extract the user's email from the authenticated token
        payload = verify_token(token)
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")

        # Connect to the database
        conn = get_conn()
        cursor = conn.cursor()

        # Fetch the connected Instagram username from UserProfiles
        cursor.execute("SELECT InstagramUsername FROM UserProfiles WHERE Email = ?", email)
        user_profile = cursor.fetchone()

        if not user_profile or not user_profile[0]:
            raise HTTPException(status_code=404, detail="Instagram username not found for the user.")

        instagram_username = user_profile[0]

        # Fetch the number of reports for this Instagram username
        cursor.execute("SELECT Report_Counts FROM ReportedUsersInstagram WHERE Username = ?", instagram_username)
        report_row = cursor.fetchone()

        if not report_row:
            return {"message": "Instagram username has no reports.", "report_count": 0}

        report_count = report_row[0]
        return {"message": f"Instagram username '{instagram_username}' has {report_count} reports.", "report_count": report_count}
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error retrieving Instagram report count: {str(e)}")

@app.get("/getConnectedTinder", dependencies=[Depends(oauth2_scheme)])
def get_connected_tinder(token: str = Depends(oauth2_scheme)):
    try:
        # Extract the user's email from the authenticated token
        payload = verify_token(token)
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")

        # Connect to the database
        conn = get_conn()
        cursor = conn.cursor()

        # Fetch the connected Tinder username from UserProfiles
        cursor.execute("SELECT TinderUsername FROM UserProfiles WHERE Email = ?", email)
        user_profile = cursor.fetchone()

        if not user_profile or not user_profile[0]:
            raise HTTPException(status_code=404, detail="Tinder username not found for the user.")

        tinder_username = user_profile[0]

        # Fetch the number of reports for this Tinder username
        cursor.execute("SELECT Report_Counts FROM ReportedUsersTinder WHERE Username = ?", tinder_username)
        report_row = cursor.fetchone()

        if not report_row:
            return {"message": "Tinder username has no reports.", "report_count": 0}

        report_count = report_row[0]
        return {"message": f"Tinder username '{tinder_username}' has {report_count} reports.", "report_count": report_count}
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error retrieving Tinder report count: {str(e)}")


# Helper functions for processing and uploading reports
def extract_text_from_image(image_data):
    try:
        headers = {
            'Ocp-Apim-Subscription-Key': subscription_key,
            'Content-Type': 'application/octet-stream'
        }
        params = {'language': 'en', 'detectOrientation': 'true'}
        response = requests.post(ocr_endpoint, headers=headers, params=params, data=image_data)

        if response.status_code != 200:
            print(f"Error: {response.status_code} - {response.text}")
            return None

        ocr_result = response.json()
        extracted_text = []
        for region in ocr_result.get('regions', []):
            for line in region['lines']:
                line_text = ' '.join([word['text'] for word in line['words']])
                extracted_text.append(line_text)

        return " ".join(extracted_text)

    except Exception as e:
        print(f"Error extracting text from image: {str(e)}")
        return None

def process_video(video_path, frame_interval=120):
    try:
        if not os.path.exists(frame_output_dir):
            os.makedirs(frame_output_dir)

        video_capture = cv2.VideoCapture(video_path)
        frame_count = 0
        success = True
        extracted_texts = []

        while success:
            success, frame = video_capture.read()

            if success and frame_count % frame_interval == 0:
                frame_filename = f"{frame_output_dir}/frame_{frame_count}.jpg"
                cv2.imwrite(frame_filename, frame)

                with open(frame_filename, "rb") as frame_file:
                    image_data = frame_file.read()

                text = extract_text_from_image(image_data)
                if text:
                    extracted_texts.append({"frame": frame_count, "text": text})

            frame_count += 1

        video_capture.release()

        return extracted_texts

    except Exception as e:
        print(f"Error processing video: {str(e)}")
        return None

def upload_report_to_blob(report_data, video_file):
    try:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        folder_name = f"{report_data['reported_username']}_{timestamp}"

        # Upload metadata (JSON)
        metadata_filename = f"{folder_name}/metadata.json"
        metadata_blob = blob_service_client.get_blob_client(container=container_name, blob=metadata_filename)
        metadata_json = json.dumps(report_data, indent=4)
        metadata_blob.upload_blob(metadata_json, overwrite=True, content_settings=ContentSettings(content_type="application/json"))
        print(f"Metadata uploaded: {metadata_filename}")

        # Upload the video file
        video_filename = f"{folder_name}/video.mp4"
        video_blob = blob_service_client.get_blob_client(container=container_name, blob=video_filename)
        video_blob.upload_blob(video_file, overwrite=True, content_settings=ContentSettings(content_type="video/mp4"))
        print(f"Video uploaded: {video_filename}")

        print("Report uploaded successfully!")

    except Exception as e:
        print(f"Error uploading report: {str(e)}")

def upload_report_to_blob_without_video(report_data):
    try:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        folder_name = f"{report_data['reported_username']}_{timestamp}"

        # Upload metadata (JSON)
        metadata_filename = f"{folder_name}/metadata.json"
        metadata_blob = blob_service_client.get_blob_client(container=container_name, blob=metadata_filename)
        metadata_json = json.dumps(report_data, indent=4)
        metadata_blob.upload_blob(metadata_json, overwrite=True, content_settings=ContentSettings(content_type="application/json"))
        print(f"Metadata uploaded: {metadata_filename}")


        print("Report uploaded successfully!")

    except Exception as e:
        print(f"Error uploading report: {str(e)}")

def delete_blob_folder(container_name: str, blob_prefix: str):
    try:
        # Initialize the container client
        container_client = blob_service_client.get_container_client(container_name)
        
        # List all blobs in the container with the specified prefix (like a folder)
        blob_list = container_client.list_blobs(name_starts_with=blob_prefix)
        
        blob_names = [blob.name for blob in blob_list]  # Collect blob names for logging
        
        # Log blob names to verify what is being retrieved
        if not blob_names:
            print(f"No blobs found for prefix {blob_prefix}")
            return False
        
        for blob_name in blob_names:
            print(f"Found blob: {blob_name}")
            container_client.delete_blob(blob_name)

        print(f"All blobs under the prefix {blob_prefix} have been deleted.")
        return True

    except Exception as e:
        print(f"Error deleting blobs in folder {blob_prefix}: {str(e)}")
        return False






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