import streamlit as st
import hashlib
import os
import json
import datetime
import shutil
import bcrypt
from pathlib import Path
import threading
import time

# Application Configuration
APP_NAME = "HashVault"
MAX_FILE_SIZE = 250 * 1024 * 1024  # 250MB in bytes
STORAGE_DIR = "file_storage"
DATABASE_FILE = "database.json"
USER_DB_FILE = "users.json"
FILE_RETENTION_DAYS = 30

# Initialize application directories
def initialize_app():
    # Create storage directory if it doesn't exist
    if not os.path.exists(STORAGE_DIR):
        os.makedirs(STORAGE_DIR)
    
    # Initialize database file if it doesn't exist
    if not os.path.exists(DATABASE_FILE):
        with open(DATABASE_FILE, 'w') as f:
            json.dump({}, f)
    
    # Initialize user database if it doesn't exist
    if not os.path.exists(USER_DB_FILE):
        admin_password = bcrypt.hashpw("admin".encode(), bcrypt.gensalt()).decode()
        with open(USER_DB_FILE, 'w') as f:
            json.dump({"admin": {
                "password": admin_password,
                "uploads": [],
                "downloads": []
            }}, f)

# Database Operations
def load_database():
    with open(DATABASE_FILE, 'r') as f:
        return json.load(f)

def save_database(db):
    with open(DATABASE_FILE, 'w') as f:
        json.dump(db, f, indent=4)

def load_user_db():
    with open(USER_DB_FILE, 'r') as f:
        return json.load(f)

def save_user_db(user_db):
    with open(USER_DB_FILE, 'w') as f:
        json.dump(user_db, f, indent=4)

# File Operations
def calculate_file_hash(file_bytes):
    """Calculate SHA256 hash of file content"""
    return hashlib.sha256(file_bytes).hexdigest()

def get_file_storage_path(file_hash):
    """Generate a storage path based on hash to organize files"""
    # Use first 2 chars of hash as subdirectory to prevent too many files in one directory
    subdir = file_hash[:2]
    directory = os.path.join(STORAGE_DIR, subdir)
    if not os.path.exists(directory):
        os.makedirs(directory)
    return os.path.join(directory, file_hash)

def store_file(file_bytes, filename, uploader):
    """Store file and record in database"""
    file_hash = calculate_file_hash(file_bytes)
    file_path = get_file_storage_path(file_hash)
    
    # Save file to disk
    with open(file_path, 'wb') as f:
        f.write(file_bytes)
    
    # Update database
    db = load_database()
    timestamp = datetime.datetime.now().isoformat()
    
    db[file_hash] = {
        "filename": filename,
        "path": file_path,
        "size": len(file_bytes),
        "upload_time": timestamp,
        "uploader": uploader
    }
    save_database(db)
    
    # Update user's upload history
    user_db = load_user_db()
    if uploader in user_db:
        user_db[uploader]["uploads"].append({
            "filename": filename,
            "hash": file_hash,
            "timestamp": timestamp
        })
        save_user_db(user_db)
    
    return file_hash

def get_file_by_hash(file_hash):
    """Retrieve file information by hash"""
    db = load_database()
    return db.get(file_hash)

def record_download(username, file_hash, filename):
    """Record file download in user's history"""
    user_db = load_user_db()
    if username in user_db:
        timestamp = datetime.datetime.now().isoformat()
        user_db[username]["downloads"].append({
            "filename": filename,
            "hash": file_hash,
            "timestamp": timestamp
        })
        save_user_db(user_db)

def clean_old_files():
    """Delete files older than retention period"""
    db = load_database()
    current_time = datetime.datetime.now()
    files_to_delete = []
    
    for file_hash, info in db.items():
        upload_time = datetime.datetime.fromisoformat(info["upload_time"])
        age_days = (current_time - upload_time).days
        
        if age_days > FILE_RETENTION_DAYS:
            # Delete from filesystem
            try:
                os.remove(info["path"])
                files_to_delete.append(file_hash)
            except FileNotFoundError:
                files_to_delete.append(file_hash)
    
    # Update database
    for file_hash in files_to_delete:
        del db[file_hash]
    
    save_database(db)
    return len(files_to_delete)

# User Authentication
def register_user(username, password):
    """Register a new user"""
    user_db = load_user_db()
    
    if username in user_db:
        return False, "Username already exists"
    
    # Hash password before storing
    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    
    user_db[username] = {
        "password": hashed_pw,
        "uploads": [],
        "downloads": []
    }
    
    save_user_db(user_db)
    return True, "Registration successful"

def authenticate_user(username, password):
    """Authenticate user credentials"""
    user_db = load_user_db()
    
    if username not in user_db:
        return False, "Invalid username or password"
    
    stored_pw = user_db[username]["password"].encode()
    
    if bcrypt.checkpw(password.encode(), stored_pw):
        return True, "Login successful"
    else:
        return False, "Invalid username or password"

def format_size(size_bytes):
    """Convert size in bytes to human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024 or unit == 'GB':
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024

def format_timestamp(timestamp_str):
    """Format ISO timestamp to readable format"""
    dt = datetime.datetime.fromisoformat(timestamp_str)
    return dt.strftime("%Y-%m-%d %H:%M:%S")

# Streamlit UI
def main():
    # Initialize app
    initialize_app()
    
    # Set page title and favicon
    st.set_page_config(page_title=APP_NAME, layout="wide")
    
    # Initialize session state for user management
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'username' not in st.session_state:
        st.session_state.username = None
    
    # App header
    st.title(f"{APP_NAME} - Secure File Storage")
    
    # Handle authentication
    if not st.session_state.logged_in:
        render_auth_page()
    else:
        # Check if admin and render appropriate page
        if st.session_state.username == "admin":
            render_admin_page()
        else:
            render_user_page()

def render_auth_page():
    """Render the authentication page"""
    st.header("Authentication")
    
    tab1, tab2 = st.tabs(["Login", "Register"])
    
    with tab1:
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submit = st.form_submit_button("Login")
            
            if submit:
                if username and password:
                    success, message = authenticate_user(username, password)
                    if success:
                        st.session_state.logged_in = True
                        st.session_state.username = username
                        st.success(message)
                        st.rerun()
                    else:
                        st.error(message)
                else:
                    st.error("Please enter both username and password")
    
    with tab2:
        with st.form("register_form"):
            new_username = st.text_input("Choose Username")
            new_password = st.text_input("Choose Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")
            submit = st.form_submit_button("Register")
            
            if submit:
                if new_username and new_password and confirm_password:
                    if new_password != confirm_password:
                        st.error("Passwords do not match")
                    else:
                        success, message = register_user(new_username, new_password)
                        if success:
                            st.success(message)
                        else:
                            st.error(message)
                else:
                    st.error("Please fill in all fields")

def render_user_page():
    """Render the user interface"""
    st.sidebar.title(f"Welcome, {st.session_state.username}")
    
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.username = None
        st.rerun()
    
    # Create tabs for different functionalities
    search_tab, upload_tab, history_tab = st.tabs(["Search Files", "Upload Files", "History"])
    
    with search_tab:
        render_search_section()
        
    with upload_tab:
        render_upload_section()
        
    with history_tab:
        render_history_section()

def render_search_section():
    """Render file search functionality"""
    st.header("Search Files by Hash")
    
    search_hash = st.text_input("Enter SHA256 Hash")
    
    if st.button("Search"):
        if search_hash:
            # Validate hash format (basic validation)
            if len(search_hash) != 64 or not all(c in "0123456789abcdefABCDEF" for c in search_hash):
                st.error("Invalid hash format. SHA256 hashes are 64 hexadecimal characters.")
            else:
                file_info = get_file_by_hash(search_hash)
                
                if file_info:
                    st.success(f"File found: {file_info['filename']}")
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.write(f"Size: {format_size(file_info['size'])}")
                    with col2:
                        st.write(f"Uploaded by: {file_info['uploader']}")
                    with col3:
                        st.write(f"Upload time: {format_timestamp(file_info['upload_time'])}")
                    
                    # Create download button
                    with open(file_info['path'], 'rb') as f:
                        file_bytes = f.read()
                        st.download_button(
                            label="Download File",
                            data=file_bytes,
                            file_name=file_info['filename'],
                            mime="application/octet-stream",
                            on_click=lambda: record_download(st.session_state.username, search_hash, file_info['filename'])
                        )
                else:
                    st.error("File not found. Please check the hash and try again.")
        else:
            st.warning("Please enter a file hash to search.")

def render_upload_section():
    """Render file upload functionality"""
    st.header("Upload Files")
    
    uploaded_file = st.file_uploader("Choose a file to upload", accept_multiple_files=False)
    
    if uploaded_file is not None:
        file_size = uploaded_file.size
        
        if file_size > MAX_FILE_SIZE:
            st.error(f"File too large. Maximum allowed size is {format_size(MAX_FILE_SIZE)}.")
        else:
            file_bytes = uploaded_file.read()
            
            if st.button("Confirm Upload"):
                with st.spinner("Processing file..."):
                    try:
                        file_hash = store_file(file_bytes, uploaded_file.name, st.session_state.username)
                        st.success(f"File uploaded successfully!")
                        st.info(f"File Hash: {file_hash}")
                    except Exception as e:
                        st.error(f"Upload failed: {str(e)}")

def render_history_section():
    """Render user history section"""
    st.header("Your Activity History")
    
    upload_history, download_history = st.tabs(["Upload History", "Download History"])
    
    user_db = load_user_db()
    user_data = user_db.get(st.session_state.username, {"uploads": [], "downloads": []})
    
    with upload_history:
        if user_data["uploads"]:
            st.subheader(f"You have uploaded {len(user_data['uploads'])} files")
            
            for upload in reversed(user_data["uploads"]):
                with st.expander(f"{upload['filename']} - {upload['hash'][:10]}..."):
                    st.text(f"Filename: {upload['filename']}")
                    st.text(f"Hash: {upload['hash']}")
                    st.text(f"Uploaded on: {format_timestamp(upload['timestamp'])}")
        else:
            st.info("You haven't uploaded any files yet.")
    
    with download_history:
        if user_data["downloads"]:
            st.subheader(f"You have downloaded {len(user_data['downloads'])} files")
            
            for download in reversed(user_data["downloads"]):
                with st.expander(f"{download['filename']} - {download['hash'][:10]}..."):
                    st.text(f"Filename: {download['filename']}")
                    st.text(f"Hash: {download['hash']}")
                    st.text(f"Downloaded on: {format_timestamp(download['timestamp'])}")
        else:
            st.info("You haven't downloaded any files yet.")

def render_admin_page():
    """Render admin panel"""
    st.sidebar.title(f"Admin Panel")
    
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.username = None
        st.rerun()
    
    st.header("System Administration")
    
    # Create tabs for admin functions
    files_tab, users_tab, maintenance_tab = st.tabs(["File Management", "User Management", "System Maintenance"])
    
    with files_tab:
        render_admin_files()
        
    with users_tab:
        render_admin_users()
        
    with maintenance_tab:
        render_admin_maintenance()

def render_admin_files():
    """Render admin file management"""
    st.subheader("Files in Storage")
    
    db = load_database()
    
    if db:
        # Display stats
        total_size = sum(info["size"] for info in db.values())
        st.info(f"Total files: {len(db)} | Total storage used: {format_size(total_size)}")
        
        # Display files table
        files_data = []
        for file_hash, info in db.items():
            files_data.append({
                "Filename": info["filename"],
                "Hash": file_hash[:15] + "...",
                "Size": format_size(info["size"]),
                "Uploaded": format_timestamp(info["upload_time"]),
                "User": info["uploader"]
            })
        
        # Sort by upload time
        files_data.sort(key=lambda x: x["Uploaded"], reverse=True)
        
        # Display as dataframe
        st.dataframe(files_data)
    else:
        st.info("No files in storage")

def render_admin_users():
    """Render admin user management"""
    st.subheader("User Management")
    
    user_db = load_user_db()
    
    if user_db:
        # Calculate stats for each user
        user_stats = []
        for username, data in user_db.items():
            user_stats.append({
                "Username": username,
                "Upload Count": len(data["uploads"]),
                "Download Count": len(data["downloads"]),
                "Is Admin": "Yes" if username == "admin" else "No"
            })
        
        # Display as dataframe
        st.dataframe(user_stats)
    else:
        st.info("No users in database")

def render_admin_maintenance():
    """Render admin maintenance tools"""
    st.subheader("System Maintenance")
    
    # File cleanup
    st.write(f"Files older than {FILE_RETENTION_DAYS} days will be deleted when cleanup is triggered.")
    
    if st.button("Run Storage Cleanup"):
        with st.spinner("Cleaning old files..."):
            deleted_count = clean_old_files()
            st.success(f"Cleanup complete. {deleted_count} files were removed.")
    
    # Database backup
    if st.button("Backup Database"):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = "backups"
        
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        
        try:
            # Copy database files
            shutil.copy2(DATABASE_FILE, f"{backup_dir}/database_{timestamp}.json")
            shutil.copy2(USER_DB_FILE, f"{backup_dir}/users_{timestamp}.json")
            st.success(f"Backup created successfully in {backup_dir} directory.")
        except Exception as e:
            st.error(f"Backup failed: {str(e)}")

# Run the application
if __name__ == "__main__":
    main()
