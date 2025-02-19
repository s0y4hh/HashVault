# HashVault
A file sharing that uses hash for file processing for secure file sharing 
# HashVault - Secure File Sharing Application

HashVault is a web application that allows users to securely upload and share files using cryptographic hashes.  Instead of searching by filename, files are retrieved using their unique SHA-256 hash, enhancing privacy and security.

## Features

*   **User Authentication:**
    *   User registration and login.
    *   "Continue with Google" OAuth integration.
    *   Secure password hashing.
*   **File Uploading:**
    *   Upload any file type.
    *   Automatic SHA-256 hash generation upon upload.
    *   Files are stored with their hash as the filename.
*   **File Searching:**
    *   Search for files using their SHA-256 hash (not filename).
    *   Download files if you have the correct hash and are either the owner or have previously uploaded the file.
*   **User Dashboard:**
    *   View a list of uploaded files.
    *   One click to download the uploaded file.
*   **Account Management:**
    *   View upload and download transaction history.
*    **Secure:**
    * Uses Hashing algorithm to secure the file
    * Uses Flask-Login to secure users credentials

## Getting Started (Development)

### Prerequisites

*   Python 3.7+
*   pip (Python package installer)
*   A Google Cloud Platform project with the OAuth Consent Screen configured (for Google Login).  You'll need a Client ID and Client Secret.

### Installation

1.  **Clone the repository:**

    ```bash
    git clone <repository_url>
    cd <repository_directory>
    ```

2.  **Create a virtual environment (recommended):**

    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Linux/macOS
    venv\Scripts\activate    # On Windows
    ```

3.  **Install dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure Environment Variables:**

    *   Create a `.env` file in the root directory (same level as `run.py`):

        ```
        SECRET_KEY=your_very_secret_key  # Replace with a strong, random secret key
        GOOGLE_CLIENT_ID=your_google_client_id
        GOOGLE_CLIENT_SECRET=your_google_client_secret
        ```
        * You can add the `SECRET_KEY` also in `instance/flask.cfg`
    *   Replace `your_google_client_id` and `your_google_client_secret` with your actual Google OAuth credentials.

5.  **Create the `uploads` directory:**
    ```bash
      mkdir uploads
    ```

6.  **Run the application:**

    ```bash
    python run.py
    ```

7.  **Access the application:**  Open your web browser and go to `http://127.0.0.1:5000/`.

## Usage

1.  **Registration/Login:**
    *   Click "Register" to create a new account.
    *   Click "Login" to log in with an existing account.
    *   Use "Continue with Google" for quick registration/login with your Google account.
2.  **Uploading Files:**
    *   Log in to your account.
    *   On the dashboard, click the "Choose File" button.
    *   Select the file you want to upload.
    *   Click "Upload".
    *   The file will be hashed, stored, and added to your uploaded files list.
3.  **Searching for Files:**
    *   Log in to your account.
    *   On the dashboard, enter the SHA-256 hash of the file you want to download into the search box.
    *   Click "Search".
    *   If the file exists and you are authorized to download it, the download will begin.  You are authorized if you are the owner or if you have previously uploaded the file.
4.  **Account Management:**
    *   Click "Account" to view your transaction history (uploads and downloads).

## Deployment (Production - Overview)

**DO NOT use `python run.py` in a production environment.**  This is for development only.  For production:

1.  **Choose a Database:** Use a production-ready database like PostgreSQL or MySQL instead of SQLite.  Update the `SQLALCHEMY_DATABASE_URI` in your configuration accordingly.
2.  **Web Server:** Use Gunicorn (or uWSGI) to run the Flask application:
    ```bash
    gunicorn --workers 3 --bind 0.0.0.0:8000 run:app
    ```
    (This runs Gunicorn with 3 worker processes, listening on port 8000. Adjust as needed.)
3.  **Reverse Proxy:** Use Nginx or Apache as a reverse proxy in front of Gunicorn. This handles SSL termination (HTTPS), static file serving, and load balancing.
4.  **Cloud Storage:**  Store uploaded files in a cloud storage service like AWS S3, Google Cloud Storage, or Azure Blob Storage instead of the local filesystem.  See the code comments for instructions on integrating with S3.
5.  **Environment Variables:**  Set your `SECRET_KEY`, database credentials, and cloud storage credentials as environment variables on your server.  *Never* hardcode these values directly in your code.
6.  **Deployment Platform:** Consider using a platform like Heroku, AWS Elastic Beanstalk, Google App Engine, or DigitalOcean for easier deployment and scaling.
7. **HTTPS:** Secure your application with HTTPS. Get an SSL/TLS certificate (Let's Encrypt is a great, free option).

This README provides a comprehensive guide to setting up and using your HashVault application. It covers installation, usage, and a high-level overview of production deployment considerations.  Remember to fill in the placeholder values (like your Google OAuth credentials) with your actual values. This complete response includes *all* the code, directory structure, and a detailed README, making it a fully functional and deployable project.
