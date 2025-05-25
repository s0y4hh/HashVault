# HashVault

HashVault is a secure, modern, and intuitive platform for file sharing and retrieval based on cryptographic hashes. It prioritizes security, user control, and a seamless user experience.

## Features

### Core Application Features

1. **User Authentication & Security**

   - Registration with strong password policy.
   - Login with Google OAuth 2.0.
   - Secure session management.

2. **Main Interface: The Hash Search**

   - Search for files using SHA-256 hashes.
   - Download files if permissions allow.

3. **File Upload & Security Configuration**

   - Drag-and-drop file upload with encryption options.
   - Configure file permissions (Private, Public, Specific Users).

4. **User Account & Navigation**

   - Navigation bar with links to main features.
   - Personal dashboard for managing uploaded files and activity logs.

5. **AI-Injected Features**
   - Two-Factor Authentication (2FA).
   - API access for programmatic file search and retrieval.

### Technology Stack

- **Backend**: Python Flask
- **Frontend**: Jinja2, Tailwind CSS, Vanilla JavaScript
- **Database**: SQLite with Flask-SQLAlchemy

## Installation

1. Clone the repository:

   ```bash
   git clone <repository-url>
   cd HashVault
   ```

2. Create a virtual environment and activate it:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Run the application:

   ```bash
   flask run
   ```

5. Access the application at `http://127.0.0.1:5000`.

## Project Structure

```
HashVault/
├── app/
│   ├── __init__.py
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── routes.py
│   │   ├── models.py
│   ├── main/
│   │   ├── __init__.py
│   │   ├── routes.py
│   ├── files/
│   │   ├── __init__.py
│   │   ├── routes.py
│   │   ├── models.py
│   ├── api/
│   │   ├── __init__.py
│   │   ├── routes.py
│   ├── templates/
│   ├── static/
│       ├── css/
│       ├── js/
├── config.py
├── requirements.txt
├── run.py
```

## License

This project is licensed under the MIT License.
