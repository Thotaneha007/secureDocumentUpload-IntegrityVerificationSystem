# Secure Document System

A secure web application for uploading, managing, and verifying documents with advanced security features including **Multi-Factor Authentication (MFA)** and **Role-Based Access Control (RBAC)**.

## Features

- **Multi-Factor Authentication (MFA):** Adds an extra layer of security. Users must provide a 6-digit TOTP code from an authenticator app (like Google Authenticator or Authy) to log in.
- **Role-Based Access Control (RBAC):** Supports 3 distinct hierarchical user roles for enterprise readiness:
  - **Admin:** Has full control. Can view all system documents and permanently delete them across the platform.
  - **Auditor:** Has read-only compliance access. Can view the metadata of all documents across the system and verify their cryptographic integrity, but cannot upload or delete.
  - **User:** Standard user who can securely upload documents and verify their personal files.
- **Secure File Storage:** Files are hashed, encrypted, and digitally signed before storage to ensure confidentiality, integrity, and authenticity.

## Prerequisites

- Python 3.12
- Flask
- Cryptography library

## Installation & Setup

1. **Clone or download** this repository to your local machine.

2. **Open a terminal/command prompt** and navigate to the project directory:
   ```bash
   cd path/to/SecureDocumentSystem
   ```

3. **Install the required dependencies** (if you haven't already). It's recommended to use a virtual environment:
   ```bash
   pip install flask cryptography bcrypt
   ```

## How to Run the Application

1. Make sure you are in the project folder (`SecureDocumentSystem`).
2. Run the main Flask application:
   ```bash
   python app.py
   ```
3. Open your web browser and go to:
   ```
   http://127.0.0.1:5000
   ```

## How to Test MFA and RBAC

### 1. Setting up an Admin Account
1. Go to the **Register** page (`http://127.0.0.1:5000/register`).
2. Create an account with the exact username: **`admin`** and a password of your choice.
3. You will be shown an **MFA Setup** page with a QR code and a secret key.
4. Open an authenticator app (e.g., Google Authenticator, Authy, or Microsoft Authenticator) on your phone.
5. **Scan the QR code** or manually enter the secret key provided on the screen.
6. Click "I have set it up. Go to Login".

### 2. Logging in as Admin
1. On the **Login** page, enter the username `admin` and your password.
2. Open your authenticator app and enter the **6-digit code** it currently displays into the "6-digit Authenticator Code" field.
3. Click Login.
4. *Result:* Because of your `admin` role, you will be automatically redirected to the **Admin Dashboard** (`/admin`), where you can see all documents uploaded by everyone.

### 3. Setting up a Regular User Account
1. Go back to the **Register** page.
2. Create an account with any username other than "admin" (e.g., `john_doe`).
3. Scan the new QR code for this user with your authenticator app.
4. Go to the **Login** page and log in with this new account and its corresponding 6-digit MFA token.
5. *Result:* Because of your standard `user` role, you will be redirected to the **Secure Upload** page (`/upload`), where you can upload and verify your own files. Standard users cannot access the `/admin` page.

## Project Structure Highlights
- `app.py`: The main application file containing routing and business logic.
- `database.db`: SQLite database storing user credentials, MFA secrets, roles, and document metadata.
- `auth/mfa.py`: Custom zero-dependency TOTP implementation for MFA logic.
- `crypto_utils/`: Modules handling hashing, encryption, and digital signatures.
- `templates/`: HTML templates for the frontend (including `admin.html` and `mfa_setup.html`).
