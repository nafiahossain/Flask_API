# Flask API with JWT Authentication

## Overview

This Flask API project includes user registration, login, and profile management functionalities. It uses JWT (JSON Web Token) for authentication and supports role-based (User/Admin) access control. The API is designed to be easily extendable and secure.

## Features

- **User Registration**: Allows users to register with username, password, email, first name, last name, and role. If the "role" is not defined while registering, the user will be registered as a regular user by default. And if "role"="Admin", the user will be registered as an Admin.
- **User Login**: Authenticates users and returns a JWT token.
- **User Management**: Allows users to view, delete, and update their details and admins to manage (view any/all users, and modify/delete) their user accounts.
- **Password Reset**: Supports password reset functionality via email.

## Installation

### Prerequisites

- Python 3.7 or later
- Flask
- PostgreSQL
- SQLAlchemy
- Virtualenv (optional but recommended)

### Setup

1. **Clone the repository**:

    ```bash
    git clone https://github.com/nafiahossain/Flask_API.git
    cd Flask-API
    ```

2. **Create and activate a virtual environment** (optional but recommended):

    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. **Install dependencies**:

    ```bash
    pip install -r requirements.txt
    ```
    
    or,
   
    ```bash
    pip install Flask Flask-SQLAlchemy Flask-JWT-Extended Werkzeug Flasgger Flask-Migrate psycopg2-binary
    ```
   
5. **Set up environment variables**:

    Create a `.env` file in the project root directory and add the following:

    ```env
    DATABASE_URL=postgresql://username:password@localhost:5433/yourdatabase
    JWT_SECRET_KEY=your-secret-key
    ```

6. **Initialize the database**:

    ```bash
    flask db init
    flask db migrate
    flask db upgrade
    ```

7. **Run the application**:

    ```bash
    python app.py
    ```

## API Endpoints

### Register

- **Endpoint**: `/register`
- **Method**: `POST`
- **Description**: Registers a new user.
- **Request Body**:

    ```json
    {
      "username": "user123",
      "password": "password123",
      "first_name": "John",
      "last_name": "Doe",
      "email": "john.doe@example.com",
      "role": "User"
    }
    ```

- **Responses**:
    - `201 Created`: User or Admin created successfully.
    - `400 Bad Request`: User or email already exists.

### Login

- **Endpoint**: `/login`
- **Method**: `POST`
- **Description**: Authenticates a user and returns a JWT token.
- **Request Body**:

    ```json
    {
      "username": "user123",
      "password": "password123"
    }
    ```

- **Responses**:
    - `200 OK`: Login successful with JWT token.
    - `401 Unauthorized`: Incorrect username or password.

### Get User Details

- **Endpoint**: `/user/<int:user_id>`
- **Method**: `GET`
- **Description**: Retrieves details of a specific user.
- **Parameters**:
    - `user_id` (path): The ID of the user.
- **Responses**:
    - `200 OK`: User details retrieved successfully.
    - `403 Forbidden`: Unauthorized access.
    - `404 Not Found`: User not found.

### Update User Details

- **Endpoint**: `/user/<int:user_id>`
- **Method**: `PUT`
- **Description**: Updates user details.
- **Parameters**:
    - `user_id` (path): The ID of the user.
- **Request Body**:

    ```json
    {
      "username": "user123",
      "first_name": "John",
      "last_name": "Doe",
      "email": "john.doe@example.com",
      "role": "User",
      "password": "newpassword123",
      "active": true
    }
    ```

- **Responses**:
    - `200 OK`: User details updated successfully.
    - `403 Forbidden`: Unauthorized access.
    - `404 Not Found`: User not found.

### Delete User

- **Endpoint**: `/user/<int:user_id>`
- **Method**: `DELETE`
- **Description**: Deletes a specific user.
- **Parameters**:
    - `user_id` (path): The ID of the user.
- **Responses**:
    - `200 OK`: User deleted successfully.
    - `403 Forbidden`: Unauthorized access.
    - `404 Not Found`: User not found.

### Request Password Reset

- **Endpoint**: `/request-password-reset`
- **Method**: `POST`
- **Description**: Requests a password reset and sends a reset link via email.
- **Request Body**:

    ```json
    {
      "email": "john.doe@example.com"
    }
    ```

- **Responses**:
    - `200 OK`: Reset token generated and sent to email.
    - `404 Not Found`: User not found.

### Reset Password

- **Endpoint**: `/reset-password/<token>`
- **Method**: `POST`
- **Description**: Resets the user password using a reset token.
- **Parameters**:
    - `token` (path): The reset token received via email.
- **Request Body**:

    ```json
    {
      "new_password": "newpassword123"
    }
    ```

- **Responses**:
    - `200 OK`: Password updated successfully.
    - `400 Bad Request`: Invalid or expired token.

## Testing

To test the API, you can use tools like [Postman](https://www.postman.com/) or [Swagger UI](http://localhost:5000/apidocs) (if integrated). Ensure that you include the `Authorization` header with the `Bearer` token for endpoints that require authentication.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue for discussion.

