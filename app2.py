from flask import Flask, request, jsonify, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flasgger import Swagger
from flask_migrate import Migrate
import secrets
import os

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://postgres:p%40stgress@localhost:5433/flask_api')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
swagger = Swagger(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(256), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.Enum('Admin', 'User', name='user_roles'), nullable=False)
    created_date = db.Column(db.DateTime, server_default=db.func.now())
    updated_date = db.Column(db.DateTime, server_default=db.func.now(), server_onupdate=db.func.now())
    active = db.Column(db.Boolean, default=True)

    reset_token = db.Column(db.String(100), unique=True)
    reset_token_expiration = db.Column(db.DateTime)



# Routes with OpenAPI docstrings
@app.route('/register', methods=['POST'])
def register():
    """
    Register a new user
    ---
    tags:
      - authentication
    requestBody:
      content:
        application/json:
          schema:
            type: object
            properties:
              username:
                type: string
              password:
                type: string
              first_name:
                type: string
              last_name:
                type: string
              email:
                type: string
              role:
                type: string
            required:
              - username
              - password
              - first_name
              - last_name
              - email
    responses:
      201:
        description: User or Admin created successfully
      400:
        description: User already exists
    """
    # User Registration function implementation
    data = request.get_json()

    # Check if username or email already exists
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"message": "This username already exists"}), 400
    if User.query.filter_by(email=data['email']).first():
        return jsonify({"message": "This email already exists"}), 400


    # Set the role, defaulting to 'User' if not provided
    role = data.get('role', 'User')

    # Create the new user
    new_user = User(
        username=data['username'],
        first_name=data['first_name'],
        last_name=data['last_name'],
        password=generate_password_hash(data['password']),
        email=data['email'],
        role=role
    )
    db.session.add(new_user)
    db.session.commit()

    # Send different messages based on the role
    if role == 'Admin':
        return jsonify({"message": "Admin created successfully"}), 201
    else:
        return jsonify({"message": "User created successfully"}), 201

   
# Authenticate a user and return a JWT token
@app.route('/login', methods=['POST'])
def login():
    """
    Authenticate a user and return a JWT token
    ---
    tags:
      - authentication
    requestBody:
      content:
        application/json:
          schema:
            type: object
            properties:
              username:
                type: string
              password:
                type: string
            required:
              - username
              - password
    responses:
      200:
        description: Login successful
        content:
          application/json:
            schema:
              type: object
              properties:
                message:
                  type: string
                access_token:
                  type: string
      401:
        description: Username or password is wrong
    """
    # ... (function implementation remains the same)
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()

    if user and check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=user.id)
        return jsonify(message="Login successful", access_token=access_token), 200
    
    return jsonify({"message": "Username or password is wrong"}), 401


@app.route('/user/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    """
    Get user details
    ---
    tags:
      - users
    parameters:
      - name: user_id
        in: path
        type: integer
        required: true
        description: The user ID
    security:
      - bearerAuth: []
    responses:
      200:
        description: User details retrieved successfully
        content:
          application/json:
            schema:
              type: object
              properties:
                id:
                  type: integer
                username:
                  type: string
                first_name:
                  type: string
                last_name:
                  type: string
                email:
                  type: string
                role:
                  type: string
                active:
                  type: boolean
      403:
        description: Unauthorized access
      404:
        description: User not found
    """
    # ... (function implementation remains the same)
    current_user = User.query.get(get_jwt_identity())
    if not current_user.role == 'Admin' and current_user.id != user_id:
        return jsonify({"message": "Unauthorized"}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404

    return jsonify({
        "id": user.id,
        "username": user.username,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "email": user.email,
        "role": user.role,
        "active": user.active
    }), 200


# Allows admins to see the list of all users
@app.route('/users', methods=['GET'])
@jwt_required()
def get_all_users():
    """
    Get a list of all users
    ---
    tags:
      - users
    security:
      - bearerAuth: []
    responses:
      200:
        description: List of users retrieved successfully
        content:
          application/json:
            schema:
              type: array
              items:
                type: object
                properties:
                  id:
                    type: integer
                  username:
                    type: string
                  first_name:
                    type: string
                  last_name:
                    type: string
                  email:
                    type: string
                  role:
                    type: string
                  active:
                    type: boolean
      403:
        description: Unauthorized access
    """
    current_user = User.query.get(get_jwt_identity())
    if current_user.role != 'Admin':
        return jsonify({"message": "Unauthorized"}), 403

    users = User.query.all()
    users_list = [{
        "id": user.id,
        "username": user.username,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "email": user.email,
        "role": user.role,
        "active": user.active
    } for user in users]

    return jsonify(users_list), 200



@app.route('/user/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    """
    Update user details
    ---
    tags:
      - users
    parameters:
      - name: user_id
        in: path
        type: integer
        required: true
        description: The user ID
      - name: body
        in: body
        required: true
        description: User details to update
        schema:
          type: object
          properties:
            username:
              type: string
            first_name:
              type: string
            last_name:
              type: string
            email:
              type: string
            role:
              type: string
            password:
              type: string
            active:
              type: boolean
    security:
      - bearerAuth: []
    responses:
      200:
        description: User details updated successfully
      403:
        description: Unauthorized access
      404:
        description: User not found
      409:
        description: Conflict in role update
    """
    current_user = User.query.get(get_jwt_identity())
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({"message": "User not found"}), 404

    # Check if the current user is authorized to make the update
    if current_user.role != 'Admin':
        if current_user.id != user_id:
            return jsonify({"message": "Unauthorized to change others' details"}), 403

        if 'role' in request.json and request.json['role'] == 'Admin':
            return jsonify({"message": "Unauthorized to change role to Admin"}), 403

    if current_user.role == 'Admin' and user.role == 'Admin' and current_user.id != user_id:
        return jsonify({"message": "Admins cannot update other admins' details"}), 403

    # Update user details
    for key, value in request.json.items():
        if key == 'role' and current_user.role != 'Admin':
            continue
        if key == 'password':
            return jsonify({"message": "Password update not allowed"}), 403
        setattr(user, key, value)
    
    db.session.commit()

    if current_user.role == 'Admin' and current_user.id == user_id:
        return jsonify({"message": "Admin details updated successfully"}), 200
    else:
        return jsonify({"message": "User details updated successfully"}), 200



@app.route('/user/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    """
    Delete a user
    ---
    tags:
      - users
    parameters:
      - name: user_id
        in: path
        type: integer
        required: true
        description: The user ID
    security:
      - bearerAuth: []
    responses:
      200:
        description: User deleted successfully
      403:
        description: Unauthorized access
      404:
        description: User not found
    """
    current_user = User.query.get(get_jwt_identity())

    # Check if the current user is allowed to delete the account
    if current_user.role != 'Admin' and current_user.id != user_id:
        return jsonify({"message": "Unauthorized"}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404

    # Prevent admins from deleting other admins' accounts
    if current_user.role == 'Admin' and user.role == 'Admin' and current_user.id != user_id:
        return jsonify({"message": "Admins cannot delete other admins' accounts"}), 403

    db.session.delete(user)
    db.session.commit()

    if current_user.role == 'Admin':
        return jsonify({"message": "Deleted by the admin"}), 200
    else:
        return jsonify({"message": "Deleted by the user"}), 200



# New route to request a password reset
@app.route('/request-password-reset', methods=['POST'])
def request_password_reset():
    """
    Request a password reset
    ---
    tags:
      - authentication
    requestBody:
      content:
        application/json:
          schema:
            type: object
            properties:
              email:
                type: string
            required:
              - email
    responses:
      200:
        description: Reset token generated successfully
      404:
        description: User not found
    """
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if not user:
        return jsonify({"message": "User not found"}), 404

    # Generate a secure token
    token = secrets.token_urlsafe(32)
    user.reset_token = token
    user.reset_token_expiration = datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
    db.session.commit()

    # Here you would typically send an email with the reset link
    reset_url = url_for('reset_password', token=token, _external=True)
    
    # For demonstration purposes, we're returning the URL in the response
    # In a real application, you'd send this URL via email and not expose it in the response
    return jsonify({
        "message": "Password reset instructions sent to email",
        "reset_url": reset_url  # Only for demonstration
    }), 200



# New route to reset the password using the token
@app.route('/reset-password/<token>', methods=['POST'])
def reset_password(token):
    """
    Reset user password using a token
    ---
    tags:
      - authentication
    parameters:
      - name: token
        in: path
        type: string
        required: true
        description: The reset token
    requestBody:
      content:
        application/json:
          schema:
            type: object
            properties:
              new_password:
                type: string
            required:
              - new_password
    responses:
      200:
        description: Password updated successfully
      400:
        description: Invalid or expired token
    """
    data = request.get_json()
    user = User.query.filter_by(reset_token=token).first()
    
    if user and user.reset_token_expiration > datetime.utcnow():
        user.password = generate_password_hash(data['new_password'])
        user.reset_token = None
        user.reset_token_expiration = None
        db.session.commit()
        return jsonify({"message": "Password updated successfully"}), 200
    else:
        return jsonify({"message": "Invalid or expired token"}), 400

  
# Create tables within app context
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)