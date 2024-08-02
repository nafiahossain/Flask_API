from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

from flask import Flask, request, jsonify, url_for
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask_migrate import Migrate
import secrets
from flasgger import Swagger
from config import Config
from models import db, User

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
swagger = Swagger(app, template={
    "swagger": "2.0",
    "info": {
        "title": "User Management API",
        "description": "API documentation",
        "version": "1.0.0"
    },
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header"
        }
    },
    "security": [
        {"Bearer": []}
    ]
})


# Authorization Routes

@app.route('/register', methods=['POST'])
def register():
    """
    User Registration
    ---
    tags:
      - Authorization
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            username:
              type: string
            first_name:
              type: string
            last_name:
              type: string
            password:
              type: string
            email:
              type: string
            role:
              type: string
              default: 'User'
    responses:
      201:
        description: User created successfully
      400:
        description: Bad request
    """
    data = request.get_json()

    if User.query.filter_by(username=data['username']).first():
        return jsonify({"message": "This username already exists"}), 400
    if User.query.filter_by(email=data['email']).first():
        return jsonify({"message": "This email already exists"}), 400

    role = data.get('role', 'User')

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

    if role == 'Admin':
        return jsonify({"message": "Admin created successfully"}), 201
    else:
        return jsonify({"message": "User created successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    """
    User Login
    ---
    tags:
      - Authorization
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            username:
              type: string
            password:
              type: string
    responses:
      200:
        description: Login successful
        schema:
          type: object
          properties:
            message:
              type: string
            access_token:
              type: string
      401:
        description: Unauthorized
    """
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()

    if user and check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=user.id)
        return jsonify(message="Login successful", access_token=access_token), 200

    return jsonify({"message": "Username or password is wrong"}), 401


# ADMIN Routes

@app.route('/users', methods=['GET'])
@jwt_required()
def get_all_users():
    """
    Get All Users
    ---
    tags:
      - Admin Privileges
    responses:
      200:
        description: List of users
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
        description: Unauthorized
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


@app.route('/user/<int:user_id>', methods=['GET'])
@jwt_required()
def get_any_user(user_id):
    """
    Get Any User Details (Admin Only)
    ---
    tags:
      - Admin Privileges
    parameters:
      - name: user_id
        in: path
        type: integer
        required: true
        description: The ID of the user to retrieve
    responses:
      200:
        description: User details
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
        description: Unauthorized
      404:
        description: User not found
    security:
      - Bearer: []
    """
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    if not current_user or current_user.role != 'Admin':
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


@app.route('/user/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_any_user(user_id):
    """
    Delete Any User Account (Admin Only)
    ---
    tags:
      - Admin Privileges
    parameters:
      - name: user_id
        in: path
        type: integer
        required: true
        description: The ID of the user to delete
    responses:
      200:
        description: Account deleted
      403:
        description: Unauthorized
      404:
        description: User not found
    security:
      - Bearer: []
    """
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    if not current_user or current_user.role != 'Admin':
        return jsonify({"message": "Unauthorized"}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404

    if user.role == 'Admin' and current_user.id != user_id:
        return jsonify({"message": "Admins cannot delete other admins' accounts"}), 403

    db.session.delete(user)
    db.session.commit()

    return jsonify({"message": "Account deleted successfully"}), 200


@app.route('/user/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_any_user(user_id):
    """
    Update Any User Details (Admin Only)
    ---
    tags:
      - Admin Privileges
    parameters:
      - name: user_id
        in: path
        type: integer
        required: true
        description: The ID of the user to update
      - name: body
        in: body
        required: true
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
    responses:
      200:
        description: User details updated successfully
      403:
        description: Unauthorized or forbidden
      404:
        description: User not found
    security:
      - Bearer: []
    """
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({"message": "User not found"}), 404

    if current_user.role != 'Admin':
        return jsonify({"message": "Unauthorized"}), 403

    if user.role == 'Admin' and current_user.id != user_id:
        return jsonify({"message": "Admins cannot update other admins' details"}), 403

    for key, value in request.json.items():
        if key == 'password' and 'email' and 'id':
            return jsonify({"message": "Password, Email, or ID update not allowed"}), 403
        setattr(user, key, value)
    
    db.session.commit()

    if current_user.id == user_id:
        return jsonify({"message": "Admin details updated successfully"}), 200
    else:
        return jsonify({"message": "User details updated successfully"}), 200



# USER Routes

@app.route('/user', methods=['GET'])
@jwt_required()
def get_user():
    """
    Get Own User Details
    ---
    tags:
      - User
    responses:
      200:
        description: User details
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
            created_date:
              type: string
              format: date-time
            updated_date:
              type: string
              format: date-time
      404:
        description: User not found
    security:
      - Bearer: []
    """
    user_id = get_jwt_identity()
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
        "active": user.active,
        "created_date": user.created_date.isoformat() if user.created_date else None,
        "updated_date": user.updated_date.isoformat() if user.updated_date else None
    }), 200


@app.route('/user', methods=['PUT'])
@jwt_required()
def update_own_details():
    """
    Update Own Details
    ---
    tags:
      - User
    parameters:
      - name: body
        in: body
        required: true
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
            password:
              type: string
    responses:
      200:
        description: User details updated successfully
      403:
        description: Password update not allowed
      404:
        description: User not found
    security:
      - Bearer: []
    """
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({"message": "User not found"}), 404

    for key, value in request.json.items():
        if key == 'password' or 'role' or 'id':
            return jsonify({"message": "Password, Role, or ID update not allowed"}), 403
        setattr(user, key, value)
    
    db.session.commit()

    return jsonify({"message": "User details updated successfully"}), 200


@app.route('/user', methods=['DELETE'])
@jwt_required()
def delete_own_account():
    """
    Delete Own Account
    ---
    tags:
      - User
    responses:
      200:
        description: Account deleted
      404:
        description: User not found
    security:
      - Bearer: []
    """
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404

    db.session.delete(user)
    db.session.commit()
    
    return jsonify({"message": "Account deleted successfully"}), 200


# PASSWORD RESET REQUEST AND UPDATE Routes

@app.route('/request-password-reset', methods=['POST'])
def request_password_reset():
    """
    Request Password Reset
    ---
    tags:
      - Password Reset and Update
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            email:
              type: string
    responses:
      200:
        description: Password reset instructions sent to email
      404:
        description: User not found
    """
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if not user:
        return jsonify({"message": "User not found"}), 404

    token = secrets.token_urlsafe(32)
    user.reset_token = token
    user.reset_token_expiration = datetime.utcnow() + timedelta(hours=1)
    db.session.commit()

    reset_url = url_for('reset_password', token=token, _external=True)
    
    return jsonify({
        "message": "Password reset instructions sent to email",
        "reset_url": reset_url,  # Only for demonstration
        "reset_token": token
    }), 200

@app.route('/reset-password/<token>', methods=['POST'])
def reset_password(token):
    """
    Reset Password
    ---
    tags:
      - Password Reset and Update
    parameters:
      - name: token
        in: path
        type: string
        required: true
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            new_password:
              type: string
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