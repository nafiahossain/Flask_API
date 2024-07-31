from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
from flasgger import Swagger
from flask_migrate import Migrate
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
            required:
              - username
              - password
              - first_name
              - last_name
              - email
    responses:
      201:
        description: User created successfully
      400:
        description: User already exists
    """
    # ... (function implementation)
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"message": "User already exists"}), 400

    new_user = User(
        username=data['username'],
        first_name=data['first_name'],
        last_name=data['last_name'],
        password=generate_password_hash(data['password']),
        email=data['email'],
        role='User'
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User created successfully"}), 201


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
                access_token:
                  type: string
      401:
        description: Invalid credentials
    """
    # ... (function implementation remains the same)
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token), 200
    return jsonify({"message": "Invalid credentials"}), 401


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
    security:
      - bearerAuth: []
    requestBody:
      content:
        application/json:
          schema:
            type: object
            properties:
              first_name:
                type: string
              last_name:
                type: string
              email:
                type: string
              active:
                type: boolean
    responses:
      200:
        description: User updated successfully
      403:
        description: Unauthorized access
      404:
        description: User not found
    """
    # ... (function implementation remains the same)
    current_user = User.query.get(get_jwt_identity())
    if not current_user.role == 'Admin' and current_user.id != user_id:
        return jsonify({"message": "Unauthorized"}), 403

    data = request.get_json()
    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404

    if 'first_name' in data:
        user.first_name = data['first_name']
    if 'last_name' in data:
        user.last_name = data['last_name']
    if 'email' in data:
        user.email = data['email']
    if 'active' in data and current_user.role == 'Admin':
        user.active = data['active']

    db.session.commit()
    return jsonify({"message": "User updated successfully"}), 200


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
    # ... (function implementation remains the same)
    current_user = User.query.get(get_jwt_identity())
    if not current_user.role == 'Admin':
        return jsonify({"message": "Unauthorized"}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404

    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted successfully"}), 200


@app.route('/reset-password', methods=['POST'])
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
        description: Password reset instructions sent
      404:
        description: User not found
    """
    # ... (function implementation remains the same)
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if not user:
        return jsonify({"message": "User not found"}), 404
    # Here you would typically send an email with a reset token
    return jsonify({"message": "Password reset instructions sent to email"}), 200


@app.route('/reset-password', methods=['PUT'])
@jwt_required()
def reset_password():
    """
    Reset user password
    ---
    tags:
      - authentication
    security:
      - bearerAuth: []
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
    """
    # ... (function implementation remains the same)
    data = request.get_json()
    current_user = User.query.get(get_jwt_identity())
    current_user.password = generate_password_hash(data['new_password'])
    db.session.commit()
    return jsonify({"message": "Password updated successfully"}), 200


# Create tables within app context
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)