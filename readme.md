
Python Version: Python 3.10.12

## Installation:
1. Clone the repository:

git clone https://github.com/your-repo/user-management-api.git
cd user-management-api

2. Set up the virtual environment:

- python3 -m venv venv

- source venv/bin/activate

- pip install Flask Flask-SQLAlchemy psycopg2-binary Flask-JWT-Extended pyyaml 

- pip install Flask Flask-SQLAlchemy Flask-JWT-Extended Werkzeug Flasgger Flask-Migrate psycopg2-binary


3. Setup

- flask db init
- flask db migrate
- flask db upgrade

4. Run

- python app.py
