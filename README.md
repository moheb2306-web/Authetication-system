# FastAPI JWT Authentication

A REST API with user signup, login, and token-protected routes built with FastAPI.

## Features
- User registration with email and password
- Login using the OAuth2 password flow, returning a JWT access token (30 min expiry)
- Protected route that requires a valid Bearer token
- Passwords hashed with bcrypt
- Input validation with Pydantic
- SQLite database via SQLAlchemy
- Interactive API docs (Swagger UI) at `/docs`

## Tech Stack
Python, FastAPI, SQLAlchemy, SQLite, PyJWT, bcrypt, Pydantic, Uvicorn

## Setup

```bash
# 1. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Set a secret key (use a long random value in production)
export SECRET_KEY=$(openssl rand -hex 32)   # Windows PowerShell: $env:SECRET_KEY="your-secret"

# 4. Run the server
uvicorn main:app --reload
```

Open http://127.0.0.1:8000/docs to try the API.

## Endpoints

| Method | Path      | Auth | Description                          |
|--------|-----------|------|--------------------------------------|
| POST   | `/signup` | No   | Create a new user                    |
| POST   | `/login`  | No   | Get a JWT (use email as `username`)  |
| GET    | `/me`     | Yes  | Get the current user's profile       |

## Example (curl)

```bash
# Sign up
curl -X POST http://127.0.0.1:8000/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password123","full_name":"Test User"}'

# Log in
curl -X POST http://127.0.0.1:8000/login \
  -d "username=user@example.com&password=password123"

# Call a protected route
curl http://127.0.0.1:8000/me -H "Authorization: Bearer <your_token>"
```

## Project Structure
```
fastapi-auth/
├── main.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Possible Improvements
- Refresh tokens
- Google / GitHub OAuth2 login
- PostgreSQL instead of SQLite
- Rate limiting and email verification
