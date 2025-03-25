from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from models import User
from settings import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES

def get_pwd_context():
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    return pwd_context


def get_hashed_password(adminpassword):
    pwd_context = get_pwd_context()
    hashed_password = pwd_context.hash(adminpassword)
    return hashed_password


# Verify password
def verify_password(plain_password, hashed_password):
    pwd_context = get_pwd_context()
    hashed_password = get_hashed_password()
    pwd_context.verify("adminpassword", hashed_password)
    return pwd_context.verify(plain_password, hashed_password)

# Get user from database
def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return User(**user_dict)

# Authenticate user
def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

# Create access token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
    