from pydantic import BaseModel
from typing import Optional

class User(BaseModel):
    username: str
    hashed_password: str

# Token model
class Token(BaseModel):
    access_token: str
    token_type: str

# Token data model
class TokenData(BaseModel):
    username: Optional[str] = None