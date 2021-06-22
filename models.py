from typing import Optional

from pydantic import BaseModel


class UserRegister(BaseModel):
    username: str
    hashed_password: str


class User(BaseModel):
    id: int
    username: str
    hashed_password: str


class UserDetail(BaseModel):
    id: int
    username: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None
