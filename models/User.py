from pydantic import BaseModel


class UserRegister(BaseModel):
    username: str
    password: str


class User(BaseModel):
    id: int
    username: str
    password: str
