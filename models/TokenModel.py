from pydantic import BaseModel

from models import User


class TokenModel(BaseModel):
    id: int
    user: User
    token: str
