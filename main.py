from typing import Optional, List

import sqlalchemy
from fastapi import FastAPI, HTTPException
import databases
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import and_

from models import User, UserRegister, TokenModel

DATABASE_URL = "sqlite:///./test.db"

database = databases.Database(DATABASE_URL)

metadata = sqlalchemy.MetaData()

users = sqlalchemy.Table(
    "users",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("username", sqlalchemy.String),
    sqlalchemy.Column("password", sqlalchemy.String),
)

tokens = sqlalchemy.Table(
    'tokens',
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("token", sqlalchemy.String),
    sqlalchemy.Column("user", sqlalchemy.ForeignKey('users.id'))
)

engine = sqlalchemy.create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)

metadata.create_all(engine)

app = FastAPI()


@app.on_event("startup")
async def startup():
    await database.connect()


@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()


@app.get("/users", response_model=List[User])
async def get_users():
    query = users.select()
    return await database.fetch_all(query)


@app.post("/register", response_model=User)
async def register(user: UserRegister):
    query = users.insert().values(username=user.username, password=user.password)
    last_record_id = await database.execute(query)
    return {**user.dict(), "id": last_record_id}


@app.post("/login")
async def login(user: UserRegister):
    query = users.select().where(users.c.username == user.username)
    data = await database.fetch_one(query)
    if data is None:
        raise HTTPException(status_code=404, detail="Item not found")
    if user.password != data.password:
        raise HTTPException(status_code=400, detail="Password error")
    delete_user_tokens = tokens.delete().where(tokens.c.user == data.id)
    await database.execute(delete_user_tokens)
    create_new_token = tokens.insert().values(user=data.id, token='1234')
    token_id = await database.execute(create_new_token)
    token = await database.fetch_one(tokens.select().where(tokens.c.id == token_id))
    return {'token': token.token}
