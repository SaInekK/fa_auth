import hashlib
import hmac
import base64
from typing import Optional
import json

from fastapi import FastAPI, Form, Cookie, Body
from fastapi.responses import Response

app = FastAPI()

SECRET_KEY = 'fed06f86df08b787129bba5ed14e7f720c2af8af8130d97798b91611dc1deb4a'
PASSWORD_SALT = '535e344fcddcb3a676ef09cf7b389c120812c9f0033a5fcd970373c0c113f98b'


def sign_data(data: str) -> str:
    """Returns signed data"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()


users = {  # DB-like dict
    'alex@gmail.com': {
        'name': 'Alex',
        'password': 'bacce629467dda155abb183bec1da00f15cf63e0c546bc03800785f19b7fa4d0',
        'balance': 100000
    },
    'peter@gmail.com': {
        'name': 'Peter',
        'password': '125bb0d02fb255940c53f758e0af6afa6f5951fdc03e78645fd3a7519e8b5830',
        'balance': 120000
    }
}


def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split('.')
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username


def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[username]['password'].lower()
    return stored_password_hash == password_hash


@app.get('/')
def index(username: Optional[str] = Cookie(default=None)):
    with open('templates/login.html', 'r') as template:
        login_template = template.read()
    if not username:
        return Response(login_template, media_type='text/html')
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_template, media_type='text/html')
        response.delete_cookie(key='username')
        return response

    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_template, media_type='text/html')
        response.delete_cookie(key='username')
        return response
    return Response(f'Hi, {users[valid_username]["name"]}!<br>'
                    f'Balance: {users[valid_username]["balance"]}', media_type='text/html')


@app.post('/login')
def login_page(data: dict = Body(...)):  # (username: str = Form(...), password: str = Form(...)):
    username = data['username']
    password = data['password']
    print(username, password)
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(json.dumps({
            "success": False,
            "message": "Who are you?"
        }),
            media_type='application/json')

    response = Response(
        json.dumps({
            "success": True,
            "message": f"Hello, {user['name']}!<br>Balance: {user['balance']}",
        }),
        media_type='application/json')
    signed_username = f'{base64.b64encode(username.encode()).decode()}' \
                      f'.{sign_data(username)}'
    response.set_cookie(key='username', value=signed_username)
    return response
