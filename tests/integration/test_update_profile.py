import requests
import pytest
from uuid import uuid4


def register_user(base_url: str, user_payload: dict):
    return requests.post(f"{base_url}/auth/register", json=user_payload)


def login_user(base_url: str, username: str, password: str):
    return requests.post(f"{base_url}/auth/login", json={"username": username, "password": password})


def update_profile(base_url: str, token: str | None, payload: dict):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return requests.post(f"{base_url}/auth/update-profile", json=payload, headers=headers)


def make_user_payload():
    uname = f"profile_{uuid4()}"
    return {
        "first_name": "Profile",
        "last_name": "User",
        "email": f"{uname}@example.com",
        "username": uname,
        "password": "Password123!",
        "confirm_password": "Password123!"
    }


def test_update_profile_success(fastapi_server: str):
    base_url = fastapi_server.rstrip('/')
    user = make_user_payload()

    # Register and login
    r = register_user(base_url, user)
    assert r.status_code == 201, r.text

    login = login_user(base_url, user['username'], user['password'])
    assert login.status_code == 200, login.text
    token = login.json().get('access_token')
    assert token

    # Update profile
    new_username = f"{user['username']}_new"
    new_email = f"{user['username']}_new@example.com"
    payload = {"username": new_username, "email": new_email,
               "first_name": "Updated", "last_name": "Name"}

    resp = requests.post(f"{base_url}/auth/update-profile", json=payload, headers={
                         "Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data['username'] == new_username
    assert data['email'] == new_email
    assert data['first_name'] == 'Updated'
    assert data['last_name'] == 'Name'

    # Ensure can login with new username
    new_login = login_user(base_url, new_username, user['password'])
    assert new_login.status_code == 200, new_login.text


def test_update_profile_duplicate_username_and_email(fastapi_server: str):
    base_url = fastapi_server.rstrip('/')
    user1 = make_user_payload()
    user2 = make_user_payload()

    r1 = register_user(base_url, user1)
    r2 = register_user(base_url, user2)
    assert r1.status_code == 201 and r2.status_code == 201

    # Login as user1
    login = login_user(base_url, user1['username'], user1['password'])
    assert login.status_code == 200
    token = login.json().get('access_token')

    # Attempt to change username to user2's username
    resp = requests.post(f"{base_url}/auth/update-profile", json={"username": user2['username']}, headers={
                         "Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    assert resp.status_code == 400
    assert 'Username already taken' in resp.text or 'Username or email already exists' in resp.text

    # Attempt to change email to user2's email
    resp2 = requests.post(f"{base_url}/auth/update-profile", json={"email": user2['email']}, headers={
                          "Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    assert resp2.status_code == 400
    assert 'Email already in use' in resp2.text or 'Username or email already exists' in resp2.text


def test_update_profile_invalid_email(fastapi_server: str):
    base_url = fastapi_server.rstrip('/')
    user = make_user_payload()
    r = register_user(base_url, user)
    assert r.status_code == 201

    login = login_user(base_url, user['username'], user['password'])
    assert login.status_code == 200
    token = login.json().get('access_token')

    # Attempt invalid email format
    resp = requests.post(f"{base_url}/auth/update-profile", json={"email": "not-an-email"},
                         headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    assert resp.status_code == 422


def test_update_profile_short_username(fastapi_server: str):
    base_url = fastapi_server.rstrip('/')
    user = make_user_payload()
    r = register_user(base_url, user)
    assert r.status_code == 201

    login = login_user(base_url, user['username'], user['password'])
    assert login.status_code == 200
    token = login.json().get('access_token')

    resp = update_profile(base_url, token, {"username": "ab"})
    assert resp.status_code == 422


def test_update_profile_blank_username_and_email(fastapi_server: str):
    base_url = fastapi_server.rstrip('/')
    user = make_user_payload()
    r = register_user(base_url, user)
    assert r.status_code == 201

    login = login_user(base_url, user['username'], user['password'])
    assert login.status_code == 200
    token = login.json().get('access_token')

    blank_username = update_profile(base_url, token, {"username": ""})
    assert blank_username.status_code == 422

    blank_email = update_profile(base_url, token, {"email": ""})
    assert blank_email.status_code == 422


def test_update_profile_missing_token(fastapi_server: str):
    base_url = fastapi_server.rstrip('/')
    user = make_user_payload()
    r = register_user(base_url, user)
    assert r.status_code == 201

    resp = update_profile(
        base_url, None, {"username": f"{user['username']}_new"})
    assert resp.status_code == 401
