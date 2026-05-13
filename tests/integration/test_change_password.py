import requests
import pytest
from uuid import uuid4


def register_user(base_url: str, user_payload: dict):
    reg_url = f"{base_url}/auth/register"
    return requests.post(reg_url, json=user_payload)


def login_user(base_url: str, username: str, password: str):
    login_url = f"{base_url}/auth/login"
    return requests.post(login_url, json={"username": username, "password": password})


@pytest.fixture
def user_payload():
    uname = f"testuser_{uuid4()}"
    return {
        "first_name": "Test",
        "last_name": "User",
        "email": f"{uname}@example.com",
        "username": uname,
        "password": "Password123!",
        "confirm_password": "Password123!"
    }


def test_change_password_success(fastapi_server: str, user_payload: dict):
    base_url = fastapi_server.rstrip('/')
    # Register
    r = register_user(base_url, user_payload)
    assert r.status_code == 201, r.text

    # Login
    login = login_user(
        base_url, user_payload["username"], user_payload["password"])
    assert login.status_code == 200, login.text
    token = login.json().get("access_token")
    assert token

    # Change password
    change_url = f"{base_url}/auth/change-password"
    headers = {"Authorization": f"Bearer {token}",
               "Content-Type": "application/json"}
    new_password = "NewPass123!"
    resp = requests.post(change_url, json={
                         "old_password": user_payload["password"], "new_password": new_password}, headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json().get("message") == "Password changed successfully"

    # Login with old password should fail
    old_login = login_user(
        base_url, user_payload["username"], user_payload["password"])
    assert old_login.status_code == 401

    # Login with new password should succeed
    new_login = login_user(base_url, user_payload["username"], new_password)
    assert new_login.status_code == 200


def test_change_password_wrong_old(fastapi_server: str, user_payload: dict):
    base_url = fastapi_server.rstrip('/')
    # Register
    r = register_user(base_url, user_payload)
    assert r.status_code == 201, r.text

    # Login
    login = login_user(
        base_url, user_payload["username"], user_payload["password"])
    assert login.status_code == 200, login.text
    token = login.json().get("access_token")
    assert token

    # Attempt change with wrong old password
    change_url = f"{base_url}/auth/change-password"
    headers = {"Authorization": f"Bearer {token}",
               "Content-Type": "application/json"}
    resp = requests.post(change_url, json={
                         "old_password": "incorrect", "new_password": "AnotherPass123"}, headers=headers)
    assert resp.status_code == 400
    assert "Old password is incorrect" in resp.text


def test_change_password_weak_new(fastapi_server: str, user_payload: dict):
    base_url = fastapi_server.rstrip('/')
    # Register
    r = register_user(base_url, user_payload)
    assert r.status_code == 201, r.text

    # Login
    login = login_user(
        base_url, user_payload["username"], user_payload["password"])
    assert login.status_code == 200, login.text
    token = login.json().get("access_token")
    assert token

    # Attempt change with weak new password (no uppercase)
    change_url = f"{base_url}/auth/change-password"
    headers = {"Authorization": f"Bearer {token}",
               "Content-Type": "application/json"}
    weak_password = "weakpass1!"
    resp = requests.post(change_url, json={
                         "old_password": user_payload["password"], "new_password": weak_password}, headers=headers)
    assert resp.status_code == 400
    # Message should mention uppercase requirement
    assert "uppercase" in resp.text.lower() or "uppercase" in (resp.json().get('detail', '').lower()
                                                               if resp.headers.get('content-type', '').startswith('application/json') else '')
