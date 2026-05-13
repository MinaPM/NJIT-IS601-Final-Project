import asyncio
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

import app.main as main_module
from app.auth import jwt as auth_jwt
from app.auth import redis as auth_redis
from app.auth.dependencies import get_current_user, get_current_active_user
import app.database as database_module
import app.database_init as database_init_module
from app.models import calculation as calculation_model
from app.models.user import User
from app.schemas.base import PasswordMixin
from app.schemas.calculation import CalculationBase, CalculationUpdate, CalculationType
from app.schemas.token import TokenType, Token, TokenData, TokenResponse
from app.schemas.user import UserCreate, UserResponse, UserUpdate, PasswordUpdate


class FakeQuery:
    def __init__(self, result):
        self.result = result

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self.result

    def all(self):
        return self.result


class FakeDB:
    def __init__(self, results_by_model=None):
        self.results_by_model = {
            model: list(results) for model, results in (results_by_model or {}).items()
        }
        self.committed = False
        self.rolled_back = False
        self.deleted = None
        self.added = None

    def query(self, model):
        results = self.results_by_model.get(model, [])
        result = results.pop(0) if results else None
        return FakeQuery(result)

    def add(self, obj):
        self.added = obj

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def refresh(self, obj):
        self.refreshed = obj

    def delete(self, obj):
        self.deleted = obj

    def flush(self):
        self.flushed = True


class DummyCalculation:
    def __init__(self, result=0.0):
        self.id = uuid4()
        self.user_id = uuid4()
        self.inputs = [1.0, 2.0]
        self.result = result
        self.updated_at = datetime.now(timezone.utc)

    def get_result(self):
        return sum(self.inputs)


class DummyCalculationCreate:
    def __init__(self, type_, inputs):
        self.type = type_
        self.inputs = inputs


class DummyCalculationUpdate:
    def __init__(self, inputs=None):
        self.inputs = inputs


def make_user(username="user1", email="user1@example.com", password="Password123!"):
    return User(
        id=uuid4(),
        first_name="Test",
        last_name="User",
        email=email,
        username=username,
        password=User.hash_password(password),
        is_active=True,
        is_verified=False,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


def test_main_template_routes_and_health(monkeypatch):
    rendered = {}

    def fake_template_response(**kwargs):
        rendered.update(kwargs)
        return kwargs

    monkeypatch.setattr(main_module.templates,
                        "TemplateResponse", fake_template_response)

    request = object()
    assert main_module.read_index(request=request)["name"] == "index.html"
    assert main_module.login_page(request=request)["name"] == "login.html"
    assert main_module.register_page(request=request)[
        "name"] == "register.html"
    assert main_module.profile_page(request=request)[
        "name"] == "user_info.html"
    assert main_module.dashboard_page(request=request)[
        "name"] == "dashboard.html"
    assert main_module.view_calculation_page(request=request, calc_id="123")[
        "context"]["calc_id"] == "123"
    assert main_module.edit_calculation_page(request=request, calc_id="456")[
        "context"]["calc_id"] == "456"
    assert main_module.read_health() == {"status": "ok"}
    assert rendered["name"] == "edit_calculation.html"


def test_register_endpoint_success_and_failure(monkeypatch):
    user_create = UserCreate(
        first_name="Test",
        last_name="User",
        email="test@example.com",
        username="testuser",
        password="Password123!",
        confirm_password="Password123!",
    )
    db = FakeDB()
    created_user = make_user()

    def fake_register(db_session, user_data):
        assert "confirm_password" not in user_data
        return created_user

    monkeypatch.setattr(main_module.User, "register", fake_register)
    response = main_module.register(user_create=user_create, db=db)
    assert response is created_user
    assert db.committed is True
    assert db.refreshed is created_user

    def raising_register(db_session, user_data):
        raise ValueError("Username or email already exists")

    monkeypatch.setattr(main_module.User, "register", raising_register)
    with pytest.raises(HTTPException) as excinfo:
        main_module.register(user_create=user_create, db=FakeDB())
    assert excinfo.value.status_code == 400


def test_login_endpoints(monkeypatch):
    user = make_user()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)
    auth_result = {
        "access_token": "access-token",
        "refresh_token": "refresh-token",
        "token_type": "bearer",
        "expires_at": expires_at.replace(tzinfo=None),
        "user": user,
    }

    monkeypatch.setattr(main_module.User, "authenticate",
                        lambda db_session, username, password: auth_result)
    response = main_module.login_json(user_login=SimpleNamespace(
        username="user", password="Password123!"), db=FakeDB())
    assert response.access_token == "access-token"
    assert response.refresh_token == "refresh-token"
    assert response.username == user.username
    assert response.expires_at.tzinfo is not None

    monkeypatch.setattr(main_module.User, "authenticate",
                        lambda db_session, username, password: None)
    with pytest.raises(HTTPException) as excinfo:
        main_module.login_json(user_login=SimpleNamespace(
            username="bad", password="bad"), db=FakeDB())
    assert excinfo.value.status_code == 401

    monkeypatch.setattr(main_module.User, "authenticate",
                        lambda db_session, username, password: auth_result)
    token_response = main_module.login_form(
        form_data=SimpleNamespace(username="user", password="Password123!"),
        db=FakeDB(),
    )
    assert token_response == {
        "access_token": "access-token", "token_type": "bearer"}


def test_change_password_endpoint(monkeypatch):
    current_user = make_user()
    db = FakeDB({User: [current_user]})

    payload = main_module.ChangePasswordRequest(
        old_password="Password123!", new_password="NewPass123!")
    response = main_module.change_password(
        payload=payload, db=db, current_user=current_user)
    assert response == {"message": "Password changed successfully"}
    assert db.committed is True

    db_not_found = FakeDB({User: [None]})
    with pytest.raises(HTTPException) as excinfo:
        main_module.change_password(
            payload=payload, db=db_not_found, current_user=current_user)
    assert excinfo.value.status_code == 404

    db_wrong = FakeDB({User: [make_user()]})
    with pytest.raises(HTTPException) as excinfo:
        main_module.change_password(
            payload=main_module.ChangePasswordRequest(
                old_password="wrong", new_password="NewPass123!"),
            db=db_wrong,
            current_user=current_user,
        )
    assert excinfo.value.status_code == 400

    with pytest.raises(HTTPException) as excinfo:
        main_module.change_password(
            payload=main_module.ChangePasswordRequest(
                old_password="Password123!", new_password="weakpass1"),
            db=FakeDB({User: [make_user()]}),
            current_user=current_user,
        )
    assert excinfo.value.status_code == 400


def test_profile_update_endpoint(monkeypatch):
    current_user = make_user(username="current", email="current@example.com")
    updated_user = make_user(username="updated", email="updated@example.com")
    db = FakeDB({User: [current_user, None, None]})

    payload = UserUpdate(
        username="updated",
        email="updated@example.com",
        first_name="New",
        last_name="Name",
    )
    monkeypatch.setattr(main_module.User, "__eq__",
                        lambda self, other: False, raising=False)
    monkeypatch.setattr(main_module.User, "username",
                        main_module.User.username, raising=False)
    response = main_module.update_profile(
        payload=payload, db=db, current_user=current_user)
    assert response.username == "updated"
    assert response.email == "updated@example.com"

    with pytest.raises(HTTPException) as excinfo:
        main_module.update_profile(
            payload=UserUpdate(username="abc"),
            db=FakeDB({User: [None]}),
            current_user=current_user,
        )
    assert excinfo.value.status_code == 404


def test_calculation_endpoints(monkeypatch):
    current_user = make_user(username="calcuser", email="calc@example.com")
    calc = DummyCalculation(result=3.0)
    db = FakeDB({main_module.Calculation: [calc]})

    monkeypatch.setattr(main_module.Calculation, "create",
                        lambda calculation_type, user_id, inputs: calc)
    create_response = main_module.create_calculation(
        calculation_data=SimpleNamespace(type="addition", inputs=[1, 2]),
        current_user=current_user,
        db=FakeDB(),
    )
    assert create_response is calc

    monkeypatch.setattr(main_module.Calculation, "create", lambda *args,
                        **kwargs: (_ for _ in ()).throw(ValueError("bad calc")))
    with pytest.raises(HTTPException) as excinfo:
        main_module.create_calculation(
            calculation_data=SimpleNamespace(type="addition", inputs=[1, 2]),
            current_user=current_user,
            db=FakeDB(),
        )
    assert excinfo.value.status_code == 400

    monkeypatch.setattr(main_module.Calculation, "create",
                        lambda calculation_type, user_id, inputs: calc)
    list_response = main_module.list_calculations(
        current_user=current_user, db=FakeDB({main_module.Calculation: [[calc]]}))
    assert list_response == [calc]

    assert main_module.get_calculation(calc_id=str(
        uuid4()), current_user=current_user, db=FakeDB({main_module.Calculation: [calc]})) is calc

    with pytest.raises(HTTPException) as excinfo:
        main_module.get_calculation(
            calc_id="bad-id", current_user=current_user, db=FakeDB())
    assert excinfo.value.status_code == 400

    with pytest.raises(HTTPException) as excinfo:
        main_module.get_calculation(calc_id=str(
            uuid4()), current_user=current_user, db=FakeDB({main_module.Calculation: [None]}))
    assert excinfo.value.status_code == 404

    update_payload = SimpleNamespace(inputs=[5, 6])
    updated = main_module.update_calculation(calc_id=str(
        uuid4()), calculation_update=update_payload, current_user=current_user, db=FakeDB({main_module.Calculation: [calc]}))
    assert updated.inputs == [5, 6]
    assert updated.result == sum(updated.inputs)

    with pytest.raises(HTTPException) as excinfo:
        main_module.update_calculation(
            calc_id="bad-id", calculation_update=update_payload, current_user=current_user, db=FakeDB())
    assert excinfo.value.status_code == 400

    with pytest.raises(HTTPException) as excinfo:
        main_module.update_calculation(calc_id=str(uuid4()), calculation_update=update_payload,
                                       current_user=current_user, db=FakeDB({main_module.Calculation: [None]}))
    assert excinfo.value.status_code == 404

    deleted_db = FakeDB({main_module.Calculation: [calc]})
    assert main_module.delete_calculation(calc_id=str(
        uuid4()), current_user=current_user, db=deleted_db) is None
    assert deleted_db.deleted is calc

    with pytest.raises(HTTPException) as excinfo:
        main_module.delete_calculation(
            calc_id="bad-id", current_user=current_user, db=FakeDB())
    assert excinfo.value.status_code == 400

    with pytest.raises(HTTPException) as excinfo:
        main_module.delete_calculation(calc_id=str(
            uuid4()), current_user=current_user, db=FakeDB({main_module.Calculation: [None]}))
    assert excinfo.value.status_code == 404


def test_current_user_dependencies(monkeypatch):
    user = make_user()
    user_response = UserResponse.model_validate(user)
    monkeypatch.setattr(main_module.User, "verify_token", lambda token: {"username": user_response.username, "email": user_response.email, "first_name": user_response.first_name,
                        "last_name": user_response.last_name, "is_active": True, "is_verified": True, "id": user_response.id, "created_at": user_response.created_at, "updated_at": user_response.updated_at})
    result = get_current_user(token="token", db=FakeDB())
    assert result.username == user.username

    monkeypatch.setattr(main_module.User, "verify_token", lambda token: {"username": user_response.username, "email": user_response.email, "first_name": user_response.first_name,
                        "last_name": user_response.last_name, "is_active": True, "is_verified": True, "id": user_response.id, "created_at": user_response.created_at, "updated_at": user_response.updated_at})
    result = get_current_user(token="token", db=FakeDB())
    assert result.username == user.username

    monkeypatch.setattr(main_module.User, "verify_token", lambda token: None)
    with pytest.raises(HTTPException):
        get_current_user(token="bad", db=FakeDB())

    monkeypatch.setattr(main_module.User, "verify_token",
                        lambda token: {"sub": str(user.id)})
    db = FakeDB({User: [user]})
    result = get_current_user(token="token", db=db)
    assert result.username == user.username

    monkeypatch.setattr(main_module.User, "verify_token",
                        lambda token: user.id)
    result = get_current_user(token="token", db=FakeDB({User: [user]}))
    assert result.username == user.username

    with pytest.raises(HTTPException) as excinfo:
        get_current_active_user(current_user=UserResponse.model_validate(
            {**user_response.model_dump(), "is_active": False}))
    assert excinfo.value.status_code == 400


def test_auth_jwt_helpers(monkeypatch):
    hashed = auth_jwt.get_password_hash("Password123!")
    assert auth_jwt.verify_password("Password123!", hashed)

    access = auth_jwt.create_token(str(uuid4()), TokenType.ACCESS)
    refresh = auth_jwt.create_token(uuid4(), TokenType.REFRESH)
    assert isinstance(access, str)
    assert isinstance(refresh, str)

    monkeypatch.setattr(auth_jwt.jwt, "encode",
                        lambda *args, **kwargs: "encoded-token")
    assert auth_jwt.create_token("123", TokenType.ACCESS) == "encoded-token"

    def raising_encode(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(auth_jwt.jwt, "encode", raising_encode)
    with pytest.raises(HTTPException):
        auth_jwt.create_token("123", TokenType.ACCESS)

    payload = {"sub": str(uuid4()),
               "type": TokenType.ACCESS.value, "jti": "abc"}
    monkeypatch.setattr(auth_jwt.jwt, "decode", lambda token,
                        secret, algorithms, options=None: payload)
    monkeypatch.setattr(auth_jwt, "is_blacklisted",
                        lambda jti: asyncio.sleep(0, result=False))
    decoded = asyncio.run(auth_jwt.decode_token("token", TokenType.ACCESS))
    assert decoded["sub"] == payload["sub"]

    monkeypatch.setattr(auth_jwt.jwt, "decode", lambda token, secret, algorithms, options=None: {
                        "sub": payload["sub"], "type": TokenType.REFRESH.value, "jti": "abc"})
    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(auth_jwt.decode_token("token", TokenType.ACCESS))
    assert excinfo.value.status_code == 401

    async def blacklisted(_):
        return True

    monkeypatch.setattr(auth_jwt.jwt, "decode", lambda token,
                        secret, algorithms, options=None: payload)
    monkeypatch.setattr(auth_jwt, "is_blacklisted", blacklisted)
    with pytest.raises(HTTPException):
        asyncio.run(auth_jwt.decode_token("token", TokenType.ACCESS))

    class ExpiredError(Exception):
        pass

    monkeypatch.setattr(auth_jwt.jwt, "decode", lambda *args, **
                        kwargs: (_ for _ in ()).throw(auth_jwt.jwt.ExpiredSignatureError()))
    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(auth_jwt.decode_token("token", TokenType.ACCESS))
    assert excinfo.value.status_code == 401

    monkeypatch.setattr(auth_jwt.jwt, "decode", lambda *args,
                        **kwargs: (_ for _ in ()).throw(auth_jwt.JWTError("bad")))
    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(auth_jwt.decode_token("token", TokenType.ACCESS))
    assert excinfo.value.status_code == 401


def test_schemas_and_model_helpers():
    with pytest.raises(ValidationError):
        UserCreate(
            first_name="Test",
            last_name="User",
            email="test@example.com",
            username="testuser",
            password="Password123!",
            confirm_password="Mismatch123!",
        )

    with pytest.raises(ValidationError):
        UserCreate(
            first_name="Test",
            last_name="User",
            email="test@example.com",
            username="testuser",
            password="weakpass1!",
            confirm_password="weakpass1!",
        )

    with pytest.raises(ValidationError):
        UserUpdate(username="ab")

    with pytest.raises(ValidationError):
        PasswordUpdate(current_password="Password123!",
                       new_password="Password123!", confirm_new_password="Password123!")

    password_update = PasswordUpdate(
        current_password="Password123!",
        new_password="NewPass123!",
        confirm_new_password="NewPass123!",
    )
    assert password_update.new_password == "NewPass123!"

    token = Token(
        access_token="a",
        refresh_token="r",
        expires_at=datetime.now(timezone.utc),
    )
    assert token.token_type == "bearer"

    token_data = TokenData(
        user_id=uuid4(),
        exp=datetime.now(timezone.utc),
        jti="abc",
        token_type=TokenType.ACCESS,
    )
    assert token_data.token_type == TokenType.ACCESS

    token_response = TokenResponse(
        access_token="a",
        refresh_token="r",
        expires_at=datetime.now(timezone.utc),
        user_id=uuid4(),
        username="u",
        email="u@example.com",
        first_name="U",
        last_name="User",
        is_active=True,
        is_verified=False,
    )
    assert token_response.username == "u"

    base = CalculationBase(type=CalculationType.ADDITION, inputs=[1, 2])
    assert base.type == CalculationType.ADDITION
    with pytest.raises(ValidationError):
        CalculationBase(type="addition", inputs=[1])

    update = CalculationUpdate(inputs=[1, 2])
    assert update.inputs == [1, 2]
    with pytest.raises(ValidationError):
        CalculationUpdate(inputs=[1])

    user = make_user()
    user.update(first_name="Updated")
    assert user.first_name == "Updated"
    assert user.hashed_password == user.password
    assert user.verify_password("Password123!")

    copied_user = User(hashed_password=User.hash_password(
        "Password123!"), first_name="A", last_name="B", email="copy@example.com", username="copy")
    assert copied_user.verify_password("Password123!")

    registered = User.register(FakeDB(), {
        "first_name": "Reg",
        "last_name": "User",
        "email": "reg@example.com",
        "username": "reguser",
        "password": "Password123!",
    })
    assert registered.username == "reguser"

    with pytest.raises(ValueError):
        User.register(FakeDB(), {
            "first_name": "Reg",
            "last_name": "User",
            "email": "reg2@example.com",
            "username": "reguser2",
            "password": "short",
        })

    auth_db = FakeDB({User: [user]})
    auth_result = User.authenticate(auth_db, user.username, "Password123!")
    assert auth_result is not None
    assert User.authenticate(
        FakeDB({User: [None]}), "missing", "Password123!") is None


def test_calculation_model_helpers():
    user_id = uuid4()

    addition = calculation_model.Calculation.create(
        "addition", user_id=user_id, inputs=[1, 2, 3])
    subtraction = calculation_model.Calculation.create(
        "subtraction", user_id=user_id, inputs=[10, 3, 2])
    multiplication = calculation_model.Calculation.create(
        "multiplication", user_id=user_id, inputs=[2, 3, 4])
    division = calculation_model.Calculation.create(
        "division", user_id=user_id, inputs=[100, 2, 5])

    assert addition.get_result() == 6
    assert subtraction.get_result() == 5
    assert multiplication.get_result() == 24
    assert division.get_result() == 10
    assert "Calculation(type=" in repr(addition)

    with pytest.raises(ValueError):
        calculation_model.Calculation.create(
            "unknown", user_id=user_id, inputs=[1, 2])

    with pytest.raises(ValueError):
        calculation_model.Addition(
            user_id=user_id, inputs="not-a-list").get_result()
    with pytest.raises(ValueError):
        calculation_model.Subtraction(user_id=user_id, inputs=[1]).get_result()
    with pytest.raises(ValueError):
        calculation_model.Multiplication(
            user_id=user_id, inputs=[1]).get_result()
    with pytest.raises(ValueError):
        calculation_model.Division(user_id=user_id, inputs=[1, 0]).get_result()


def test_database_and_redis_helpers(monkeypatch):
    class FakeSession:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    session = FakeSession()
    monkeypatch.setattr(database_module, "SessionLocal", lambda: session)
    generator = database_module.get_db()
    assert next(generator) is session
    with pytest.raises(StopIteration):
        next(generator)
    assert session.closed is True

    engine = database_module.get_engine("sqlite:///:memory:")
    sessionmaker = database_module.get_sessionmaker(engine)
    assert sessionmaker is not None

    calls = {"create_all": 0, "drop_all": 0}
    monkeypatch.setattr(database_init_module.Base.metadata, "create_all",
                        lambda bind=None: calls.__setitem__("create_all", calls["create_all"] + 1))
    monkeypatch.setattr(database_init_module.Base.metadata, "drop_all",
                        lambda bind=None: calls.__setitem__("drop_all", calls["drop_all"] + 1))
    database_init_module.init_db()
    database_init_module.drop_db()
    assert calls == {"create_all": 1, "drop_all": 1}

    class FakeRedis:
        def __init__(self):
            self.values = {}

        async def set(self, key, value, ex=None):
            self.values[key] = (value, ex)

        async def exists(self, key):
            return 1 if key in self.values else 0

    fake_redis = FakeRedis()

    async def fake_get_redis():
        return fake_redis

    monkeypatch.setattr(auth_redis, "get_redis", fake_get_redis)

    async def run():
        await auth_redis.add_to_blacklist("jti123", 60)
        assert await auth_redis.is_blacklisted("jti123") == 1
        assert await auth_redis.is_blacklisted("other") == 0

    asyncio.run(run())


def test_user_verify_token_branches():
    user = make_user()
    valid_token = User.create_access_token({"sub": str(user.id)})
    assert User.verify_token(valid_token) == user.id

    missing_sub_token = auth_jwt.jwt.encode(
        {"foo": "bar"},
        auth_jwt.settings.JWT_SECRET_KEY,
        algorithm=auth_jwt.settings.ALGORITHM,
    )
    assert User.verify_token(missing_sub_token) is None

    assert User.verify_token("not-a-token") is None
