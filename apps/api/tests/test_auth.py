"""Authentication, authorization, and token lifecycle."""

from __future__ import annotations

import datetime as dt

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from sentinelforge.core.config import get_settings
from sentinelforge.core.security import (
    TokenError,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from sentinelforge.models import User, UserRole
from sentinelforge.services.auth import (
    AccountLockedError,
    AuthError,
    authenticate,
    create_user,
)
from tests.conftest import TEST_PASSWORD


class TestPasswordHashing:
    def test_roundtrip(self) -> None:
        hashed = hash_password("a-perfectly-fine-password")
        assert verify_password("a-perfectly-fine-password", hashed)
        assert not verify_password("not-the-password", hashed)

    def test_hash_is_salted(self) -> None:
        assert hash_password("same") != hash_password("same")

    def test_long_password_not_truncated(self) -> None:
        """bcrypt truncates at 72 bytes; the SHA-256 pre-hash is what prevents that.

        Without pre-hashing, these two 100-character passwords sharing a 72-byte prefix
        would verify against each other's hash.
        """
        shared_prefix = "x" * 72
        first = shared_prefix + "AAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        second = shared_prefix + "BBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        hashed = hash_password(first)
        assert verify_password(first, hashed)
        assert not verify_password(second, hashed)

    def test_null_byte_password_not_truncated(self) -> None:
        hashed = hash_password("prefix\x00suffix-one")
        assert not verify_password("prefix\x00suffix-two", hashed)

    def test_malformed_hash_returns_false(self) -> None:
        assert not verify_password("anything", "not-a-bcrypt-hash")


class TestAuthenticateService:
    def test_unknown_user_and_wrong_password_are_indistinguishable(self, db: Session) -> None:
        create_user(db, email="known@test.local", password=TEST_PASSWORD)
        db.commit()

        with pytest.raises(AuthError) as unknown:
            authenticate(db, email="nobody@test.local", password=TEST_PASSWORD)
        with pytest.raises(AuthError) as wrong:
            authenticate(db, email="known@test.local", password="wrong-password-here")

        assert str(unknown.value) == str(wrong.value)

    def test_email_is_normalised(self, db: Session) -> None:
        create_user(db, email="Mixed.Case@Test.Local", password=TEST_PASSWORD)
        db.commit()
        user = authenticate(db, email="  mixed.case@test.local  ", password=TEST_PASSWORD)
        assert user.email == "mixed.case@test.local"

    def test_duplicate_email_rejected(self, db: Session) -> None:
        create_user(db, email="dup@test.local", password=TEST_PASSWORD)
        db.commit()
        with pytest.raises(AuthError):
            create_user(db, email="dup@test.local", password=TEST_PASSWORD)

    def test_lockout_after_threshold(self, db: Session) -> None:
        settings = get_settings()
        create_user(db, email="lock@test.local", password=TEST_PASSWORD)
        db.commit()

        for _ in range(settings.account_lockout_threshold):
            with pytest.raises(AuthError):
                authenticate(db, email="lock@test.local", password="wrong")

        # Correct credentials are now refused too — that is the point of a lockout.
        with pytest.raises(AccountLockedError):
            authenticate(db, email="lock@test.local", password=TEST_PASSWORD)

    def test_successful_login_clears_failure_counter(self, db: Session) -> None:
        create_user(db, email="reset@test.local", password=TEST_PASSWORD)
        db.commit()
        with pytest.raises(AuthError):
            authenticate(db, email="reset@test.local", password="wrong")
        user = authenticate(db, email="reset@test.local", password=TEST_PASSWORD)
        assert user.failed_login_count == 0
        assert user.last_login_at is not None

    def test_inactive_user_cannot_authenticate(self, db: Session) -> None:
        create_user(db, email="off@test.local", password=TEST_PASSWORD, is_active=False)
        db.commit()
        with pytest.raises(AuthError):
            authenticate(db, email="off@test.local", password=TEST_PASSWORD)


class TestTokens:
    def test_refresh_token_rejected_as_access_token(self) -> None:
        """Type confusion here would hand out a long-lived credential as a short one."""
        import uuid

        token, _jti, _exp = create_refresh_token(subject=uuid.uuid4())
        with pytest.raises(TokenError):
            decode_token(token, expected_type="access")

    def test_tampered_token_rejected(self) -> None:
        import uuid

        token, _jti, _exp = create_refresh_token(subject=uuid.uuid4())
        head, payload, signature = token.split(".")
        tampered = f"{head}.{payload}.{signature[:-4]}AAAA"
        with pytest.raises(TokenError):
            decode_token(tampered, expected_type="refresh")


class TestAuthEndpoints:
    def test_login_returns_tokens(self, client: TestClient, admin_user: User, api: str) -> None:
        response = client.post(
            f"{api}/auth/login", json={"email": admin_user.email, "password": TEST_PASSWORD}
        )
        assert response.status_code == 200
        body = response.json()
        assert body["token_type"] == "bearer"
        assert body["access_token"] and body["refresh_token"]

    def test_login_with_bad_password_is_401(
        self, client: TestClient, admin_user: User, api: str
    ) -> None:
        response = client.post(
            f"{api}/auth/login", json={"email": admin_user.email, "password": "nope"}
        )
        assert response.status_code == 401

    def test_me_requires_authentication(self, client: TestClient, api: str) -> None:
        assert client.get(f"{api}/auth/me").status_code == 401

    def test_me_returns_profile(
        self, client: TestClient, admin_headers: dict[str, str], api: str
    ) -> None:
        response = client.get(f"{api}/auth/me", headers=admin_headers)
        assert response.status_code == 200
        assert response.json()["role"] == UserRole.ADMIN.value
        assert "hashed_password" not in response.json()

    def test_refresh_rotates_and_invalidates_old_token(
        self, client: TestClient, admin_user: User, api: str
    ) -> None:
        login = client.post(
            f"{api}/auth/login", json={"email": admin_user.email, "password": TEST_PASSWORD}
        ).json()

        first = client.post(f"{api}/auth/refresh", json={"refresh_token": login["refresh_token"]})
        assert first.status_code == 200

        replay = client.post(f"{api}/auth/refresh", json={"refresh_token": login["refresh_token"]})
        assert replay.status_code == 401, "a rotated refresh token must not be reusable"

    def test_logout_revokes_refresh_token(
        self, client: TestClient, admin_user: User, api: str
    ) -> None:
        login = client.post(
            f"{api}/auth/login", json={"email": admin_user.email, "password": TEST_PASSWORD}
        ).json()
        headers = {"Authorization": f"Bearer {login['access_token']}"}

        assert (
            client.post(
                f"{api}/auth/logout",
                json={"refresh_token": login["refresh_token"]},
                headers=headers,
            ).status_code
            == 200
        )
        assert (
            client.post(
                f"{api}/auth/refresh", json={"refresh_token": login["refresh_token"]}
            ).status_code
            == 401
        )

    def test_rate_limit_triggers_429(self, client: TestClient, admin_user: User, api: str) -> None:
        settings = get_settings()
        for _ in range(settings.login_rate_limit_attempts):
            client.post(f"{api}/auth/login", json={"email": admin_user.email, "password": "bad"})
        response = client.post(
            f"{api}/auth/login", json={"email": admin_user.email, "password": TEST_PASSWORD}
        )
        assert response.status_code == 429
        assert "Retry-After" in response.headers


class TestAuthorization:
    def test_analyst_cannot_list_users(
        self, client: TestClient, analyst_headers: dict[str, str], api: str
    ) -> None:
        assert client.get(f"{api}/users", headers=analyst_headers).status_code == 403

    def test_admin_can_list_users(
        self, client: TestClient, admin_headers: dict[str, str], api: str
    ) -> None:
        assert client.get(f"{api}/users", headers=admin_headers).status_code == 200

    def test_admin_can_create_user(
        self, client: TestClient, admin_headers: dict[str, str], api: str, unique_email: str
    ) -> None:
        response = client.post(
            f"{api}/users",
            headers=admin_headers,
            json={"email": unique_email, "password": "another-long-passphrase", "role": "analyst"},
        )
        assert response.status_code == 201
        assert response.json()["email"] == unique_email

    def test_weak_password_rejected(
        self, client: TestClient, admin_headers: dict[str, str], api: str, unique_email: str
    ) -> None:
        response = client.post(
            f"{api}/users",
            headers=admin_headers,
            json={"email": unique_email, "password": "short", "role": "analyst"},
        )
        assert response.status_code == 422

    def test_cannot_demote_last_admin(
        self, client: TestClient, admin_headers: dict[str, str], admin_user: User, api: str
    ) -> None:
        """Locking every administrator out of the system should not be one PATCH away."""
        response = client.patch(
            f"{api}/users/{admin_user.id}", headers=admin_headers, json={"role": "analyst"}
        )
        assert response.status_code == 409


class TestAuditTrail:
    def test_login_success_and_failure_are_recorded(
        self, client: TestClient, admin_user: User, api: str, db: Session
    ) -> None:
        from sentinelforge.models import AuditLog

        client.post(f"{api}/auth/login", json={"email": admin_user.email, "password": "wrong"})
        client.post(
            f"{api}/auth/login", json={"email": admin_user.email, "password": TEST_PASSWORD}
        )

        actions = {row.action for row in db.query(AuditLog).all()}
        assert "login_failure" in actions
        assert "login_success" in actions

    def test_audit_survives_actor_deletion(self, db: Session) -> None:
        from sentinelforge.models import AuditAction, AuditLog
        from sentinelforge.services import audit

        user = create_user(db, email="gone@test.local", password=TEST_PASSWORD)
        db.commit()
        audit.record(db, action=AuditAction.RULE_CREATE, actor=user, entity_type="rule")
        db.commit()

        db.delete(user)
        db.commit()

        entry = db.query(AuditLog).filter(AuditLog.action == "rule_create").one()
        assert entry.actor_id is None
        assert entry.actor_email == "gone@test.local", "the trail must outlive the account"


def test_expired_token_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    import uuid

    import jwt

    settings = get_settings()
    expired = jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "type": "access",
            "jti": str(uuid.uuid4()),
            "iat": int((dt.datetime.now(dt.UTC) - dt.timedelta(hours=2)).timestamp()),
            "exp": int((dt.datetime.now(dt.UTC) - dt.timedelta(hours=1)).timestamp()),
        },
        settings.secret_key,
        algorithm=settings.jwt_algorithm,
    )
    with pytest.raises(TokenError):
        decode_token(expired, expected_type="access")
