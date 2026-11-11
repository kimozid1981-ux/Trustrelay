"""API and database integration tests (real PostgreSQL)."""

from __future__ import annotations

import io
import json

import pyotp
from PIL import Image
from sqlalchemy import text

from app.core.config import get_settings
from app.db.session import get_sessionmaker
from tests.conftest import PASSWORD, auth, make_staff, register

SMISHING = "La Poste: votre colis est bloqué. Payez 1,99 € de frais de livraison sous 24h sur https://laposte-suivi-colis.com/fr"


# --- auth ------------------------------------------------------------------------------------------------


async def test_health(client) -> None:  # type: ignore[no-untyped-def]
    assert (await client.get("/healthz")).json() == {"status": "ok"}
    assert (await client.get("/readyz")).json() == {"status": "ready"}


async def test_register_login_refresh_rotation_and_reuse_detection(client) -> None:  # type: ignore[no-untyped-def]
    t = await register(client, "alice@example.org")
    assert t["refresh_token"] and t["role"] == "user"
    me = await client.get("/api/v1/me", headers=auth(t))
    assert me.status_code == 200 and me.json()["email"] == "alice@example.org" and me.json()["plan"] == "free"

    r1 = await client.post("/api/v1/auth/refresh", json={"refresh_token": t["refresh_token"]})
    assert r1.status_code == 200
    new = r1.json()
    # Old refresh token reused -> whole chain revoked, including the new one
    reuse = await client.post("/api/v1/auth/refresh", json={"refresh_token": t["refresh_token"]})
    assert reuse.status_code == 401
    after = await client.post("/api/v1/auth/refresh", json={"refresh_token": new["refresh_token"]})
    assert after.status_code == 401
    assert (await client.get("/api/v1/me", headers=auth(new))).status_code == 401


async def test_web_refresh_uses_httponly_cookie_and_csrf_header(client) -> None:  # type: ignore[no-untyped-def]
    r = await client.post(
        "/api/v1/auth/register", json={"email": "web@example.org", "password": PASSWORD, "accept_terms": True, "client": "web"}
    )
    assert r.status_code == 201 and r.json()["refresh_token"] is None
    cookie = r.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie.replace("Strict", "strict") and "Path=/api/v1/auth" in cookie
    no_header = await client.post("/api/v1/auth/refresh")
    assert no_header.status_code == 401
    ok = await client.post("/api/v1/auth/refresh", headers={"X-Requested-With": "trustrelay"})
    assert ok.status_code == 200 and ok.json()["access_token"]


async def test_weak_password_terms_and_duplicate(client) -> None:  # type: ignore[no-untyped-def]
    r = await client.post("/api/v1/auth/register", json={"email": "b@example.org", "password": "short", "accept_terms": True})
    assert r.status_code == 422 and r.json()["code"] == "weak_password"
    r = await client.post("/api/v1/auth/register", json={"email": "b@example.org", "password": PASSWORD, "accept_terms": False})
    assert r.json()["code"] == "terms_not_accepted"
    await register(client, "b@example.org")
    r = await client.post("/api/v1/auth/register", json={"email": "B@example.org", "password": PASSWORD, "accept_terms": True})
    assert r.status_code == 409


async def test_login_lockout_and_generic_errors(client) -> None:  # type: ignore[no-untyped-def]
    await register(client, "c@example.org")
    unknown = await client.post("/api/v1/auth/login", json={"email": "nobody@example.org", "password": "x" * 12})
    wrong = await client.post("/api/v1/auth/login", json={"email": "c@example.org", "password": "x" * 12})
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json()["detail"] == wrong.json()["detail"]  # no account enumeration
    for _ in range(get_settings().login_max_failures - 1):
        await client.post("/api/v1/auth/login", json={"email": "c@example.org", "password": "x" * 12})
    locked = await client.post("/api/v1/auth/login", json={"email": "c@example.org", "password": PASSWORD})
    assert locked.status_code == 429 and locked.json()["code"] == "account_locked"


async def test_tokens_are_rejected_when_tampered_or_missing(client) -> None:  # type: ignore[no-untyped-def]
    t = await register(client, "d@example.org")
    assert (await client.get("/api/v1/me")).status_code == 401
    bad = t["access_token"][:-3] + ("aaa" if not t["access_token"].endswith("aaa") else "bbb")
    assert (await client.get("/api/v1/me", headers={"Authorization": f"Bearer {bad}"})).status_code == 401
    import jwt as pyjwt

    forged = pyjwt.encode({"sub": "x", "role": "admin"}, "wrong-secret", algorithm="HS256")
    assert (await client.get("/api/v1/me", headers={"Authorization": f"Bearer {forged}"})).status_code == 401


async def test_logout_revokes_session(client) -> None:  # type: ignore[no-untyped-def]
    t = await register(client, "e@example.org")
    assert (await client.post("/api/v1/auth/logout", headers=auth(t))).status_code == 204
    assert (await client.get("/api/v1/me", headers=auth(t))).status_code == 401
    assert (await client.post("/api/v1/auth/refresh", json={"refresh_token": t["refresh_token"]})).status_code == 401


async def test_mfa_login_and_replay_protection(client) -> None:  # type: ignore[no-untyped-def]
    staff = await make_staff(client, "admin@example.org")
    assert staff["mfa"] is True
    login = {"email": "admin@example.org", "password": PASSWORD, "client": "mobile"}
    r = await client.post("/api/v1/auth/login", json=login)
    assert r.json()["code"] == "mfa_code_required"
    # The code used to enable MFA cannot be replayed within its time step.
    totp = pyotp.TOTP(staff["totp_secret"])
    r = await client.post("/api/v1/auth/login", json=login | {"totp_code": totp.now()})
    assert r.status_code == 401 and r.json()["code"] == "invalid_mfa_code"


# --- analyses ---------------------------------------------------------------------------------------------


async def test_analysis_flow_history_note_delete(client) -> None:  # type: ignore[no-untyped-def]
    t = await register(client, "f@example.org")
    r = await client.post(
        "/api/v1/analyses", json={"kind": "message", "text": SMISHING}, headers=auth(t) | {"Accept-Language": "fr-FR"}
    )
    assert r.status_code == 202, r.text
    a = r.json()
    assert a["status"] == "completed" and a["verdict"] == "strong_suspicious"
    assert a["verdict_title"] == "Signaux d'alerte forts"
    assert a["findings"] and all(
        {"evidence", "source_name", "checked_at", "confidence", "limitation"} <= set(f) for f in a["findings"]
    )
    assert a["recommended_action"]["text"] and a["disclaimer"]
    assert "laposte-suivi-colis.com" in a["identified_domains"]

    en = (await client.get(f"/api/v1/analyses/{a['id']}?lang=en", headers=auth(t))).json()
    assert en["verdict_title"] == "Strong warning signs"

    note = await client.put(f"/api/v1/analyses/{a['id']}/note", json={"note": "SMS reçu le 3 mars"}, headers=auth(t))
    assert note.status_code == 200
    hist = (await client.get("/api/v1/analyses", headers=auth(t))).json()
    assert hist["items"][0]["note"] == "SMS reçu le 3 mars" and hist["items"][0]["label"] == "laposte-suivi-colis.com"

    assert (await client.delete(f"/api/v1/analyses/{a['id']}", headers=auth(t))).status_code == 204
    assert (await client.get(f"/api/v1/analyses/{a['id']}", headers=auth(t))).status_code == 404


async def test_content_is_encrypted_at_rest(client) -> None:  # type: ignore[no-untyped-def]
    t = await register(client, "g@example.org")
    await client.post("/api/v1/analyses", json={"kind": "message", "text": SMISHING}, headers=auth(t))
    async with get_sessionmaker()() as db:
        dump = (
            await db.execute(
                text(
                    "SELECT string_agg(encode(coalesce(input_enc,''::bytea),'escape') || encode(coalesce(result_enc,''::bytea),'escape')"
                    " || encode(coalesce(label_enc,''::bytea),'escape'), '') FROM analyses"
                )
            )
        ).scalar_one()
        findings = (await db.execute(text("SELECT string_agg(encode(details_enc,'escape'), '') FROM findings"))).scalar_one()
    for needle in ("colis", "laposte-suivi", "1,99"):
        assert needle not in dump and needle not in findings


async def test_users_cannot_access_each_others_analyses(client) -> None:  # type: ignore[no-untyped-def]
    a = await register(client, "h1@example.org")
    b = await register(client, "h2@example.org")
    res = (await client.post("/api/v1/analyses", json={"kind": "url", "text": "https://paypa1.com"}, headers=auth(a))).json()
    for method, path in (("GET", ""), ("DELETE", ""), ("PUT", "/note")):
        r = await client.request(
            method, f"/api/v1/analyses/{res['id']}{path}", headers=auth(b), json={"note": "x"} if method == "PUT" else None
        )
        assert r.status_code == 404
    assert (await client.get("/api/v1/analyses", headers=auth(b))).json()["items"] == []


async def test_input_validation(client) -> None:  # type: ignore[no-untyped-def]
    t = await register(client, "i@example.org")
    for body in (
        {"kind": "message"},
        {"kind": "sql", "text": "x"},
        {"kind": "message", "text": "x" * 20_001},
        {"kind": "image"},
        {"kind": "message", "text": "   "},
    ):
        r = await client.post("/api/v1/analyses", json=body, headers=auth(t))
        assert r.status_code == 422, body
        assert "x" * 50 not in r.text  # submitted values are not echoed back


async def test_free_plan_quota(client, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(get_settings(), "free_monthly_checks", 2)
    t = await register(client, "j@example.org")
    for _ in range(2):
        assert (
            await client.post(
                "/api/v1/analyses", json={"kind": "message", "text": "Bonjour, ceci est un test simple"}, headers=auth(t)
            )
        ).status_code == 202
    r = await client.post(
        "/api/v1/analyses", json={"kind": "message", "text": "Bonjour, ceci est un test simple"}, headers=auth(t)
    )
    assert r.status_code == 402 and r.json()["code"] == "quota_exceeded"
    # deleting history does not give checks back
    await client.delete("/api/v1/analyses", headers=auth(t))
    assert (
        await client.post("/api/v1/analyses", json={"kind": "message", "text": "Bonjour test"}, headers=auth(t))
    ).status_code == 402


async def test_rate_limit(client, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(get_settings(), "rate_limit_analyses_per_minute", 3)
    t = await register(client, "k@example.org")
    codes = [
        (
            await client.post("/api/v1/analyses", json={"kind": "message", "text": "Bonjour, test de limite"}, headers=auth(t))
        ).status_code
        for _ in range(5)
    ]
    assert codes[:3] == [202, 202, 202] and codes[3] == 429


def _png(color: str = "white") -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (60, 60), color).save(buf, format="PNG")
    return buf.getvalue()


async def test_upload_and_image_analysis_without_ai(client) -> None:  # type: ignore[no-untyped-def]
    t = await register(client, "l@example.org")
    up = await client.post("/api/v1/uploads", files={"file": ("shot.png", _png(), "image/png")}, headers=auth(t))
    assert up.status_code == 201, up.text
    r = await client.post("/api/v1/analyses", json={"kind": "image", "upload_id": up.json()["id"]}, headers=auth(t))
    assert r.json()["verdict"] == "insufficient_information"
    bad = await client.post("/api/v1/uploads", files={"file": ("x.png", b"<svg onload=alert(1)>", "image/png")}, headers=auth(t))
    assert bad.status_code == 422 and bad.json()["code"] == "unsupported_type"
    other = await register(client, "l2@example.org")
    r = await client.post("/api/v1/analyses", json={"kind": "image", "upload_id": up.json()["id"]}, headers=auth(other))
    assert r.status_code == 404


# --- privacy controls ------------------------------------------------------------------------------------


async def test_export_contains_decrypted_data(client) -> None:  # type: ignore[no-untyped-def]
    t = await register(client, "m@example.org")
    await client.post("/api/v1/analyses", json={"kind": "message", "text": SMISHING}, headers=auth(t))
    r = await client.get("/api/v1/me/export", headers=auth(t))
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    doc = json.loads(r.text)
    assert doc["format"] == "trustrelay-export-v1"
    assert doc["profile"]["email"] == "m@example.org"
    assert doc["analyses"][0]["input"] == SMISHING
    assert any(e["action"] == "analysis.create" for e in doc["activity_log"])


async def test_account_deletion_removes_everything(client) -> None:  # type: ignore[no-untyped-def]
    t = await register(client, "n@example.org")
    uid = (await client.get("/api/v1/me", headers=auth(t))).json()["id"]
    up = (await client.post("/api/v1/uploads", files={"file": ("s.png", _png(), "image/png")}, headers=auth(t))).json()
    await client.post("/api/v1/analyses", json={"kind": "image", "upload_id": up["id"]}, headers=auth(t))
    await client.post("/api/v1/analyses", json={"kind": "message", "text": SMISHING}, headers=auth(t))
    bad = await client.post("/api/v1/me/delete", json={"password": "wrong-password", "confirm": "DELETE"}, headers=auth(t))
    assert bad.status_code == 401
    r = await client.post("/api/v1/me/delete", json={"password": PASSWORD, "confirm": "DELETE"}, headers=auth(t))
    assert r.status_code == 204
    async with get_sessionmaker()() as db:
        for table in ("users", "analyses", "findings", "uploads", "auth_sessions", "user_preferences", "usage_counters"):
            assert (await db.execute(text(f"SELECT count(*) FROM {table}"))).scalar_one() == 0, table
    from pathlib import Path

    user_dir = Path(get_settings().storage_local_path) / "uploads" / uid
    assert not list(user_dir.rglob("*.bin"))
    login = await client.post("/api/v1/auth/login", json={"email": "n@example.org", "password": PASSWORD})
    assert login.status_code == 401


async def test_retention_zero_drops_content_and_purge(client) -> None:  # type: ignore[no-untyped-def]
    t = await register(client, "o@example.org")
    await client.patch("/api/v1/me/preferences", json={"retention_days": 0}, headers=auth(t))
    a = (await client.post("/api/v1/analyses", json={"kind": "message", "text": SMISHING}, headers=auth(t))).json()
    assert a["input"] is None and a["verdict"] == "strong_suspicious"
    async with get_sessionmaker()() as db:
        await db.execute(text("UPDATE analyses SET expires_at = now() - interval '1 minute'"))
        await db.commit()
        from app.services.analysis_service import purge_expired

        result = await purge_expired(db)
    assert result["analyses"] == 1
    assert (await client.get(f"/api/v1/analyses/{a['id']}", headers=auth(t))).status_code == 404


async def test_shortening_retention_updates_existing_rows(client) -> None:  # type: ignore[no-untyped-def]
    t = await register(client, "o2@example.org")
    await client.post("/api/v1/analyses", json={"kind": "message", "text": SMISHING}, headers=auth(t))
    await client.patch("/api/v1/me/preferences", json={"retention_days": 30}, headers=auth(t))
    async with get_sessionmaker()() as db:
        days = (await db.execute(text("SELECT extract(day FROM expires_at - created_at) FROM analyses"))).scalar_one()
    assert int(days) == 30


async def test_audit_log_is_append_only(client) -> None:  # type: ignore[no-untyped-def]
    await register(client, "p@example.org")
    import pytest
    from sqlalchemy.exc import DBAPIError

    async with get_sessionmaker()() as db:
        with pytest.raises(DBAPIError):
            await db.execute(text("UPDATE audit_logs SET action = 'tampered'"))
        await db.rollback()
        with pytest.raises(DBAPIError):
            await db.execute(text("DELETE FROM audit_logs"))
        await db.rollback()


# --- family ---------------------------------------------------------------------------------------------


async def test_family_invite_join_share_and_privacy(client) -> None:  # type: ignore[no-untyped-def]
    parent = await register(client, "parent@example.org")
    teen = await register(client, "teen@example.org")
    g = await client.post("/api/v1/family", json={"name": "Famille Test"}, headers=auth(parent))
    assert g.status_code == 201
    code = (
        await client.post("/api/v1/family/invites", json={"role": "member", "age_band": "teen"}, headers=auth(parent))
    ).json()["code"]
    bad = await client.post("/api/v1/family/join", json={"code": "AAAA-BBBB-CCCC"}, headers=auth(teen))
    assert bad.status_code == 404
    joined = await client.post("/api/v1/family/join", json={"code": code}, headers=auth(teen))
    assert joined.status_code == 200 and len(joined.json()["group"]["members"]) == 2
    # code is single-use
    third = await register(client, "third@example.org")
    assert (await client.post("/api/v1/family/join", json={"code": code}, headers=auth(third))).status_code == 404

    a = (await client.post("/api/v1/analyses", json={"kind": "message", "text": SMISHING}, headers=auth(parent))).json()
    assert (
        await client.post(f"/api/v1/analyses/{a['id']}/share", json={"confirm": False}, headers=auth(parent))
    ).status_code == 422
    assert (
        await client.post(
            f"/api/v1/analyses/{a['id']}/share", json={"confirm": True, "message": "Attention à ce SMS"}, headers=auth(parent)
        )
    ).status_code == 201
    view = (await client.get("/api/v1/family?lang=fr", headers=auth(teen))).json()
    w = view["warnings"][0]
    assert w["verdict"] == "strong_suspicious" and w["message"] == "Attention à ce SMS"
    assert "laposte-suivi" not in json.dumps(view)  # raw content never shared
    assert "adulte" in w["verdict_summary"]  # age-appropriate wording for teens
    # teen cannot read the parent's analysis
    assert (await client.get(f"/api/v1/analyses/{a['id']}", headers=auth(teen))).status_code == 404
    # a member cannot change someone else's permissions; can opt out of receiving warnings
    me_id = [m for m in view["group"]["members"] if m["is_me"]][0]["user_id"]
    parent_id = [m for m in view["group"]["members"] if not m["is_me"]][0]["user_id"]
    assert (
        await client.patch(f"/api/v1/family/members/{parent_id}", json={"receive_warnings": False}, headers=auth(teen))
    ).status_code == 403
    assert (
        await client.patch(f"/api/v1/family/members/{me_id}", json={"can_share_warnings": True}, headers=auth(teen))
    ).status_code == 403
    r = await client.patch(f"/api/v1/family/members/{me_id}", json={"receive_warnings": False}, headers=auth(teen))
    assert r.status_code == 200 and r.json()["warnings"] == []


# --- admin / support ------------------------------------------------------------------------------------


async def test_admin_requires_role_and_mfa(client) -> None:  # type: ignore[no-untyped-def]
    user = await register(client, "q@example.org")
    assert (await client.get("/api/v1/admin/stats", headers=auth(user))).status_code == 403
    await register(client, "nomfa@example.org")
    async with get_sessionmaker()() as db:
        await db.execute(text("UPDATE users SET role='admin' WHERE email='nomfa@example.org'"))
        await db.commit()
    tokens = (await client.post("/api/v1/auth/login", json={"email": "nomfa@example.org", "password": PASSWORD})).json()
    r = await client.get("/api/v1/admin/stats", headers=auth(tokens))
    assert r.status_code == 403 and r.json()["code"] == "mfa_required"


async def test_role_change_invalidates_existing_tokens(client) -> None:  # type: ignore[no-untyped-def]
    admin = await make_staff(client, "boss@example.org")
    u = await register(client, "promoted@example.org")
    users = (await client.get("/api/v1/admin/users?q=promoted", headers=auth(admin))).json()["items"]
    r = await client.patch(f"/api/v1/admin/users/{users[0]['id']}", json={"role": "support"}, headers=auth(admin))
    assert r.status_code == 200
    assert (await client.get("/api/v1/me", headers=auth(u))).json()["code"] == "role_changed"


async def test_admin_never_sees_content(client) -> None:  # type: ignore[no-untyped-def]
    admin = await make_staff(client, "root@example.org")
    t = await register(client, "victim@example.org")
    await client.post("/api/v1/analyses", json={"kind": "message", "text": SMISHING}, headers=auth(t))
    await client.post(
        "/api/v1/support/tickets",
        json={"category": "fraud", "subject": "SMS La Poste reçu", "body": "J'ai reçu un SMS bizarre de laposte-suivi"},
        headers=auth(t),
    )
    blobs = []
    for path in (
        "stats",
        "users",
        "threat-sources",
        "ai-usage",
        "errors",
        "security-events",
        "abuse",
        "audit-logs",
        "support-overview",
        "feature-flags",
        "config",
    ):
        r = await client.get(f"/api/v1/admin/{path}", headers=auth(admin))
        assert r.status_code == 200, (path, r.text)
        blobs.append(r.text)
    everything = "\n".join(blobs)
    for needle in ("colis", "laposte-suivi", "1,99", "SMS bizarre"):
        assert needle not in everything
    stats = json.loads(blobs[0])
    assert stats["analyses_by_verdict"]["strong_suspicious"] == 1 and stats["users_total"] == 2


async def test_support_needs_customer_grant_to_view_analysis(client) -> None:  # type: ignore[no-untyped-def]
    agent = await make_staff(client, "agent@example.org", role="support")
    t = await register(client, "cust@example.org")
    a = (await client.post("/api/v1/analyses", json={"kind": "message", "text": SMISHING}, headers=auth(t))).json()
    ticket = (
        await client.post(
            "/api/v1/support/tickets",
            json={"category": "fraud", "subject": "Aide SVP", "body": "Pouvez-vous regarder mon analyse ?"},
            headers=auth(t),
        )
    ).json()
    listing = (await client.get("/api/v1/staff/tickets", headers=auth(agent))).json()
    assert "subject" not in listing[0]
    import uuid as _uuid

    assert (await client.get(f"/api/v1/staff/access-grants/{_uuid.uuid4()}/analysis", headers=auth(agent))).status_code == 403
    g = (
        await client.post(
            f"/api/v1/analyses/{a['id']}/support-access", json={"hours": 2, "ticket_id": ticket["id"]}, headers=auth(t)
        )
    ).json()
    detail = (await client.get(f"/api/v1/staff/tickets/{ticket['id']}", headers=auth(agent))).json()
    assert detail["access_grants"][0]["id"] == g["id"]
    view = await client.get(f"/api/v1/staff/access-grants/{g['id']}/analysis", headers=auth(agent))
    assert view.status_code == 200 and view.json()["input"] == SMISHING
    await client.delete(f"/api/v1/support-access/{g['id']}", headers=auth(t))
    assert (await client.get(f"/api/v1/staff/access-grants/{g['id']}/analysis", headers=auth(agent))).status_code == 403
    admin_logs = (
        await client.get(
            "/api/v1/admin/audit-logs?action=support.analysis_viewed",
            headers=auth(await make_staff(client, "auditor@example.org")),
        )
    ).json()
    assert len(admin_logs) == 1


async def test_feature_flag_disables_module(client) -> None:  # type: ignore[no-untyped-def]
    admin = await make_staff(client, "ff@example.org")
    assert (
        await client.put("/api/v1/admin/feature-flags/module.message", json={"enabled": False}, headers=auth(admin))
    ).status_code == 200
    t = await register(client, "ffu@example.org")
    a = (
        await client.post(
            "/api/v1/analyses",
            json={"kind": "message", "text": "Communiquez-moi le code reçu par SMS pour valider"},
            headers=auth(t),
        )
    ).json()
    assert "message" not in a["modules_run"]


async def test_security_headers_and_problem_json(client) -> None:  # type: ignore[no-untyped-def]
    r = await client.get("/api/v1/me")
    assert r.headers["content-type"].startswith("application/problem+json")
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-request-id"]


async def test_unsafe_production_config_refuses_to_start(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import pytest

    from app.core.config import Settings

    s = Settings(environment="production")
    with pytest.raises(RuntimeError, match="Unsafe configuration"):
        s.validate_for_environment()
