"""All 35 Uvicorn proxy, lifespan, constructor, and ASGI3 security tests (Rev10 §20.3)."""

import asyncio
from contextlib import asynccontextmanager
import inspect
import os
import pickle
from typing import Any

from fastapi import Request
from fastapi.testclient import TestClient
import pytest
from starlette.testclient import _is_asgi3
import uvicorn
import uvicorn._compat as uvicorn_compat
from uvicorn.config import STARTUP_FAILURE
from uvicorn.lifespan.off import LifespanOff
from uvicorn.lifespan.on import LifespanOn
from uvicorn.middleware.asgi2 import ASGI2Middleware
from uvicorn.middleware.message_logger import MessageLoggerMiddleware
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
from uvicorn.middleware.wsgi import WSGIMiddleware

from app.core.config import Settings, get_settings
from app.main import Folio360FastAPI, create_app, lifespan
from app.server import (
    _ACTIVE_VERIFIED_CONFIG_LOAD,
    _VERIFIED_APP_REGISTRY,
    VerifiedUvicornConfig,
    build_uvicorn_config,
    main as server_cli_main,
    validate_effective_uvicorn_config,
    verify_loaded_asgi_middleware,
    verify_production_asgi_trust_boundary,
)


def _make_prod_settings(
    *,
    proxy_headers_enabled: bool = False,
    trusted_proxy_ips: list[str] | None = None,
) -> Settings:
    return Settings(
        _env_file=None,
        ENVIRONMENT="production",
        DATABASE_URL="postgresql+psycopg://folio360_test_app:pass@127.0.0.1:5434/folio360_test",
        DB_ECHO=False,
        JWT_SECRET_KEY="prod-test-jwt-secret-key-with-at-least-32-characters",
        RESEND_API_KEY="re_test_key_1234567890abcdef",
        EMAIL_FROM_ADDRESS="no-reply@folio360.com",
        FRONTEND_BASE_URL="https://app.folio360.com",
        CORS_ORIGINS=["https://app.folio360.com"],
        REFRESH_COOKIE_SECURE=True,
        COOKIE_DEPLOYMENT_MODE="same_site",
        REFRESH_COOKIE_SAMESITE="lax",
        RATE_LIMIT_ENABLED=True,
        PROXY_HEADERS_ENABLED=proxy_headers_enabled,
        TRUSTED_PROXY_IPS=trusted_proxy_ips if trusted_proxy_ips is not None else [],
    )


def _set_prod_env(
    monkeypatch: pytest.MonkeyPatch,
    *,
    proxy_headers_enabled: bool = False,
    trusted_proxy_ips_json: str = "[]",
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+psycopg://folio360_test_app:pass@127.0.0.1:5434/folio360_test",
    )
    monkeypatch.setenv("DB_ECHO", "false")
    monkeypatch.setenv(
        "JWT_SECRET_KEY",
        "prod-test-jwt-secret-key-with-at-least-32-characters",
    )
    monkeypatch.setenv("RESEND_API_KEY", "re_test_key_1234567890abcdef")
    monkeypatch.setenv("EMAIL_FROM_ADDRESS", "no-reply@folio360.com")
    monkeypatch.setenv("FRONTEND_BASE_URL", "https://app.folio360.com")
    monkeypatch.setenv("CORS_ORIGINS", '["https://app.folio360.com"]')
    monkeypatch.setenv("REFRESH_COOKIE_SECURE", "true")
    monkeypatch.setenv("COOKIE_DEPLOYMENT_MODE", "same_site")
    monkeypatch.setenv("REFRESH_COOKIE_SAMESITE", "lax")
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv(
        "PROXY_HEADERS_ENABLED",
        "true" if proxy_headers_enabled else "false",
    )
    monkeypatch.setenv("TRUSTED_PROXY_IPS", trusted_proxy_ips_json)
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _cleanup_registry_and_settings_cache():
    yield
    _VERIFIED_APP_REGISTRY.clear()
    get_settings.cache_clear()


def _unwrap_app(config: VerifiedUvicornConfig) -> Folio360FastAPI:
    if isinstance(config.loaded_app, ProxyHeadersMiddleware):
        return config.loaded_app.app  # type: ignore[return-value]
    return config.loaded_app  # type: ignore[return-value]


def _run_http_scope(
    asgi_app: Any,
    *,
    path: str = "/api/v1/health",
    client: tuple[str, int] = ("127.0.0.1", 12345),
    headers: list[tuple[bytes, bytes]] | None = None,
) -> tuple[int, list[tuple[bytes, bytes]], bytes, Any]:
    async def _invoke():
        messages: list[dict[str, Any]] = []
        scope: dict[str, Any] = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.4"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": b"",
            "headers": headers or [(b"host", b"app.folio360.com")],
            "client": client,
            "server": ("127.0.0.1", 8000),
        }

        async def receive() -> dict[str, Any]:
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message: dict[str, Any]) -> None:
            messages.append(message)

        ret = await asgi_app(scope, receive, send)
        return messages, ret

    messages, ret = asyncio.run(_invoke())
    status_code = next(
        m["status"] for m in messages if m["type"] == "http.response.start"
    )
    resp_headers = next(
        m["headers"] for m in messages if m["type"] == "http.response.start"
    )
    body = b"".join(
        m.get("body", b"") for m in messages if m["type"] == "http.response.body"
    )
    return status_code, resp_headers, body, ret


@asynccontextmanager
async def _started_lifespan(config: VerifiedUvicornConfig):
    ls = LifespanOn(config)
    await ls.startup()
    try:
        yield ls
    finally:
        await ls.shutdown()


def _test_startup_and_teardown(config: VerifiedUvicornConfig) -> Folio360FastAPI:
    async def _boot():
        async with _started_lifespan(config) as ls:
            assert ls.should_exit is False
            return _unwrap_app(config)

    return asyncio.run(_boot())


# ==============================================================================
# Part A: Core Proxy & Startup Trust-Boundary Tests (Tests 1-13)
# ==============================================================================


def test_01_raw_uvicorn_factory_wildcard_forwarded_trust_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_prod_env(
        monkeypatch,
        proxy_headers_enabled=True,
        trusted_proxy_ips_json='["10.0.0.1"]',
    )
    cfg = uvicorn.Config(
        "app.main:create_app",
        factory=True,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )
    with pytest.raises(RuntimeError, match="Unverified Uvicorn Config.load"):
        cfg.load()


def test_02_raw_uvicorn_or_cli_conflicting_proxy_headers_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_prod_env(
        monkeypatch,
        proxy_headers_enabled=False,
        trusted_proxy_ips_json="[]",
    )
    cfg = uvicorn.Config(
        "app.main:create_app",
        factory=True,
        proxy_headers=True,
        forwarded_allow_ips="10.0.0.1",
    )
    with pytest.raises(RuntimeError):
        cfg.load()

    with pytest.raises(RuntimeError, match="Conflicting proxy_headers"):
        server_cli_main(["--proxy-headers"])

    _set_prod_env(
        monkeypatch,
        proxy_headers_enabled=True,
        trusted_proxy_ips_json='["10.0.0.1"]',
    )
    with pytest.raises(RuntimeError, match="Conflicting proxy_headers"):
        server_cli_main(["--no-proxy-headers"])


def test_03_raw_programmatic_uvicorn_config_wildcard_rejected() -> None:
    settings = _make_prod_settings(
        proxy_headers_enabled=True,
        trusted_proxy_ips=["10.0.0.1"],
    )
    app = create_app(settings)
    cfg = uvicorn.Config(app, proxy_headers=True, forwarded_allow_ips="*")
    with pytest.raises(RuntimeError, match="Unverified Uvicorn Config.load"):
        cfg.load()

    async def _run_ls():
        async with lifespan(app):
            pass

    with pytest.raises(RuntimeError, match="Unverified ASGI startup"):
        asyncio.run(_run_ls())


def test_04_raw_programmatic_uvicorn_config_conflicting_proxy_rejected() -> None:
    settings = _make_prod_settings(
        proxy_headers_enabled=True,
        trusted_proxy_ips=["10.0.0.1"],
    )
    cfg_disabled = uvicorn.Config(create_app(settings), proxy_headers=False)
    with pytest.raises(RuntimeError):
        cfg_disabled.load()

    cfg_wrong_ip = uvicorn.Config(
        create_app(settings),
        proxy_headers=True,
        forwarded_allow_ips="10.0.0.2",
    )
    with pytest.raises(RuntimeError):
        cfg_wrong_ip.load()


def test_05_controlled_launcher_unsafe_override_rejected() -> None:
    settings = _make_prod_settings(
        proxy_headers_enabled=True,
        trusted_proxy_ips=["10.0.0.1"],
    )
    with pytest.raises(RuntimeError):
        build_uvicorn_config(settings, forwarded_allow_ips="*")
    with pytest.raises(RuntimeError):
        VerifiedUvicornConfig(
            create_app(settings),
            settings=settings,
            forwarded_allow_ips="*",
        )


def test_06_factory_created_app_cannot_self_certify() -> None:
    settings = _make_prod_settings()
    app = create_app(settings)
    assert _VERIFIED_APP_REGISTRY.get(id(app)) is None
    assert not hasattr(app.state, "proxy_verified")
    assert not hasattr(app.state, "lifespan_verified")


def test_07_production_lifespan_rejects_unverified_testclient() -> None:
    settings = _make_prod_settings()
    app = create_app(settings)
    with pytest.raises(RuntimeError, match="Unverified ASGI startup"):
        with TestClient(app):
            pass


def test_08_production_lifespan_rejects_post_load_mutation() -> None:
    settings = _make_prod_settings(
        proxy_headers_enabled=True,
        trusted_proxy_ips=["10.0.0.1"],
    )

    # 8a: Mutate forwarded_allow_ips post-load
    cfg1 = build_uvicorn_config(settings)
    cfg1.load()
    cfg1.forwarded_allow_ips = "*"
    app1 = _unwrap_app(cfg1)
    with pytest.raises(RuntimeError):
        verify_production_asgi_trust_boundary(app1, settings)

    # 8b: Mutate proxy_headers post-load
    cfg2 = build_uvicorn_config(settings)
    cfg2.load()
    cfg2.proxy_headers = False
    app2 = _unwrap_app(cfg2)
    with pytest.raises(RuntimeError):
        verify_production_asgi_trust_boundary(app2, settings)

    # 8c: Replace loaded_app post-load
    cfg3 = build_uvicorn_config(settings)
    cfg3.load()
    app3 = _unwrap_app(cfg3)
    cfg3.loaded_app = app3
    with pytest.raises(RuntimeError):
        verify_production_asgi_trust_boundary(app3, settings)


def test_09_controlled_launcher_direct_deployment_succeeds() -> None:
    settings = _make_prod_settings(proxy_headers_enabled=False, trusted_proxy_ips=[])
    cfg = build_uvicorn_config(settings)
    cfg.load()
    app = _unwrap_app(cfg)

    observed_client_ip: dict[str, str | None] = {}

    @app.get("/_ip-probe")
    def _probe(request: Request) -> dict[str, str | None]:
        observed_client_ip["host"] = request.client.host if request.client else None
        return observed_client_ip

    async def _run():
        async with _started_lifespan(cfg):
            assert cfg.proxy_headers is False
            assert cfg.interface == "asgi3"
            assert cfg.loaded_app is app
            assert _VERIFIED_APP_REGISTRY[id(app)].lifespan_verified is True

    asyncio.run(_run())

    # Re-enter lifespan cleanly for HTTP request dispatch check
    async def _run_with_req():
        async with _started_lifespan(cfg):
            messages: list[dict[str, Any]] = []
            scope = {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": "GET",
                "scheme": "https",
                "path": "/_ip-probe",
                "raw_path": b"/_ip-probe",
                "query_string": b"",
                "headers": [
                    (b"host", b"app.folio360.com"),
                    (b"x-forwarded-for", b"198.51.100.77"),
                ],
                "client": ("10.0.0.99", 5555),
                "server": ("127.0.0.1", 8000),
            }

            async def receive():
                return {"type": "http.request", "body": b"", "more_body": False}

            async def send(msg):
                messages.append(msg)

            await cfg.loaded_app(scope, receive, send)
            return messages

    asyncio.run(_run_with_req())
    assert observed_client_ip["host"] == "10.0.0.99"


def test_10_controlled_launcher_trusted_reverse_proxy_succeeds() -> None:
    settings = _make_prod_settings(
        proxy_headers_enabled=True,
        trusted_proxy_ips=["10.0.0.1", "172.16.0.0/12"],
    )
    cfg = build_uvicorn_config(settings)
    cfg.load()
    app = _unwrap_app(cfg)

    async def _run():
        async with _started_lifespan(cfg):
            assert isinstance(cfg.loaded_app, ProxyHeadersMiddleware)
            assert cfg.interface == "asgi3"
            assert cfg.loaded_app.trusted_hosts.always_trust is False
            assert cfg.loaded_app.trusted_hosts.trusted_literals == set()
            assert _VERIFIED_APP_REGISTRY[id(app)].lifespan_verified is True

    asyncio.run(_run())


def test_11_multiworker_pickled_config_validates_independently() -> None:
    settings = _make_prod_settings(
        proxy_headers_enabled=True,
        trusted_proxy_ips=["10.0.0.1"],
    )
    cfg = build_uvicorn_config(
        settings,
        app="app.main:create_app",
        factory=True,
        workers=2,
    )
    worker_cfg: VerifiedUvicornConfig = pickle.loads(pickle.dumps(cfg))
    assert isinstance(worker_cfg, VerifiedUvicornConfig)
    worker_cfg.load()
    worker_app = _unwrap_app(worker_cfg)

    async def _run():
        async with _started_lifespan(worker_cfg):
            assert worker_cfg.lifespan == "on"
            assert worker_cfg.interface == "asgi3"
            assert isinstance(worker_cfg.loaded_app, ProxyHeadersMiddleware)
            assert _VERIFIED_APP_REGISTRY[id(worker_app)].lifespan_verified is True

    asyncio.run(_run())


def test_12_multiworker_tampered_worker_fails_before_serving(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert STARTUP_FAILURE == 3
    settings = _make_prod_settings(
        proxy_headers_enabled=True,
        trusted_proxy_ips=["10.0.0.1"],
    )
    cfg = build_uvicorn_config(
        settings,
        app="app.main:create_app",
        factory=True,
        workers=2,
    )

    # 12a: Mutate forwarded_allow_ips in worker
    w1: VerifiedUvicornConfig = pickle.loads(pickle.dumps(cfg))
    w1.forwarded_allow_ips = "*"
    with pytest.raises(RuntimeError):
        w1.load()

    # 12b: Mutate lifespan to "off" in worker
    w2: VerifiedUvicornConfig = pickle.loads(pickle.dumps(cfg))
    w2.lifespan = "off"
    with pytest.raises(RuntimeError):
        w2.load()

    # 12c: Mutate interface to "asgi2" in worker
    w3: VerifiedUvicornConfig = pickle.loads(pickle.dumps(cfg))
    w3.interface = "asgi2"
    with pytest.raises(RuntimeError):
        w3.load()

    # 12d: Inject FORWARDED_ALLOW_IPS="*" into worker environ
    w4: VerifiedUvicornConfig = pickle.loads(pickle.dumps(cfg))
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "*")
    with pytest.raises(RuntimeError):
        w4.load()


def test_13_single_hop_and_multi_hop_trusted_proxy_ip_resolution() -> None:
    from app.api.deps.auth import resolve_client_ip

    settings = _make_prod_settings(
        proxy_headers_enabled=True,
        trusted_proxy_ips=["10.0.0.1", "10.0.0.2"],
    )
    cfg = build_uvicorn_config(settings)
    cfg.load()
    app = _unwrap_app(cfg)
    captured: list[str] = []

    @app.get("/_resolve-ip")
    def _resolve(request: Request) -> dict[str, str]:
        ip = resolve_client_ip(request)
        captured.append(ip)
        return {"ip": ip}

    async def _dispatch_all():
        async with _started_lifespan(cfg):
            for headers in (
                [(b"host", b"app.folio360.com"), (b"x-forwarded-for", b"spoof, 203.0.113.10")],
                [
                    (b"host", b"app.folio360.com"),
                    (b"x-forwarded-for", b"spoof, 203.0.113.10, 10.0.0.2"),
                ],
                [(b"host", b"app.folio360.com")],
                [(b"host", b"app.folio360.com"), (b"x-forwarded-for", b"not_an_ip")],
            ):
                scope = {
                    "type": "http",
                    "asgi": {"version": "3.0"},
                    "http_version": "1.1",
                    "method": "GET",
                    "scheme": "https",
                    "path": "/_resolve-ip",
                    "raw_path": b"/_resolve-ip",
                    "query_string": b"",
                    "headers": headers,
                    "client": ("10.0.0.1", 40000),
                    "server": ("127.0.0.1", 8000),
                }

                async def receive():
                    return {"type": "http.request", "body": b"", "more_body": False}

                async def send(_msg):
                    return None

                await cfg.loaded_app(scope, receive, send)

    asyncio.run(_dispatch_all())
    assert captured == ["203.0.113.10", "203.0.113.10", "10.0.0.1", "invalid-client-ip"]


# ==============================================================================
# Part B: Lifespan-Disable Bypass & Effective-Lifespan Verification (Tests 14-19)
# ==============================================================================


def test_14_raw_cli_lifespan_off_and_wildcard_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_prod_env(
        monkeypatch,
        proxy_headers_enabled=True,
        trusted_proxy_ips_json='["10.0.0.1"]',
    )
    cfg = uvicorn.Config(
        "app.main:create_app",
        factory=True,
        proxy_headers=True,
        forwarded_allow_ips="*",
        lifespan="off",
    )
    with pytest.raises(RuntimeError, match="Unverified Uvicorn Config.load"):
        cfg.load()


def test_15_raw_programmatic_lifespan_off_blocked_at_load_and_request() -> None:
    settings = _make_prod_settings(
        proxy_headers_enabled=True,
        trusted_proxy_ips=["10.0.0.1"],
    )
    app = create_app(settings)
    cfg = uvicorn.Config(
        app,
        proxy_headers=True,
        forwarded_allow_ips="10.0.0.1",
        lifespan="off",
    )
    with pytest.raises(RuntimeError, match="Unverified Uvicorn Config.load"):
        cfg.load()

    with pytest.raises(RuntimeError, match="VerifiedUvicornConfig lifespan verification"):
        _run_http_scope(app)


def test_16_raw_and_mutated_lifespan_auto_rejected() -> None:
    settings = _make_prod_settings()
    app = create_app(settings)

    raw_cfg = uvicorn.Config(app, lifespan="auto")
    with pytest.raises(RuntimeError, match="Unverified Uvicorn Config.load"):
        raw_cfg.load()

    cfg = build_uvicorn_config(settings)
    cfg.load()
    cfg.lifespan = "auto"
    loaded_inner = _unwrap_app(cfg)
    with pytest.raises(RuntimeError, match="lifespan='on'"):
        validate_effective_uvicorn_config(cfg, cfg._expected_proxy_policy)

    async def _run_ls():
        async with lifespan(loaded_inner):
            pass

    with pytest.raises(RuntimeError, match="lifespan='on'"):
        asyncio.run(_run_ls())


def test_17_controlled_launcher_conflicting_lifespan_overrides_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _make_prod_settings()
    for bad_ls in ("off", "auto"):
        with pytest.raises(RuntimeError, match="Invalid lifespan override"):
            build_uvicorn_config(settings, lifespan=bad_ls)

    _set_prod_env(monkeypatch)
    with pytest.raises(RuntimeError, match="Invalid lifespan override"):
        server_cli_main(["--lifespan", "off"])

    for env_ls in ("off", "auto"):
        monkeypatch.setenv("UVICORN_LIFESPAN", env_ls)
        with pytest.raises(RuntimeError, match="UVICORN_LIFESPAN"):
            build_uvicorn_config(settings)


def test_18_controlled_launcher_valid_lifespan_on_succeeds() -> None:
    settings = _make_prod_settings()
    cfg = build_uvicorn_config(settings)
    cfg_explicit = build_uvicorn_config(settings, lifespan="on")
    for candidate in (cfg, cfg_explicit):
        candidate.load()
        assert candidate.lifespan == "on"
        assert candidate.lifespan_class is LifespanOn
        app = _test_startup_and_teardown(candidate)
        assert _VERIFIED_APP_REGISTRY[id(app)].lifespan_verified is True


def test_19_production_request_and_lifespan_fail_closed_if_lifespan_skipped() -> None:
    settings = _make_prod_settings()
    cfg = build_uvicorn_config(settings)
    cfg.load()
    app = _unwrap_app(cfg)
    assert _VERIFIED_APP_REGISTRY[id(app)].lifespan_verified is False

    # Lifespan skipped -> _dispatch_asgi rejects HTTP scope
    with pytest.raises(RuntimeError, match="VerifiedUvicornConfig lifespan verification"):
        _run_http_scope(cfg.loaded_app)

    # LifespanOff class injected -> lifespan verification fails
    cfg.lifespan_class = LifespanOff
    with pytest.raises(RuntimeError, match="LifespanOn"):
        verify_production_asgi_trust_boundary(app, settings)


# ==============================================================================
# Part C: VerifiedUvicornConfig Constructor Argument-Handling Tests (Tests 20-27)
# ==============================================================================


def test_20_explicit_matching_proxy_headers_accepted() -> None:
    settings = _make_prod_settings(
        proxy_headers_enabled=True,
        trusted_proxy_ips=["10.0.0.1"],
    )
    cfg = VerifiedUvicornConfig(create_app(settings), settings=settings, proxy_headers=True)
    assert cfg.proxy_headers is True


def test_21_explicit_matching_forwarded_allow_ips_accepted() -> None:
    settings = _make_prod_settings(
        proxy_headers_enabled=True,
        trusted_proxy_ips=["10.0.0.1", "172.16.0.0/12"],
    )
    cfg_str = VerifiedUvicornConfig(
        create_app(settings),
        settings=settings,
        forwarded_allow_ips="10.0.0.1,172.16.0.0/12",
    )
    assert cfg_str.forwarded_allow_ips == "10.0.0.1,172.16.0.0/12"

    cfg_list = VerifiedUvicornConfig(
        create_app(settings),
        settings=settings,
        forwarded_allow_ips=["10.0.0.1", "172.16.0.0/12"],
    )
    assert cfg_list.forwarded_allow_ips == "10.0.0.1,172.16.0.0/12"


def test_22_all_governed_explicit_values_together_succeed() -> None:
    settings = _make_prod_settings(
        proxy_headers_enabled=True,
        trusted_proxy_ips=["10.0.0.1"],
    )
    cfg = VerifiedUvicornConfig(
        create_app(settings),
        settings=settings,
        proxy_headers=True,
        forwarded_allow_ips="10.0.0.1",
        lifespan="on",
        interface="asgi3",
    )
    assert cfg.proxy_headers is True
    assert cfg.forwarded_allow_ips == "10.0.0.1"
    assert cfg.lifespan == "on"
    assert cfg.interface == "asgi3"


def test_23_conflicting_proxy_headers_override_rejected() -> None:
    settings = _make_prod_settings(proxy_headers_enabled=False, trusted_proxy_ips=[])
    with pytest.raises(RuntimeError, match="Conflicting proxy_headers override"):
        VerifiedUvicornConfig(create_app(settings), settings=settings, proxy_headers=True)


def test_24_conflicting_forwarded_allow_ips_override_rejected() -> None:
    settings = _make_prod_settings(
        proxy_headers_enabled=True,
        trusted_proxy_ips=["10.0.0.1"],
    )
    with pytest.raises(RuntimeError):
        VerifiedUvicornConfig(
            create_app(settings),
            settings=settings,
            forwarded_allow_ips="10.0.0.2",
        )
    with pytest.raises(RuntimeError):
        VerifiedUvicornConfig(
            create_app(settings),
            settings=settings,
            forwarded_allow_ips="*",
        )


def test_25_duplicate_keyword_regression_absent() -> None:
    settings = _make_prod_settings(
        proxy_headers_enabled=True,
        trusted_proxy_ips=["10.0.0.1"],
    )
    cfg = build_uvicorn_config(
        settings,
        proxy_headers=True,
        forwarded_allow_ips="10.0.0.1",
        lifespan="on",
        interface="asgi3",
    )
    assert isinstance(cfg, VerifiedUvicornConfig)


def test_26_defaults_when_no_overrides_supplied() -> None:
    settings = _make_prod_settings(
        proxy_headers_enabled=True,
        trusted_proxy_ips=["10.0.0.1"],
    )
    cfg = VerifiedUvicornConfig(create_app(settings), settings=settings)
    assert cfg.proxy_headers is True
    assert cfg.forwarded_allow_ips == "10.0.0.1"
    assert cfg.lifespan == "on"
    assert cfg.interface == "asgi3"
    assert cfg.asgi_version == "3.0"


def test_27_unrelated_uvicorn_args_preserved_and_unknown_rejected() -> None:
    settings = _make_prod_settings()
    cfg = VerifiedUvicornConfig(
        create_app(settings),
        settings=settings,
        host="0.0.0.0",
        port=9001,
        timeout_keep_alive=15,
        access_log=False,
    )
    assert cfg.host == "0.0.0.0"
    assert cfg.port == 9001
    assert cfg.timeout_keep_alive == 15
    assert cfg.access_log is False

    with pytest.raises(TypeError):
        VerifiedUvicornConfig(
            create_app(settings),
            settings=settings,
            unknown_uvicorn_arg=123,
        )


# ==============================================================================
# Part D: Explicit ASGI3 Interface, Zero-Arg Probe & Dispatch (Tests 28-35)
# ==============================================================================


def test_28_verified_config_sets_explicit_asgi3_and_version_3_0() -> None:
    settings = _make_prod_settings()
    cfg = build_uvicorn_config(settings)
    cfg_explicit = VerifiedUvicornConfig(
        create_app(settings), settings=settings, interface="asgi3"
    )
    assert cfg.interface == "asgi3"
    assert cfg.asgi_version == "3.0"
    assert cfg_explicit.interface == "asgi3"
    assert cfg_explicit.asgi_version == "3.0"


def test_29_invalid_or_overridden_interface_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _make_prod_settings()
    for bad_iface in ("auto", "asgi2", "wsgi"):
        with pytest.raises(RuntimeError, match="Invalid interface override"):
            build_uvicorn_config(settings, interface=bad_iface)
        with pytest.raises(RuntimeError, match="Invalid interface override"):
            VerifiedUvicornConfig(create_app(settings), settings=settings, interface=bad_iface)

    _set_prod_env(monkeypatch)
    for cli_iface in ("asgi2", "auto"):
        with pytest.raises(RuntimeError, match="Invalid interface override"):
            server_cli_main(["--interface", cli_iface])

    for env_iface in ("asgi2", "auto"):
        monkeypatch.setenv("UVICORN_INTERFACE", env_iface)
        with pytest.raises(RuntimeError, match="UVICORN_INTERFACE"):
            build_uvicorn_config(settings)

    monkeypatch.delenv("UVICORN_INTERFACE", raising=False)

    # Mutate pre-load
    cfg = build_uvicorn_config(settings)
    cfg.interface = "auto"
    with pytest.raises(RuntimeError, match="interface='asgi3'"):
        cfg.load()

    # Mutate post-load
    cfg2 = build_uvicorn_config(settings)
    cfg2.load()
    app2 = _unwrap_app(cfg2)
    cfg2.interface = "asgi2"
    with pytest.raises(RuntimeError, match="interface='asgi3'"):
        verify_production_asgi_trust_boundary(app2, settings)


def test_30_zero_arg_probe_and_asgi3_coroutine_identity() -> None:
    prod_settings = _make_prod_settings()
    dev_settings = Settings(_env_file=None, ENVIRONMENT="development")
    prod_app = create_app(prod_settings)
    dev_app = create_app(dev_settings)

    with pytest.raises(RuntimeError, match="Unverified Uvicorn Config.load"):
        prod_app()

    with pytest.raises(TypeError, match="not a factory"):
        dev_app()

    cfg = VerifiedUvicornConfig(prod_app, settings=prod_settings)
    token = _ACTIVE_VERIFIED_CONFIG_LOAD.set(cfg)
    try:
        with pytest.raises(TypeError, match="not a factory"):
            prod_app()
    finally:
        _ACTIVE_VERIFIED_CONFIG_LOAD.reset(token)

    with pytest.raises(TypeError, match="ASGI3"):
        prod_app({"type": "http"})

    assert inspect.iscoroutinefunction(prod_app.__call__) is True
    assert asyncio.iscoroutinefunction(prod_app.__call__) is True
    assert uvicorn_compat.iscoroutinefunction(prod_app.__call__) is True
    assert _is_asgi3(prod_app) is True


def test_31_loaded_app_never_wrapped_in_asgi2_wsgi_or_message_logger() -> None:
    for proxy_enabled, ips in ((False, []), (True, ["10.0.0.1"])):
        settings = _make_prod_settings(
            proxy_headers_enabled=proxy_enabled,
            trusted_proxy_ips=ips,
        )
        cfg = build_uvicorn_config(settings)
        cfg.load()
        assert isinstance(cfg.loaded_app, ASGI2Middleware) is False
        inner = _unwrap_app(cfg)
        assert isinstance(inner, Folio360FastAPI)

        policy = cfg._expected_proxy_policy
        with pytest.raises(RuntimeError, match="Forbidden ASGI2Middleware"):
            verify_loaded_asgi_middleware(ASGI2Middleware(inner), inner, policy)
        with pytest.raises(RuntimeError, match="Forbidden ASGI2Middleware"):
            verify_loaded_asgi_middleware(WSGIMiddleware(inner), inner, policy)
        with pytest.raises(RuntimeError, match="Forbidden ASGI2Middleware"):
            verify_loaded_asgi_middleware(MessageLoggerMiddleware(inner), inner, policy)


def test_32_proxy_enabled_retains_direct_proxy_middleware_to_folio360fastapi() -> None:
    settings = _make_prod_settings(
        proxy_headers_enabled=True,
        trusted_proxy_ips=["10.0.0.1"],
    )
    cfg = build_uvicorn_config(settings)
    cfg.load()
    app = _test_startup_and_teardown(cfg)
    assert isinstance(cfg.loaded_app, ProxyHeadersMiddleware)
    assert cfg.loaded_app.app is app
    assert isinstance(app, Folio360FastAPI)


def test_33_proxy_disabled_retains_direct_folio360fastapi() -> None:
    settings = _make_prod_settings(proxy_headers_enabled=False, trusted_proxy_ips=[])
    cfg = build_uvicorn_config(settings)
    cfg.load()
    app = _test_startup_and_teardown(cfg)
    assert isinstance(cfg.loaded_app, Folio360FastAPI)
    assert not isinstance(cfg.loaded_app, (ProxyHeadersMiddleware, ASGI2Middleware))
    assert cfg.loaded_app is app


def test_34_http_and_websocket_asgi3_dispatch_and_unverified_ws_fail_closed() -> None:
    from fastapi import WebSocket

    for proxy_enabled, ips in ((True, ["10.0.0.1"]), (False, [])):
        settings = _make_prod_settings(
            proxy_headers_enabled=proxy_enabled,
            trusted_proxy_ips=ips,
        )
        cfg = build_uvicorn_config(settings)
        cfg.load()
        app = _unwrap_app(cfg)

        @app.websocket("/_ws-test")
        async def _ws_echo(websocket: WebSocket) -> None:
            await websocket.accept()
            text_msg = await websocket.receive_text()
            await websocket.send_text(text_msg)
            await websocket.close()

        async def _exercise_http_and_ws():
            async with _started_lifespan(cfg):
                # (a) HTTP ASGI3 scope
                http_msgs: list[dict[str, Any]] = []
                http_scope = {
                    "type": "http",
                    "asgi": {"version": "3.0"},
                    "http_version": "1.1",
                    "method": "GET",
                    "scheme": "http",
                    "path": "/api/v1/health",
                    "raw_path": b"/api/v1/health",
                    "query_string": b"",
                    "headers": [
                        (b"host", b"app.folio360.com"),
                        (b"x-forwarded-for", b"203.0.113.55"),
                        (b"x-forwarded-proto", b"https"),
                    ],
                    "client": ("10.0.0.1", 50000),
                    "server": ("127.0.0.1", 8000),
                }

                async def http_receive():
                    return {"type": "http.request", "body": b"", "more_body": False}

                async def http_send(msg):
                    http_msgs.append(msg)

                http_ret = await cfg.loaded_app(http_scope, http_receive, http_send)
                assert http_ret is None
                assert http_msgs[0]["status"] == 200
                if proxy_enabled:
                    assert http_scope["client"][0] == "203.0.113.55"
                    assert http_scope["scheme"] == "https"
                else:
                    assert http_scope["client"][0] == "10.0.0.1"

                # (b) WebSocket ASGI3 scope
                ws_sent: list[dict[str, Any]] = []
                ws_incoming = iter(
                    [
                        {"type": "websocket.connect"},
                        {"type": "websocket.receive", "text": "ping"},
                        {"type": "websocket.disconnect", "code": 1000},
                    ]
                )
                ws_scope = {
                    "type": "websocket",
                    "asgi": {"version": "3.0"},
                    "scheme": "ws",
                    "path": "/_ws-test",
                    "raw_path": b"/_ws-test",
                    "query_string": b"",
                    "headers": [(b"host", b"app.folio360.com")],
                    "client": ("10.0.0.1", 50001),
                    "server": ("127.0.0.1", 8000),
                }

                async def ws_receive():
                    return next(ws_incoming)

                async def ws_send(msg):
                    ws_sent.append(msg)

                ws_ret = await cfg.loaded_app(ws_scope, ws_receive, ws_send)
                assert ws_ret is None
                assert any(m["type"] == "websocket.accept" for m in ws_sent)
                assert any(
                    m["type"] == "websocket.send" and m.get("text") == "ping"
                    for m in ws_sent
                )

        asyncio.run(_exercise_http_and_ws())

    # (c) Unverified production WebSocket scope fails closed at _dispatch_asgi
    unverified_prod_app = create_app(_make_prod_settings())

    async def _unverified_ws():
        await unverified_prod_app(
            {
                "type": "websocket",
                "asgi": {"version": "3.0"},
                "path": "/_ws-test",
                "headers": [],
            },
            lambda: None,
            lambda _m: None,
        )

    with pytest.raises(RuntimeError, match="VerifiedUvicornConfig lifespan verification"):
        asyncio.run(_unverified_ws())


@pytest.mark.parametrize("interface_mode", ["auto", "asgi2", "asgi3", "wsgi"])
@pytest.mark.parametrize("lifespan_mode", ["auto", "on", "off"])
def test_35_raw_uvicorn_startup_rejected_across_all_interface_and_lifespan_modes(
    monkeypatch: pytest.MonkeyPatch,
    interface_mode: str,
    lifespan_mode: str,
) -> None:
    _set_prod_env(monkeypatch)
    prod_settings = _make_prod_settings()

    factory_cfg = uvicorn.Config(
        "app.main:create_app",
        factory=True,
        interface=interface_mode,  # type: ignore[arg-type]
        lifespan=lifespan_mode,  # type: ignore[arg-type]
    )
    with pytest.raises(RuntimeError, match="Unverified Uvicorn Config"):
        factory_cfg.load()

    instance_cfg = uvicorn.Config(
        create_app(prod_settings),
        interface=interface_mode,  # type: ignore[arg-type]
        lifespan=lifespan_mode,  # type: ignore[arg-type]
    )
    with pytest.raises(RuntimeError, match="Unverified Uvicorn Config"):
        instance_cfg.load()
