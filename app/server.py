"""Authoritative Uvicorn ASGI3, proxy-header, and lifespan trust-boundary launcher (Rev10 §19)."""

import argparse
from contextvars import ContextVar
from dataclasses import dataclass
import ipaddress
import os
import sys
from typing import TYPE_CHECKING, Any, Callable, Mapping, Sequence
import weakref

from fastapi import FastAPI
import uvicorn
from uvicorn._compat import iscoroutinefunction as uvicorn_iscoroutinefunction
from uvicorn._types import ASGIApplication
from uvicorn.config import InterfaceType, LifespanType
from uvicorn.lifespan.on import LifespanOn
from uvicorn.middleware.asgi2 import ASGI2Middleware
from uvicorn.middleware.message_logger import MessageLoggerMiddleware
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
from uvicorn.middleware.wsgi import WSGIMiddleware

from app.core.config import Settings, get_settings

if TYPE_CHECKING:
    from app.main import Folio360FastAPI

_UNSET = object()
_ACTIVE_VERIFIED_CONFIG_LOAD: ContextVar["VerifiedUvicornConfig | None"] = ContextVar(
    "_ACTIVE_VERIFIED_CONFIG_LOAD",
    default=None,
)


@dataclass(frozen=True)
class VerifiedProxyPolicy:
    """Immutable, picklable proxy and ASGI trust policy derived from Settings."""

    proxy_headers: bool
    trusted_proxy_ips: tuple[str, ...]
    forwarded_allow_ips_csv: str


@dataclass
class _VerifiedBindingRecord:
    """Process-local weakref binding between a Folio360FastAPI instance and VerifiedUvicornConfig."""

    app_id: int
    pid: int
    app_ref: weakref.ReferenceType[Any]
    config_ref: weakref.ReferenceType["VerifiedUvicornConfig"]
    loaded_app_ref: weakref.ReferenceType[Any]
    policy: VerifiedProxyPolicy
    lifespan_verified: bool = False


_VERIFIED_APP_REGISTRY: dict[int, _VerifiedBindingRecord] = {}


def _parse_and_validate_proxy_ips(
    entries: Sequence[str],
    *,
    proxy_headers_enabled: bool,
) -> list[str]:
    """Validate explicit proxy IP/CIDR entries and reject wildcards, hostnames, or blanks."""
    canonical_ips: list[str] = []
    seen: set[str] = set()

    for raw_entry in entries:
        if not isinstance(raw_entry, str):
            raise RuntimeError("Proxy IP entries must be strings.")
        entry = raw_entry.strip()
        if not entry or entry == "*":
            raise RuntimeError("Trusted proxy IPs must not be empty or contain wildcard '*'.")
        try:
            if "/" in entry:
                normalized = str(ipaddress.ip_network(entry, strict=False))
            else:
                normalized = str(ipaddress.ip_address(entry))
        except ValueError as exc:
            raise RuntimeError(
                f"Trusted proxy entry {entry!r} is not a valid IP address or CIDR network."
            ) from exc

        if normalized not in seen:
            seen.add(normalized)
            canonical_ips.append(normalized)

    if not proxy_headers_enabled and canonical_ips:
        raise RuntimeError(
            "TRUSTED_PROXY_IPS must be empty when PROXY_HEADERS_ENABLED is False."
        )
    if proxy_headers_enabled and not canonical_ips:
        raise RuntimeError(
            "TRUSTED_PROXY_IPS must be configured when PROXY_HEADERS_ENABLED is True."
        )
    return canonical_ips


def normalize_forwarded_allow_ips_override(
    raw_override: list[str] | str | None,
    *,
    proxy_headers_enabled: bool,
) -> str:
    """Validate and canonicalize an explicit forwarded_allow_ips override."""
    entries: list[str]
    if raw_override is None:
        if proxy_headers_enabled:
            raise RuntimeError(
                "forwarded_allow_ips cannot be None when PROXY_HEADERS_ENABLED is True."
            )
        entries = []
    elif isinstance(raw_override, str):
        stripped = raw_override.strip()
        if not stripped:
            entries = []
        else:
            parts = [part.strip() for part in stripped.split(",")]
            if any(not part for part in parts):
                raise RuntimeError("forwarded_allow_ips contains an empty entry.")
            entries = parts
    elif isinstance(raw_override, (list, tuple)):
        entries = []
        for item in raw_override:
            if not isinstance(item, str) or not item.strip():
                raise RuntimeError("forwarded_allow_ips list entries must be non-empty strings.")
            entries.append(item.strip())
    else:
        raise RuntimeError(
            f"forwarded_allow_ips must be str, list[str], or None, got {type(raw_override).__name__}."
        )

    canonical_ips = _parse_and_validate_proxy_ips(
        entries,
        proxy_headers_enabled=proxy_headers_enabled,
    )
    return ",".join(canonical_ips)


def _parse_env_bool(value: str, *, var_name: str) -> bool:
    lowered = value.strip().lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    raise RuntimeError(f"Invalid boolean value in {var_name}.")


def validate_proxy_policy(
    settings: Settings,
    environ: Mapping[str, str],
) -> VerifiedProxyPolicy:
    """
    Concept 1: Validate Settings proxy/lifespan/interface policy and ambient Uvicorn env vars.
    """
    if "UVICORN_LIFESPAN" in environ:
        if environ["UVICORN_LIFESPAN"].strip() != "on":
            raise RuntimeError(
                f"Invalid UVICORN_LIFESPAN={environ['UVICORN_LIFESPAN']!r}: must be 'on'."
            )

    if "UVICORN_INTERFACE" in environ:
        if environ["UVICORN_INTERFACE"].strip() != "asgi3":
            raise RuntimeError(
                f"Invalid UVICORN_INTERFACE={environ['UVICORN_INTERFACE']!r}: must be 'asgi3'."
            )

    if type(settings.PROXY_HEADERS_ENABLED) is not bool:
        raise RuntimeError("PROXY_HEADERS_ENABLED must be a boolean.")

    canonical_ips = _parse_and_validate_proxy_ips(
        settings.TRUSTED_PROXY_IPS,
        proxy_headers_enabled=settings.PROXY_HEADERS_ENABLED,
    )
    forwarded_allow_ips_csv = ",".join(canonical_ips)

    if "UVICORN_PROXY_HEADERS" in environ:
        env_proxy_headers = _parse_env_bool(
            environ["UVICORN_PROXY_HEADERS"],
            var_name="UVICORN_PROXY_HEADERS",
        )
        if env_proxy_headers != settings.PROXY_HEADERS_ENABLED:
            raise RuntimeError(
                "UVICORN_PROXY_HEADERS conflicts with Settings.PROXY_HEADERS_ENABLED."
            )

    for env_key in ("FORWARDED_ALLOW_IPS", "UVICORN_FORWARDED_ALLOW_IPS"):
        if env_key in environ:
            env_csv = normalize_forwarded_allow_ips_override(
                environ[env_key],
                proxy_headers_enabled=settings.PROXY_HEADERS_ENABLED,
            )
            if env_csv != forwarded_allow_ips_csv:
                raise RuntimeError(
                    f"{env_key} conflicts with Settings.TRUSTED_PROXY_IPS."
                )

    return VerifiedProxyPolicy(
        proxy_headers=settings.PROXY_HEADERS_ENABLED,
        trusted_proxy_ips=tuple(canonical_ips),
        forwarded_allow_ips_csv=forwarded_allow_ips_csv,
    )


def validate_effective_uvicorn_config(
    config: uvicorn.Config,
    policy: VerifiedProxyPolicy,
) -> None:
    """
    Concept 2: Validate live Uvicorn Config attributes including lifespan='on' and interface='asgi3'.
    """
    if not isinstance(config, VerifiedUvicornConfig):
        raise RuntimeError(
            f"Unverified Uvicorn Config type {type(config).__name__}; expected VerifiedUvicornConfig."
        )
    if type(config.proxy_headers) is not bool or config.proxy_headers != policy.proxy_headers:
        raise RuntimeError(
            f"Effective Uvicorn config proxy_headers={config.proxy_headers!r} does not match policy {policy.proxy_headers!r}."
        )
    if config.forwarded_allow_ips != policy.forwarded_allow_ips_csv:
        raise RuntimeError(
            "Effective Uvicorn config forwarded_allow_ips does not match canonical Settings.TRUSTED_PROXY_IPS."
        )
    if config.lifespan != "on":
        raise RuntimeError("Effective Uvicorn config must have lifespan='on'.")
    if config.interface != "asgi3":
        raise RuntimeError("Effective Uvicorn config must have interface='asgi3'.")
    if config.asgi_version != "3.0":
        raise RuntimeError("Effective Uvicorn asgi_version must be '3.0'.")
    if config.loaded and getattr(config, "lifespan_class", None) is not LifespanOn:
        raise RuntimeError("Effective Uvicorn config must select LifespanOn.")


def verify_loaded_asgi_middleware(
    loaded_app: Any,
    fastapi_app: Any,
    policy: VerifiedProxyPolicy,
) -> None:
    """
    Concept 3: Verify post-load ASGI3 dispatch chain, coroutine identity, and _TrustedHosts internals.
    """
    from app.main import Folio360FastAPI

    forbidden = (ASGI2Middleware, WSGIMiddleware, MessageLoggerMiddleware)
    if isinstance(loaded_app, forbidden) or isinstance(fastapi_app, forbidden):
        raise RuntimeError(
            "Forbidden ASGI2Middleware, WSGIMiddleware, or MessageLoggerMiddleware detected in loaded app."
        )

    if not isinstance(fastapi_app, Folio360FastAPI):
        raise RuntimeError(
            f"Expected Folio360FastAPI instance, got {type(fastapi_app).__name__}."
        )

    if uvicorn_iscoroutinefunction(getattr(fastapi_app, "__call__", None)) is not True:
        raise RuntimeError("Folio360FastAPI.__call__ must be recognized as an ASGI3 coroutine function.")

    if policy.proxy_headers:
        if not isinstance(loaded_app, ProxyHeadersMiddleware):
            raise RuntimeError(
                "Expected outer ProxyHeadersMiddleware when PROXY_HEADERS_ENABLED is True."
            )
        if loaded_app.app is not fastapi_app:
            raise RuntimeError(
                "ProxyHeadersMiddleware must directly wrap the Folio360FastAPI instance."
            )

        trusted = loaded_app.trusted_hosts
        if trusted.always_trust is not False:
            raise RuntimeError("ProxyHeadersMiddleware always_trust must be False.")
        if trusted.trusted_literals != set():
            raise RuntimeError("ProxyHeadersMiddleware trusted_literals must be empty.")

        expected_hosts: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        expected_networks: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
        for entry in policy.trusted_proxy_ips:
            if "/" in entry:
                expected_networks.add(ipaddress.ip_network(entry, strict=False))
            else:
                expected_hosts.add(ipaddress.ip_address(entry))

        if trusted.trusted_hosts != expected_hosts or trusted.trusted_networks != expected_networks:
            raise RuntimeError(
                "ProxyHeadersMiddleware trusted_hosts/trusted_networks do not match verified policy."
            )
    else:
        if isinstance(loaded_app, ProxyHeadersMiddleware) or loaded_app is not fastapi_app:
            raise RuntimeError(
                "Expected direct Folio360FastAPI dispatch without ProxyHeadersMiddleware when PROXY_HEADERS_ENABLED is False."
            )


class VerifiedUvicornConfig(uvicorn.Config):
    """Hardened uvicorn.Config subclass enforcing ASGI3, LifespanOn, and proxy trust invariants."""

    def __init__(
        self,
        app: ASGIApplication | Callable[..., Any] | str,
        *,
        settings: Settings | None = None,
        proxy_headers: bool | object = _UNSET,
        forwarded_allow_ips: list[str] | str | None | object = _UNSET,
        lifespan: LifespanType | object = _UNSET,
        interface: InterfaceType | object = _UNSET,
        **kwargs: Any,
    ) -> None:
        effective_settings = settings or (
            getattr(app.state, "settings", None) if isinstance(app, FastAPI) else get_settings()
        )
        policy = validate_proxy_policy(effective_settings, os.environ)

        if proxy_headers is not _UNSET:
            if type(proxy_headers) is not bool or proxy_headers != policy.proxy_headers:
                raise RuntimeError(
                    f"Conflicting proxy_headers override: expected {policy.proxy_headers!r} "
                    "matching Settings.PROXY_HEADERS_ENABLED."
                )

        if forwarded_allow_ips is not _UNSET:
            normalized_override = normalize_forwarded_allow_ips_override(
                forwarded_allow_ips,  # type: ignore[arg-type]
                proxy_headers_enabled=policy.proxy_headers,
            )
            if normalized_override != policy.forwarded_allow_ips_csv:
                raise RuntimeError(
                    "Conflicting forwarded_allow_ips override: must match canonical "
                    "Settings.TRUSTED_PROXY_IPS."
                )

        if lifespan is not _UNSET and lifespan != "on":
            raise RuntimeError(
                f"Invalid lifespan override {lifespan!r}: production configuration requires lifespan='on'."
            )

        if interface is not _UNSET and interface != "asgi3":
            raise RuntimeError(
                f"Invalid interface override {interface!r}: production configuration requires interface='asgi3'."
            )

        self._expected_proxy_policy = policy
        self._bound_settings: Settings | None = settings

        super().__init__(
            app,
            proxy_headers=policy.proxy_headers,
            forwarded_allow_ips=policy.forwarded_allow_ips_csv,
            lifespan="on",
            interface="asgi3",
            **kwargs,
        )
        validate_effective_uvicorn_config(self, policy)

    def load(self) -> None:
        from app.main import Folio360FastAPI

        validate_effective_uvicorn_config(self, self._expected_proxy_policy)

        token = _ACTIVE_VERIFIED_CONFIG_LOAD.set(self)
        try:
            super().load()
        finally:
            _ACTIVE_VERIFIED_CONFIG_LOAD.reset(token)

        if isinstance(self.loaded_app, (ASGI2Middleware, WSGIMiddleware, MessageLoggerMiddleware)):
            raise RuntimeError(
                f"Forbidden middleware wrapper {type(self.loaded_app).__name__} detected after load."
            )

        if isinstance(self.loaded_app, ProxyHeadersMiddleware):
            fastapi_app = self.loaded_app.app
        else:
            fastapi_app = self.loaded_app

        if not isinstance(fastapi_app, Folio360FastAPI):
            raise RuntimeError(
                f"Expected inner ASGI3 application to be Folio360FastAPI, got {type(fastapi_app).__name__}."
            )

        app_settings: Settings = getattr(fastapi_app.state, "settings", None) or get_settings()
        policy = validate_proxy_policy(app_settings, os.environ)
        if policy != self._expected_proxy_policy:
            raise RuntimeError("Worker proxy policy drifted from parent VerifiedUvicornConfig policy.")

        validate_effective_uvicorn_config(self, policy)
        verify_loaded_asgi_middleware(self.loaded_app, fastapi_app, policy)

        _VERIFIED_APP_REGISTRY[id(fastapi_app)] = _VerifiedBindingRecord(
            app_id=id(fastapi_app),
            pid=os.getpid(),
            app_ref=weakref.ref(fastapi_app),
            config_ref=weakref.ref(self),
            loaded_app_ref=weakref.ref(self.loaded_app),
            policy=policy,
            lifespan_verified=False,
        )


def verify_production_asgi_trust_boundary(app: FastAPI, settings: Settings) -> None:
    """
    Live lifespan re-verification of all three trust-boundary concepts (Rev10 §19.3).
    """
    current_policy = validate_proxy_policy(settings, os.environ)

    if settings.ENVIRONMENT != "production":
        return

    record = _VERIFIED_APP_REGISTRY.get(id(app))
    if record is None or record.pid != os.getpid() or record.app_ref() is not app:
        raise RuntimeError(
            "Unverified ASGI startup rejected in production: missing valid VerifiedUvicornConfig binding."
        )

    live_config = record.config_ref()
    live_loaded_app = record.loaded_app_ref()
    if (
        live_config is None
        or live_loaded_app is None
        or not live_config.loaded
        or live_config.loaded_app is not live_loaded_app
    ):
        raise RuntimeError(
            "Unverified ASGI startup rejected in production: live config or loaded_app reference invalid."
        )

    if current_policy != record.policy:
        raise RuntimeError("Production proxy policy drifted between load() and lifespan().")

    validate_effective_uvicorn_config(live_config, current_policy)
    verify_loaded_asgi_middleware(live_loaded_app, app, current_policy)
    record.lifespan_verified = True


def assert_production_lifespan_verified(app: FastAPI) -> None:
    """Fail closed at ASGI request entry if production lifespan verification did not complete."""
    record = _VERIFIED_APP_REGISTRY.get(id(app))
    if (
        record is None
        or record.pid != os.getpid()
        or record.app_ref() is not app
        or record.lifespan_verified is not True
    ):
        raise RuntimeError(
            "Production ASGI request rejected: application has not completed VerifiedUvicornConfig lifespan verification."
        )


def build_uvicorn_config(
    settings: Settings | None = None,
    *,
    app: ASGIApplication | Callable[..., Any] | str | None = None,
    factory: bool | None = None,
    **kwargs: Any,
) -> VerifiedUvicornConfig:
    """Construct a VerifiedUvicornConfig bound to Folio360FastAPI or factory import string."""
    effective_settings = settings or get_settings()
    workers = kwargs.get("workers")

    target_app: ASGIApplication | Callable[..., Any] | str
    effective_factory: bool
    if app is not None:
        target_app = app
        effective_factory = bool(factory) if factory is not None else False
    elif workers is not None and int(workers) > 1:
        target_app = "app.main:create_app"
        effective_factory = True
    else:
        from app.main import create_app

        target_app = create_app(effective_settings)
        effective_factory = False

    return VerifiedUvicornConfig(
        target_app,
        settings=effective_settings,
        factory=effective_factory,
        **kwargs,
    )


def run_server(
    settings: Settings | None = None,
    **kwargs: Any,
) -> None:
    """Build VerifiedUvicornConfig and run uvicorn.Server synchronously."""
    config = build_uvicorn_config(settings=settings, **kwargs)
    server = uvicorn.Server(config)
    server.run()


def _build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.server",
        description="Run Folio360 backend with VerifiedUvicornConfig ASGI3 security boundary.",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--workers", type=int, default=None)
    parser.add_argument("--log-level", default=None)
    parser.add_argument("--lifespan", default=_UNSET)
    parser.add_argument("--interface", default=_UNSET)
    parser.add_argument(
        "--proxy-headers",
        action=argparse.BooleanOptionalAction,
        default=_UNSET,
    )
    parser.add_argument("--forwarded-allow-ips", default=_UNSET)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for `python -m app.server`."""
    parser = _build_cli_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    settings = get_settings()

    kwargs: dict[str, Any] = {
        "host": args.host,
        "port": args.port,
    }
    if args.workers is not None:
        kwargs["workers"] = args.workers
    if args.log_level is not None:
        kwargs["log_level"] = args.log_level
    if args.lifespan is not _UNSET:
        kwargs["lifespan"] = args.lifespan
    if args.interface is not _UNSET:
        kwargs["interface"] = args.interface
    if args.proxy_headers is not _UNSET:
        kwargs["proxy_headers"] = args.proxy_headers
    if args.forwarded_allow_ips is not _UNSET:
        kwargs["forwarded_allow_ips"] = args.forwarded_allow_ips

    target_app = "app.main:create_app"
    run_server(settings=settings, app=target_app, factory=True, **kwargs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
