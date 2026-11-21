"""Tests for Rev10 §10.2.C & §20.4 environment-policy URI validation and 4-gate parity."""

from pydantic import ValidationError
import pytest

from app.core.config import Settings
from app.core.uri_policy import (
    canonicalize_mobile_login_allowlist,
    match_mobile_login_uri,
    parse_and_canonicalize_mobile_login_uri,
    validate_app_environment,
    validate_frontend_backend_parity,
)


@pytest.mark.parametrize("env", ["development", "testing", "production"])
def test_https_universal_app_link_accepted_in_all_environments(env: str) -> None:
    parsed = parse_and_canonicalize_mobile_login_uri(
        "HTTPS://App.Folio360.COM/login",
        environment=env,
    )
    assert parsed.canonical == "https://app.folio360.com/login"
    assert parsed.as_tuple == ("https", "app.folio360.com", None, "/login")

    matched = match_mobile_login_uri(
        "https://app.folio360.com/login",
        ["https://app.folio360.com/login"],
        environment=env,
    )
    assert matched == "https://app.folio360.com/login"


@pytest.mark.parametrize("env", ["development", "testing", "production"])
def test_explicit_custom_scheme_accepted_only_when_allowlisted(env: str) -> None:
    parsed = parse_and_canonicalize_mobile_login_uri(
        "folio360://auth/login",
        environment=env,
    )
    assert parsed.canonical == "folio360://auth/login"
    assert (
        match_mobile_login_uri(
            "folio360://auth/login",
            ["folio360://auth/login"],
            environment=env,
        )
        == "folio360://auth/login"
    )
    assert (
        match_mobile_login_uri(
            "myapp://auth/login",
            ["folio360://auth/login"],
            environment=env,
        )
        is None
    )


@pytest.mark.parametrize("env", ["development", "testing", "production"])
@pytest.mark.parametrize(
    "malicious_uri",
    [
        "javascript:alert(1)",
        "javascript://alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "vbscript:msgbox(1)",
        "file:///etc/passwd",
        "blob:https://app.folio360.com/123",
        "about:blank",
        "intent://scan/#Intent;scheme=zxing;end",
        "mailto:user@example.com",
        "tel:+1234567890",
        "ftp://files.folio360.com/login",
    ],
)
def test_dangerous_and_unsupported_schemes_rejected_everywhere(
    env: str,
    malicious_uri: str,
) -> None:
    with pytest.raises(ValueError):
        parse_and_canonicalize_mobile_login_uri(malicious_uri, environment=env)
    assert (
        match_mobile_login_uri(
            malicious_uri,
            ["https://app.folio360.com/login", "folio360://auth/login"],
            environment=env,
        )
        is None
    )


@pytest.mark.parametrize(
    "loopback_uri",
    [
        "http://localhost:5173/login",
        "http://127.0.0.1:8081/login",
        "http://[::1]:5173/login",
        "http://[0:0:0:0:0:0:0:1]:5173/login",
    ],
)
def test_production_unconditionally_rejects_all_http_including_loopback(
    loopback_uri: str,
) -> None:
    with pytest.raises(ValueError, match="production"):
        parse_and_canonicalize_mobile_login_uri(loopback_uri, environment="production")

    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            ENVIRONMENT="production",
            EMAIL_VERIFICATION_MOBILE_LOGIN_URIS=[loopback_uri],
        )

    with pytest.raises(ValueError):
        validate_frontend_backend_parity(
            backend_environment="production",
            frontend_environment="production",
            backend_uris=[loopback_uri],
            frontend_uris=[loopback_uri],
        )


@pytest.mark.parametrize("env", ["development", "testing"])
def test_dev_and_testing_accept_explicit_loopback_http_with_canonical_ipv6(
    env: str,
) -> None:
    assert (
        parse_and_canonicalize_mobile_login_uri(
            "http://localhost:5173/login",
            environment=env,
        ).canonical
        == "http://localhost:5173/login"
    )
    assert (
        parse_and_canonicalize_mobile_login_uri(
            "http://127.0.0.1:8081/login",
            environment=env,
        ).canonical
        == "http://127.0.0.1:8081/login"
    )
    ipv6_parsed = parse_and_canonicalize_mobile_login_uri(
        "http://[0:0:0:0:0:0:0:1]:5173/login",
        environment=env,
    )
    assert ipv6_parsed.host == "[::1]"
    assert ipv6_parsed.canonical == "http://[::1]:5173/login"


@pytest.mark.parametrize("env", ["development", "testing", "production"])
@pytest.mark.parametrize(
    "external_http",
    [
        "http://example.com/login",
        "http://evil.test/login",
        "http://app.folio360.com/login",
        "http://8.8.8.8/login",
        "http://10.0.0.1/login",
    ],
)
def test_external_http_rejected_in_all_environments(
    env: str,
    external_http: str,
) -> None:
    with pytest.raises(ValueError):
        parse_and_canonicalize_mobile_login_uri(external_http, environment=env)


@pytest.mark.parametrize(
    "bad_uri",
    [
        "",
        "   ",
        " https://app.folio360.com/login",
        "https://app.folio360.com/login ",
        "https://app.folio360.com/lo gin",
        "https://app.folio360.com/login\n",
        "https://app.folio360.com/login\x00",
        "https://app.folio360.com:443/login",
        "http://localhost:80/login",
        "http://[::1]:80/login",
        "https://[::1]:443/login",
        "folio360://auth:8080/login",
        "https://app.folio360.com/login/",
        "https://app.folio360.com",
        "https://app.folio360.com/login?next=/home",
        "https://app.folio360.com/login?",
        "https://app.folio360.com/login#frag",
        "https://app.folio360.com/login#",
        "https://user@app.folio360.com/login",
        "https://user:pass@app.folio360.com/login",
        "https://app.folio360.com/login\\evil",
        "https://*.folio360.com/login",
        "https://app.folio360.com//login",
        "https://app.folio360.com/./login",
        "https://app.folio360.com/../login",
        "https://app.folio360.com/login/%2f",
        "https://app.folio360.com/login/%5C",
        "https://app.folio360.com/login/%2e",
        "https://app.folio360.com/login/%00",
        "https://xn--app-000.folio360.com/login",
        "https://app.fólìo360.com/login",
        "https://app.folio360.com:/login",
    ],
)
def test_malformed_traversal_default_port_and_noncanonical_uris_rejected(
    bad_uri: str,
) -> None:
    with pytest.raises(ValueError):
        parse_and_canonicalize_mobile_login_uri(bad_uri, environment="development")


@pytest.mark.parametrize(
    "bad_env",
    [None, "", " ", "PROD", "Production", "Development", "staging", "preview", "local", 123],
)
def test_closed_enum_environment_validation_fails_closed(bad_env: object) -> None:
    with pytest.raises(ValueError):
        validate_app_environment(bad_env, field_name="VITE_APP_ENVIRONMENT")


@pytest.mark.parametrize(
    ("env", "uris"),
    [
        ("development", ["http://localhost:5173/login", "folio360://auth/login"]),
        ("testing", ["http://[::1]:5173/login", "https://staging.folio360.com/login"]),
        ("production", ["https://app.folio360.com/login", "folio360://auth/login"]),
    ],
)
def test_parity_succeeds_for_all_three_matching_environments(
    env: str,
    uris: list[str],
) -> None:
    canonical = validate_frontend_backend_parity(
        backend_environment=env,
        frontend_environment=env,
        backend_uris=uris,
        frontend_uris=list(reversed(uris)),
    )
    assert set(canonical) == set(canonicalize_mobile_login_allowlist(uris, environment=env))


def test_parity_succeeds_with_ipv6_canonicalization() -> None:
    canonical = validate_frontend_backend_parity(
        backend_environment="development",
        frontend_environment="development",
        backend_uris=["http://[0:0:0:0:0:0:0:1]:5173/login"],
        frontend_uris=["http://[::1]:5173/login"],
    )
    assert canonical == ["http://[::1]:5173/login"]


@pytest.mark.parametrize(
    ("backend_env", "frontend_env"),
    [
        ("development", "production"),
        ("testing", "production"),
        ("development", "testing"),
        ("production", "development"),
    ],
)
def test_parity_fails_on_environment_mismatch(
    backend_env: str,
    frontend_env: str,
) -> None:
    with pytest.raises(ValueError, match="Environment parity mismatch"):
        validate_frontend_backend_parity(
            backend_environment=backend_env,
            frontend_environment=frontend_env,
            backend_uris=["https://app.folio360.com/login"],
            frontend_uris=["https://app.folio360.com/login"],
        )


def test_parity_fails_on_allowlist_mismatch() -> None:
    with pytest.raises(ValueError, match="Canonical allowlist parity mismatch"):
        validate_frontend_backend_parity(
            backend_environment="production",
            frontend_environment="production",
            backend_uris=["https://app.folio360.com/login"],
            frontend_uris=["https://app.folio360.com/login", "folio360://auth/login"],
        )
