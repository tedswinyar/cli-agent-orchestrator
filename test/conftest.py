"""Top-level pytest configuration.

Sets process-wide env vars that disable optional v2.5 listeners so the
existing test suite (and CI) doesn't have to coordinate around real
port bindings or filesystem writes.

These knobs match how the lifespan reads them at runtime — see
``api/main.py``. Each is opt-out: the default is "feature on" in
production; tests flip them off.

Also exposes shared security fixtures (RSA keys, JWKS stub,
``AUTH0_*`` env, JWT mint helper) for tests outside ``test/security/``
that need to exercise the Auth0 paths.
"""

import os
import pathlib
import time
from typing import Any, Dict
from unittest.mock import patch

import pytest

# Make the `mock_cli` test-fixture binary discoverable for the pytest
# session so MockCliProvider can `shlex.join(["mock_cli", ...])` without
# an absolute path. Not on PATH outside the test session — production
# code paths never reach this binary. See docs/mock-cli-provider.md.
_MOCK_CLI_BIN_DIR = pathlib.Path(__file__).parent / "providers" / "fixtures" / "bin"
if str(_MOCK_CLI_BIN_DIR) not in os.environ.get("PATH", "").split(os.pathsep):
    os.environ["PATH"] = f"{_MOCK_CLI_BIN_DIR}{os.pathsep}{os.environ.get('PATH', '')}"


# Expose the managed-subprocess fixtures (cao_server, cao_server_with_auth,
# cao_terminal) and the shared infra fixtures (jwt_factory, jwks_server,
# terminal_factory) to every test under test/ without per-conftest imports.
#
# ``test._must_run`` is the must_run assurance gate (see that module): it turns a
# skipped or deselected assurance test into a session failure in the CI job that
# owns the gate.
pytest_plugins = (
    "test._must_run",
    "test.fixtures.cao_server",
    "test.fixtures.jwt_factory",
    "test.fixtures.jwks_server",
    "test.fixtures.terminal_factory",
)


_AUTH_TEST_DOMAIN = "test.local"
_AUTH_TEST_AUDIENCE = "cao://test"


@pytest.fixture
def rsa_keys():
    """Generate a fresh RSA-2048 keypair for the test.

    Same shape as the local fixture in ``test/security/test_auth.py``
    (which still wins locally — pytest fixture resolution prefers the
    closest definition). Lifted here so sibling test modules can mint
    their own tokens without duplicating the RSA boilerplate.
    """
    from authlib.jose import JsonWebKey
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_jwk = JsonWebKey.import_key(public_pem, {"kty": "RSA", "use": "sig", "kid": "test-kid"})
    return private_pem, public_jwk


def mint_test_token(
    private_pem: bytes,
    *,
    scopes: str = "cao:read cao:write cao:admin",
    audience: str = _AUTH_TEST_AUDIENCE,
    exp_offset: int = 300,
    iat_offset: int = 0,
) -> str:
    """Mint an RS256 JWT for tests. Mirrors test/security/test_auth.py."""
    from authlib.jose import JsonWebToken

    jwt = JsonWebToken(["RS256"])
    now = int(time.time())
    header = {"alg": "RS256", "kid": "test-kid"}
    claims: Dict[str, Any] = {
        "iss": f"https://{_AUTH_TEST_DOMAIN}/",
        "aud": audience,
        "iat": now + iat_offset,
        "exp": now + exp_offset,
        "scope": scopes,
    }
    token = jwt.encode(header, claims, private_pem)
    return token.decode("utf-8") if isinstance(token, bytes) else token


@pytest.fixture
def auth_enabled_env(monkeypatch):
    """Switch on Auth0 enforcement (AUTH0_DOMAIN + AUTH0_AUDIENCE)."""
    from cli_agent_orchestrator.security import auth as _auth_mod

    monkeypatch.setenv("AUTH0_DOMAIN", _AUTH_TEST_DOMAIN)
    monkeypatch.setenv("AUTH0_AUDIENCE", _AUTH_TEST_AUDIENCE)
    _auth_mod.reset_jwks_cache()
    yield
    _auth_mod.reset_jwks_cache()


@pytest.fixture
def mock_jwks(rsa_keys):
    """Stub the JWKS HTTP fetch with the in-process public key."""
    _, public_jwk = rsa_keys
    jwks = {"keys": [public_jwk.as_dict()]}

    class _Resp:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return jwks

    with patch("cli_agent_orchestrator.security.auth.requests.get", return_value=_Resp()):
        yield


@pytest.fixture(autouse=True)
def _no_llm_compile_in_tests(monkeypatch):
    """Default memory wiki compilation to append mode for every test.

    The production default is "llm", which drives whichever coding-agent CLI
    (claude / codex / kiro-cli) is installed on the developer's machine — each
    invocation cold-starts for tens of seconds and would make the suite both
    slow and non-hermetic. Tests that exercise the LLM path override this env
    var themselves or stub the ``wiki_compiler`` seams.
    """
    monkeypatch.setenv("CAO_MEMORY_COMPILE_MODE", "append")


@pytest.fixture(autouse=True)
def _reset_backend_registry():
    """Prevent leaked backend singletons from crossing test boundaries (fixes #522)."""
    from cli_agent_orchestrator.backends import registry

    original = registry._backend
    registry._backend = None
    yield
    registry._backend = original


@pytest.fixture(autouse=True)
def _hermetic_cao_env(monkeypatch, tmp_path):
    """Keep tests independent of CAO runtime identity and persisted settings.

    Settings reads use a fresh per-test file while ``CAO_HOME_DIR`` stays
    unchanged, so tests see documented defaults without invalidating assertions
    about the default home layout. Runtime env vars are removed before each test;
    tests can still set them explicitly after fixture setup. In particular,
    stripping ``CAO_TERMINAL_ID`` is load-bearing for vault-recall exclusion
    tests as well as sender-id defaults.
    """
    from cli_agent_orchestrator.services import settings_service

    monkeypatch.setattr(settings_service, "SETTINGS_FILE", tmp_path / "settings.json")
    monkeypatch.setattr(settings_service, "_server_settings_cache", None)
    monkeypatch.setattr(settings_service, "_server_settings_mtime_ns", -1)
    # The server lock (#406) lives beside settings.json in the real home. Every
    # in-process ``lifespan`` run would otherwise contend with a cao-server the
    # developer has running, so each test locks its own file.
    from cli_agent_orchestrator.utils import server_lock

    monkeypatch.setattr(server_lock, "SERVER_LOCK_FILE", tmp_path / "server.lock")

    # server.py defaults sender_id to "supervisor" when unset
    monkeypatch.delenv("CAO_TERMINAL_ID", raising=False)
    # security.agent_credential prefers this over the operator token (#965);
    # a suite run inside a CAO terminal must not present the host's credential.
    monkeypatch.delenv("CAO_TERMINAL_TOKEN", raising=False)
    # server.py reads these for workflow_return context detection
    monkeypatch.delenv("CAO_WORKFLOW_RUN_ID", raising=False)
    monkeypatch.delenv("CAO_WORKFLOW_STEP_ID", raising=False)
    # cli/commands/info.py uses this for session detection
    monkeypatch.delenv("CAO_SESSION_NAME", raising=False)


@pytest.fixture
def isolated_memory_db(tmp_path, monkeypatch):
    """Route default memory sessions to an initialized per-test SQLite database."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from cli_agent_orchestrator.clients import database

    engine = create_engine(
        f"sqlite:///{tmp_path / 'memory-metadata.db'}",
        connect_args={"check_same_thread": False},
    )
    database.Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(
        database,
        "SessionLocal",
        sessionmaker(autocommit=False, autoflush=False, bind=engine),
    )
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture(autouse=True)
def legacy_operator_token_fallback(request, monkeypatch):
    """Restore the pre-#965 operator-token fallback for tests that predate credentials.

    ``security.agent_credential`` now raises ``MissingTerminalCredential`` when a
    process claims ``CAO_TERMINAL_ID`` and holds no ``CAO_TERMINAL_TOKEN``,
    instead of silently presenting ``CAO_AUTH_LOCAL_TOKEN`` and reaching the API
    with the OPERATOR's authority. That is the fix; this fixture is about the
    blast radius of it inside the suite.

    154 sites across 60 test files set ``CAO_TERMINAL_ID`` with no token, because
    before #965 the id WAS the identity and the credential hop fell back. Every
    one of those sites is a place where production used to escalate silently --
    the population four reviewers said warn mode could not reveal. Their subject,
    though, is assign/handoff/memory/ephemeral behaviour, not credential
    selection: injecting a synthetic token is worse than useless because the real
    API resolves it, finds no matching digest, and answers 401, so the test would
    exercise neither the old path nor the new one.

    So those tests keep the old fallback and
    ``test/security/test_agent_credential.py`` owns the credential-selection
    contract, under ``@pytest.mark.unpaired_terminal_credential``. Any test whose
    subject IS the credential (or which seeds real rows with real digests) takes
    the marker and sees production behaviour.

    This is a recorded compromise, not a clean solution. Converting those 154
    sites to seed a real row and a real digest is the honest fix and belongs with
    the migration work the proposal has to specify -- it is not a side quest
    inside a defect fix.
    """
    if "unpaired_terminal_credential" in request.keywords:
        return

    from cli_agent_orchestrator.mcp_server import app_tools
    from cli_agent_orchestrator.mcp_server import utils as mcp_utils
    from cli_agent_orchestrator.security import agent_credential
    from cli_agent_orchestrator.utils import orchestration

    def _legacy(operator_bearer=None):
        token = agent_credential.terminal_token()
        if token:
            return {"Authorization": f"Bearer {token}"}
        bearer = (operator_bearer or agent_credential.get_local_bearer)()
        return {"Authorization": f"Bearer {bearer}"} if bearer else {}

    # The three alias modules bind the function by name at import, so patching
    # the definition alone would miss every real call site. Patching all four is
    # also what makes the blast radius visible: these are exactly the modules
    # ``test/security/test_agent_credential_guard.py`` walks.
    monkeypatch.setattr(agent_credential, "agent_credential", _legacy)
    for module in (mcp_utils, app_tools, orchestration):
        monkeypatch.setattr(module, "agent_credential", _legacy, raising=False)
