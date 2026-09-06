"""Tests for ${env:VAR} secret resolution (framework/secret_resolver.py).

The properties that matter: a valid reference resolves from the runner's env, and
an unset/empty reference fails LOUDLY (never silently injects an empty
credential). The last test characterizes the known silent-passthrough gap so a
future hardening changes it on purpose.
"""

from __future__ import annotations

import pytest

from framework.secret_resolver import (
    SecretResolutionError,
    env_var_name,
    is_env_ref_attempt,
    resolve,
    resolve_dict,
)


def test_resolves_valid_reference_from_env(monkeypatch):
    monkeypatch.setenv("MY_TOKEN", "abc123")
    assert resolve("${env:MY_TOKEN}") == "abc123"


def test_unset_env_var_raises_loudly(monkeypatch):
    monkeypatch.delenv("NOPE_TOKEN", raising=False)
    with pytest.raises(SecretResolutionError, match="NOPE_TOKEN"):
        resolve("${env:NOPE_TOKEN}")


def test_empty_env_value_raises_not_silently_empty(monkeypatch):
    # A var explicitly set to "" must be treated as unresolved, not as a
    # silently-empty secret that the fetcher would authenticate with.
    monkeypatch.setenv("EMPTY_TOKEN", "")
    with pytest.raises(SecretResolutionError):
        resolve("${env:EMPTY_TOKEN}")


def test_plain_string_passes_through_unchanged():
    assert resolve("a-literal-non-reference-value") == "a-literal-non-reference-value"


def test_surrounding_whitespace_is_tolerated(monkeypatch):
    monkeypatch.setenv("T", "v")
    assert resolve("  ${env:T}  ") == "v"


def test_non_string_value_passes_through():
    assert resolve(123) == 123


def test_resolve_dict_resolves_each_value(monkeypatch):
    monkeypatch.setenv("A", "1")
    monkeypatch.setenv("B", "2")
    assert resolve_dict({"a": "${env:A}", "b": "${env:B}"}) == {"a": "1", "b": "2"}


@pytest.mark.parametrize("bad", [
    "${env:my_token}",   # lowercase var name — the common typo
    "${env:MY-TOKEN}",   # hyphen is not a valid env var character
    "${env:}",           # empty name
    "${env:FOO",         # unclosed
])
def test_malformed_reference_raises_instead_of_passing_through(bad, monkeypatch):
    """A broken reference must fail loudly, not become the credential.

    This replaces a characterization test that pinned the old silent
    passthrough. Passing it through handed the fetcher the literal string
    "${env:my_token}" as its secret; the TUI rendered it as a correctly-set
    variable named my_token, and redaction then added the literal to the secret
    sink — so the 401 that echoed it back printed ***REDACTED*** exactly where
    the bug's own name would have been. Three layers agreeing on a wrong answer.
    """
    monkeypatch.setenv("my_token", "secret")
    with pytest.raises(SecretResolutionError, match="Malformed secret reference"):
        resolve(bad)


def test_a_value_that_is_not_a_reference_is_still_a_literal(monkeypatch):
    """Literal secrets are supported, so only a value that OPENS with the sigil
    counts as an attempted reference. An embedded ${env:...} stays a literal —
    substitution was never a feature, and a real password may contain anything."""
    monkeypatch.setenv("T", "v")
    assert resolve("prefix-${env:T}") == "prefix-${env:T}"
    assert resolve("hunter2") == "hunter2"
    assert resolve("https://host/path$notaref") == "https://host/path$notaref"


def test_env_var_name_and_resolve_agree_on_what_is_valid(monkeypatch):
    """The display path and the run path must not disagree — that disagreement
    is what let the console show a malformed ref as set."""
    monkeypatch.setenv("REAL_TOKEN", "v")
    assert env_var_name("${env:REAL_TOKEN}") == "REAL_TOKEN"
    assert resolve("${env:REAL_TOKEN}") == "v"

    assert env_var_name("${env:my_token}") is None
    assert is_env_ref_attempt("${env:my_token}") is True
    with pytest.raises(SecretResolutionError):
        resolve("${env:my_token}")

    assert env_var_name("literal") is None
    assert is_env_ref_attempt("literal") is False
    assert resolve("literal") == "literal"
