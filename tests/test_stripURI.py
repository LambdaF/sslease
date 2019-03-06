import pytest
from ..sslease import stripURI


def test_validHostnameSchema():
    assert stripURI("https://google.com") == "google.com"


def test_validHostnameNoSchema():
    assert stripURI("google.com") == "google.com"


def test_validHostnameDifferentSchema():
    assert stripURI("ftp://google.com") == "google.com"


def test_validHostnameSchemaPort():
    assert stripURI("https://google.com:443") == "google.com-443"


def test_validHostnamePort():
    assert stripURI("google.com:443") == "google.com-443"


def test_validIP():
    assert stripURI("127.0.0.1") == "127.0.0.1"


def test_validIPSchema():
    assert stripURI("https://127.0.0.1") == "127.0.0.1"


def test_validIPDifferentSchema():
    assert stripURI("https://127.0.0.1") == "127.0.0.1"


def test_validIPPort():
    assert stripURI("127.0.0.1:443") == "127.0.0.1-443"


def test_validIPSchemaPort():
    assert stripURI("https://127.0.0.1:443") == "127.0.0.1-443"
