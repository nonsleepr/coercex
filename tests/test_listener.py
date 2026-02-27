"""Tests for listener token extraction logic."""

from __future__ import annotations

from coercex.listener import AsyncListener


class TestExtractTokenFromPath:
    """Test token extraction from UNC and URL paths."""

    def setup_method(self):
        self._listener = AsyncListener.__new__(AsyncListener)

    def test_unc_share_path(self):
        token = self._listener._extract_token_from_path(
            r"\\10.0.0.1\abc123def456\file.txt"
        )
        assert token == "abc123def456"

    def test_url_path(self):
        token = self._listener._extract_token_from_path("/abc123def456/file.txt")
        assert token == "abc123def456"

    def test_bare_token(self):
        token = self._listener._extract_token_from_path("abc123def456")
        assert token == "abc123def456"

    def test_no_token(self):
        token = self._listener._extract_token_from_path(r"\\10.0.0.1\share\file.txt")
        assert token is None

    def test_non_hex_12_char(self):
        token = self._listener._extract_token_from_path(
            r"\\10.0.0.1\notahextoken\file.txt"
        )
        assert token is None

    def test_empty_path(self):
        token = self._listener._extract_token_from_path("")
        assert token is None
