"""Tests for IPC$ pipe enumeration (coercex.pipes).

All impacket SMB calls are mocked; no network access required.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from coercex.models import Credentials
from coercex.pipes import enumerate_pipes


# -- Helpers ----------------------------------------------------------------


def _make_entry(name: str, *, is_dir: bool = False) -> MagicMock:
    """Create a mock SharedFile entry returned by SMBConnection.listPath."""
    entry = MagicMock()
    entry.get_longname.return_value = name
    entry.is_directory.return_value = is_dir
    return entry


def _make_creds(**overrides) -> Credentials:
    defaults = dict(username="admin", password="P@ssw0rd", domain="CORP")
    defaults.update(overrides)
    return Credentials(**defaults)


# -- Tests ------------------------------------------------------------------


class TestEnumeratePipesSuccess:
    """Successful IPC$ enumeration scenarios."""

    @patch("impacket.smbconnection.SMBConnection")
    def test_returns_formatted_pipe_names(self, mock_smb_cls: MagicMock) -> None:
        """Discovered files are formatted as \\PIPE\\<name>."""
        mock_conn = MagicMock()
        mock_smb_cls.return_value = mock_conn
        mock_conn.listPath.return_value = [
            _make_entry("."),
            _make_entry(".."),
            _make_entry("spoolss"),
            _make_entry("efsrpc"),
            _make_entry("netlogon"),
        ]

        creds = _make_creds()
        result = enumerate_pipes("10.0.0.5", creds, timeout=3)

        assert result == {
            r"\PIPE\spoolss",
            r"\PIPE\efsrpc",
            r"\PIPE\netlogon",
        }
        mock_conn.login.assert_called_once()
        mock_conn.close.assert_called_once()

    @patch("impacket.smbconnection.SMBConnection")
    def test_bfs_traverses_subdirectories(self, mock_smb_cls: MagicMock) -> None:
        """Breadth-first traversal discovers pipes in subdirectories."""
        mock_conn = MagicMock()
        mock_smb_cls.return_value = mock_conn

        # First call: root of IPC$ — one file and one directory
        root_entries = [
            _make_entry("."),
            _make_entry(".."),
            _make_entry("spoolss"),
            _make_entry("subdir", is_dir=True),
        ]
        # Second call: inside subdir/ — one file
        subdir_entries = [
            _make_entry("."),
            _make_entry(".."),
            _make_entry("nested_pipe"),
        ]
        mock_conn.listPath.side_effect = [root_entries, subdir_entries]

        creds = _make_creds()
        result = enumerate_pipes("10.0.0.5", creds)

        assert r"\PIPE\spoolss" in result
        assert r"\PIPE\subdir/nested_pipe" in result
        assert len(result) == 2

    @patch("impacket.smbconnection.SMBConnection")
    def test_deduplicates_pipe_names(self, mock_smb_cls: MagicMock) -> None:
        """Duplicate entries in listPath are deduplicated."""
        mock_conn = MagicMock()
        mock_smb_cls.return_value = mock_conn
        mock_conn.listPath.return_value = [
            _make_entry("spoolss"),
            _make_entry("spoolss"),
        ]

        creds = _make_creds()
        result = enumerate_pipes("10.0.0.5", creds)

        assert result == {r"\PIPE\spoolss"}


class TestEnumeratePipesKerberos:
    """Kerberos authentication path."""

    @patch("impacket.smbconnection.SMBConnection")
    def test_kerberos_auth_calls_kerberos_login(self, mock_smb_cls: MagicMock) -> None:
        """When do_kerberos is True, uses kerberosLogin."""
        mock_conn = MagicMock()
        mock_smb_cls.return_value = mock_conn
        mock_conn.listPath.return_value = [_make_entry("spoolss")]

        creds = _make_creds(do_kerberos=True, dc_host="dc01.corp.local")
        result = enumerate_pipes("dc01.corp.local", creds)

        mock_conn.kerberosLogin.assert_called_once()
        mock_conn.login.assert_not_called()
        assert r"\PIPE\spoolss" in result


class TestEnumeratePipesFailure:
    """Error handling in pipe enumeration."""

    @patch("impacket.smbconnection.SMBConnection")
    def test_connect_failure_returns_empty_set(self, mock_smb_cls: MagicMock) -> None:
        """Connection failure returns empty set."""
        mock_smb_cls.side_effect = OSError("Connection refused")

        creds = _make_creds()
        result = enumerate_pipes("10.0.0.5", creds)

        assert result == set()

    @patch("impacket.smbconnection.SMBConnection")
    def test_auth_failure_returns_empty_set(self, mock_smb_cls: MagicMock) -> None:
        """Authentication failure returns empty set and closes connection."""
        mock_conn = MagicMock()
        mock_smb_cls.return_value = mock_conn
        mock_conn.login.side_effect = Exception("STATUS_LOGON_FAILURE")

        creds = _make_creds()
        result = enumerate_pipes("10.0.0.5", creds)

        assert result == set()
        mock_conn.close.assert_called_once()

    @patch("impacket.smbconnection.SMBConnection")
    def test_listpath_failure_returns_empty_set(self, mock_smb_cls: MagicMock) -> None:
        """listPath failure returns empty set (no pipes found)."""
        mock_conn = MagicMock()
        mock_smb_cls.return_value = mock_conn
        mock_conn.listPath.side_effect = Exception("STATUS_ACCESS_DENIED")

        creds = _make_creds()
        result = enumerate_pipes("10.0.0.5", creds)

        assert result == set()
        mock_conn.close.assert_called_once()

    @patch("impacket.smbconnection.SMBConnection")
    def test_empty_share_returns_empty_set(self, mock_smb_cls: MagicMock) -> None:
        """IPC$ share with only . and .. returns empty set."""
        mock_conn = MagicMock()
        mock_smb_cls.return_value = mock_conn
        mock_conn.listPath.return_value = [
            _make_entry("."),
            _make_entry(".."),
        ]

        creds = _make_creds()
        result = enumerate_pipes("10.0.0.5", creds)

        assert result == set()
